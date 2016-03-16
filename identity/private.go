// Copyright (c) 2015 Monetas
// Copyright 2016 Daniel Krawisz.
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package identity

import (
	"bytes"
	"crypto/sha512"
	"errors"

	"github.com/btcsuite/btcd/btcec"
	"github.com/btcsuite/btcutil/hdkeychain"
	"github.com/DanielKrawisz/bmutil"
	"github.com/DanielKrawisz/bmutil/pow"
	"golang.org/x/crypto/ripemd160"
)

const (
	// BMPurposeCode is the purpose code used for HD key derivation.
	BMPurposeCode = 0x80000052
)

// Private contains the identity of the user, which includes private encryption
// and signing keys, POW parameters and the address that contains information
// about stream number and address version.
type Private struct {
	bmutil.Address
	NonceTrialsPerByte uint64
	ExtraBytes         uint64
	SigningKey         *btcec.PrivateKey
	EncryptionKey      *btcec.PrivateKey
	Behavior           uint32
}

// ToPublic turns a Private identity object into Public identity object.
func (id *Private) ToPublic() *Public {
	return &Public{
		Address:            id.Address,
		NonceTrialsPerByte: id.NonceTrialsPerByte,
		ExtraBytes:         id.ExtraBytes,
		SigningKey:         id.SigningKey.PubKey(),
		EncryptionKey:      id.EncryptionKey.PubKey(),
	}
}

// NewRandom creates an identity based on a random data, with the required
// number of initial zeros in front (minimum 1). Each initial zero requires
// exponentially more work. Note that this does not create an address.
func NewRandom(initialZeros int) (*Private, error) {
	if initialZeros < 1 { // Cannot take this
		return nil, errors.New("minimum 1 initial zero needed")
	}

	var id = new(Private)
	var err error

	// Create signing key
	id.SigningKey, err = btcec.NewPrivateKey(btcec.S256())
	if err != nil {
		return nil, err
	}

	initialZeroBytes := make([]byte, initialZeros) // used for comparison
	// Go through loop to encryption keys with required num. of zeros
	for {
		// Generate encryption keys
		id.EncryptionKey, err = btcec.NewPrivateKey(btcec.S256())
		if err != nil {
			return nil, err
		}

		// We found our hash!
		if bytes.Equal(id.hash()[0:initialZeros], initialZeroBytes) {
			break // stop calculations
		}
	}

	id.setDefaultPOWParams()

	return id, nil
}

// NewDeterministic creates n identities based on a deterministic passphrase.
// Note that this does not create an address.
func NewDeterministic(passphrase string, initialZeros uint64, n int) ([]*Private,
	error) {
	if initialZeros < 1 { // Cannot take this
		return nil, errors.New("minimum 1 initial zero needed")
	}

	ids := make([]*Private, n)

	var b bytes.Buffer

	// set the nonces
	var signingKeyNonce, encryptionKeyNonce uint64 = 0, 1

	initialZeroBytes := make([]byte, initialZeros) // used for comparison
	sha := sha512.New()

	// Generate n identities.
	for i := 0; i < n; i++ {
		id := new(Private)

		// Go through loop to encryption keys with required num. of zeros
		for {
			// Create signing keys
			b.WriteString(passphrase)
			bmutil.WriteVarInt(&b, signingKeyNonce)
			sha.Reset()
			sha.Write(b.Bytes())
			b.Reset()
			id.SigningKey, _ = btcec.PrivKeyFromBytes(btcec.S256(),
				sha.Sum(nil)[:32])

			// Create encryption keys
			b.WriteString(passphrase)
			bmutil.WriteVarInt(&b, encryptionKeyNonce)
			sha.Reset()
			sha.Write(b.Bytes())
			b.Reset()
			id.EncryptionKey, _ = btcec.PrivKeyFromBytes(btcec.S256(),
				sha.Sum(nil)[:32])

			// Increment nonces
			signingKeyNonce += 2
			encryptionKeyNonce += 2

			// We found our hash!
			if bytes.Equal(id.hash()[0:initialZeros], initialZeroBytes) {
				break // stop calculations
			}
		}
		id.setDefaultPOWParams()

		ids[i] = id
	}

	return ids, nil
}

// NewHD generates a new hierarchically deterministic key based on BIP-BM01.
// Master key must be a private master key generated according to BIP32. `n' is
// the n'th identity to generate. NewHD also generates a v4 address based on the
// specified stream.
func NewHD(masterKey *hdkeychain.ExtendedKey, n uint32, stream uint32) (*Private, error) {

	if !masterKey.IsPrivate() {
		return nil, errors.New("master key must be private")
	}

	// m / purpose'
	p, err := masterKey.Child(BMPurposeCode)
	if err != nil {
		return nil, err
	}

	// m / purpose' / identity'
	i, err := p.Child(hdkeychain.HardenedKeyStart + n)
	if err != nil {
		return nil, err
	}

	// m / purpose' / identity' / stream'
	s, err := i.Child(hdkeychain.HardenedKeyStart + stream)
	if err != nil {
		return nil, err
	}

	// m / purpose' / identity' / stream' / address'
	a, err := s.Child(hdkeychain.HardenedKeyStart + 0)
	if err != nil {
		return nil, err
	}

	// m / purpose' / identity' / stream' / address' / 0
	signKey, err := a.Child(0)
	if err != nil {
		return nil, err
	}

	id := new(Private)
	id.SigningKey, _ = signKey.ECPrivKey()

	for i := uint32(1); ; i++ {
		encKey, err := a.Child(i)
		if err != nil {
			continue
		}
		id.EncryptionKey, _ = encKey.ECPrivKey()

		// We found our hash!
		if h := id.hash(); h[0] == 0x00 { // First byte should be zero.
			break // stop calculations
		}
	}

	id.CreateAddress(4, uint64(stream))
	id.setDefaultPOWParams()
	return id, nil
}

func (id *Private) setDefaultPOWParams() {
	id.NonceTrialsPerByte = pow.DefaultNonceTrialsPerByte
	id.ExtraBytes = pow.DefaultExtraBytes
}

// ImportWIF creates a Private identity from the Bitmessage address and Wallet
// Import Format (WIF) signing and encryption keys.
func ImportWIF(address, signingKeyWif, encryptionKeyWif string,
	nonceTrials, extraBytes uint64) (*Private, error) {
	// (Try to) decode address
	addr, err := bmutil.DecodeAddress(address)
	if err != nil {
		return nil, err
	}

	privSigningKey, err := bmutil.DecodeWIF(signingKeyWif)
	if err != nil {
		err = errors.New("signing key decode failed: " + err.Error())
		return nil, err
	}
	privEncryptionKey, err := bmutil.DecodeWIF(encryptionKeyWif)
	if err != nil {
		err = errors.New("encryption key decode failed: " + err.Error())
		return nil, err
	}

	priv := &Private{
		Address:            *addr,
		SigningKey:         privSigningKey,
		EncryptionKey:      privEncryptionKey,
		NonceTrialsPerByte: nonceTrials,
		ExtraBytes:         extraBytes,
	}

	// check if everything is valid
	priv.CreateAddress(addr.Version, addr.Stream) // CreateAddress generates ripe
	if !bytes.Equal(priv.Address.Ripe[:], addr.Ripe[:]) {
		return nil, errors.New("address does not correspond to private keys")
	}
	return priv, nil
}

// ExportWIF exports a Private identity to WIF for storage on disk or use by
// other software. It exports the address, private signing key and private
// encryption key.
func (id *Private) ExportWIF() (address, signingKeyWif, encryptionKeyWif string,
	err error) {

	copy(id.Address.Ripe[:], id.hash())
	address, err = id.Address.Encode()
	if err != nil {
		err = errors.New("error encoding address: " + err.Error())
		return
	}
	signingKeyWif = bmutil.EncodeWIF(id.SigningKey)
	encryptionKeyWif = bmutil.EncodeWIF(id.EncryptionKey)
	return
}

// hashHelper exists for delegating the task of hash calculation
func hashHelper(signingKey []byte, encryptionKey []byte) []byte {
	sha := sha512.New()
	ripemd := ripemd160.New()

	sha.Write(signingKey)
	sha.Write(encryptionKey)

	ripemd.Write(sha.Sum(nil)) // take ripemd160 of required elements
	return ripemd.Sum(nil)     // Get the hash
}

// hash returns the ripemd160 hash used in the address
func (id *Private) hash() []byte {
	return hashHelper(id.SigningKey.PubKey().SerializeUncompressed(),
		id.EncryptionKey.PubKey().SerializeUncompressed())
}

// CreateAddress populates the Address object within the identity based on the
// provided version and stream values and also generates the ripe.
func (id *Private) CreateAddress(version, stream uint64) {
	id.Address.Version = version
	id.Address.Stream = stream
	copy(id.Address.Ripe[:], id.hash())
}
