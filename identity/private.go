// Copyright (c) 2015 Monetas
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package identity

import (
	"bytes"
	"crypto/sha512"
	"errors"

	"github.com/btcsuite/btcd/btcec"
	"golang.org/x/crypto/ripemd160"

	"github.com/monetas/bmutil"
	"github.com/monetas/bmutil/pow"
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

// Create identities based on a deterministic passphrase. Note that this does
// not create an address.
func NewDeterministic(passphrase string, initialZeros uint64) (*Private, error) {
	if initialZeros < 1 { // Cannot take this
		return nil, errors.New("minimum 1 initial zero needed")
	}

	var id = new(Private)

	var b bytes.Buffer

	// set the nonces
	var signingKeyNonce, encryptionKeyNonce uint64 = 0, 1

	initialZeroBytes := make([]byte, initialZeros) // used for comparison
	sha := sha512.New()

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

	return &Private{
		Address:            *addr,
		SigningKey:         privSigningKey,
		EncryptionKey:      privEncryptionKey,
		NonceTrialsPerByte: nonceTrials,
		ExtraBytes:         extraBytes,
	}, nil
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

// hash_helper exists for delegating the task of hash calculation
func hash_helper(signingKey []byte, encryptionKey []byte) []byte {
	sha := sha512.New()
	ripemd := ripemd160.New()

	sha.Write(signingKey)
	sha.Write(encryptionKey)

	ripemd.Write(sha.Sum(nil)) // take ripemd160 of required elements
	return ripemd.Sum(nil)     // Get the hash
}

// hash returns the ripemd160 hash used in the address
func (id *Private) hash() []byte {
	return hash_helper(id.SigningKey.PubKey().SerializeUncompressed(),
		id.EncryptionKey.PubKey().SerializeUncompressed())
}

// CreateAddress populates the Address object within the identity based on the
// provided version and stream values and also generates the ripe.
func (id *Private) CreateAddress(version, stream uint64) {
	id.Address.Version = version
	id.Address.Stream = stream
	copy(id.Address.Ripe[:], id.hash())
}
