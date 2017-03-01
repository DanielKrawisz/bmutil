// Copyright (c) 2015 Monetas
// Copyright 2016 Daniel Krawisz.
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package identity

import (
	"bytes"
	"crypto/sha512"
	"errors"

	. "github.com/DanielKrawisz/bmutil"
	"github.com/DanielKrawisz/bmutil/hash"
	"github.com/btcsuite/btcd/btcec"
	"github.com/btcsuite/btcutil/hdkeychain"
)

// BMPurposeCode is the purpose code used for HD key derivation.
const BMPurposeCode = 0x80000052

// PrivateKey contains the private keys.
type PrivateKey struct {
	Signing    *btcec.PrivateKey
	Decryption *btcec.PrivateKey
}

// Public turns a Private identity object into Public identity object.
func (pk *PrivateKey) Public() *PublicKey {
	return &PublicKey{
		Verification: (*PubKey)(pk.Signing.PubKey()),
		Encryption:   (*PubKey)(pk.Decryption.PubKey()),
	}
}

// Hash returns the ripemd160 hash used in the address
func (pk *PrivateKey) Hash() *hash.Ripe {
	return pk.Public().Hash()
}

// ExportWIF exports the private keys in WIF format.
func (pk *PrivateKey) ExportWIF() (SigningWif, DecryptionWif string) {
	SigningWif = EncodeWIF(pk.Signing)
	DecryptionWif = EncodeWIF(pk.Decryption)
	return
}

// NewRandom creates an identity based on a random data, with the required
// number of initial zeros in front (minimum 1). Each initial zero requires
// exponentially more work. Note that this does not create an address.
func NewRandom(initialZeros int) (*PrivateKey, error) {
	if initialZeros < 1 { // Cannot take this
		return nil, errors.New("minimum 1 initial zero needed")
	}

	var pk = new(PrivateKey)
	var err error

	// Create signing key
	pk.Signing, err = btcec.NewPrivateKey(btcec.S256())
	if err != nil {
		return nil, err
	}

	initialZeroBytes := make([]byte, initialZeros) // used for comparison
	// Go through loop to encryption keys with required num. of zeros
	for {
		// Generate encryption keys
		pk.Decryption, err = btcec.NewPrivateKey(btcec.S256())
		if err != nil {
			return nil, err
		}

		// We found our hash!
		if bytes.Equal(pk.Hash()[0:initialZeros], initialZeroBytes) {
			break // stop calculations
		}
	}

	return pk, nil
}

// NewDeterministic creates n identities based on a deterministic passphrase.
// Note that this does not create an address.
func NewDeterministic(passphrase string, initialZeros uint64, n int) ([]*PrivateKey, error) {
	if initialZeros < 1 { // Cannot take this
		return nil, errors.New("minimum 1 initial zero needed")
	}

	pks := make([]*PrivateKey, n)

	var b bytes.Buffer

	// set the nonces
	var SigningNonce, DecryptionNonce uint64 = 0, 1

	initialZeroBytes := make([]byte, initialZeros) // used for comparison
	sha := sha512.New()

	// Generate n identities.
	for i := 0; i < n; i++ {
		pk := new(PrivateKey)

		// Go through loop to encryption keys with required num. of zeros
		for {
			// Create signing keys
			b.WriteString(passphrase)
			WriteVarInt(&b, SigningNonce)
			sha.Reset()
			sha.Write(b.Bytes())
			b.Reset()
			pk.Signing, _ = btcec.PrivKeyFromBytes(btcec.S256(),
				sha.Sum(nil)[:32])

			// Create encryption keys
			b.WriteString(passphrase)
			WriteVarInt(&b, DecryptionNonce)
			sha.Reset()
			sha.Write(b.Bytes())
			b.Reset()
			pk.Decryption, _ = btcec.PrivKeyFromBytes(btcec.S256(),
				sha.Sum(nil)[:32])

			// Increment nonces
			SigningNonce += 2
			DecryptionNonce += 2

			// We found our hash!
			if bytes.Equal(pk.Hash()[0:initialZeros], initialZeroBytes) {
				break // stop calculations
			}
		}

		pks[i] = pk
	}

	return pks, nil
}

// NewHD generates a new hierarchically deterministic key based on BIP-BM01.
// Master key must be a private master key generated according to BIP32. `n' is
// the n'th identity to generate. NewHD also generates a v4 address based on the
// specified stream.
func NewHD(masterKey *hdkeychain.ExtendedKey, n uint32, stream uint64) (*PrivateKey, error) {

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
	s, err := i.Child(hdkeychain.HardenedKeyStart + uint32(stream))
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

	pk := new(PrivateKey)
	pk.Signing, _ = signKey.ECPrivKey()

	for i := uint32(1); ; i++ {
		encKey, err := a.Child(i)
		if err != nil {
			continue
		}
		pk.Decryption, _ = encKey.ECPrivKey()

		// We found our hash!
		if h := pk.Hash(); h[0] == 0x00 { // First byte should be zero.
			break // stop calculations
		}
	}

	return pk, nil
}
