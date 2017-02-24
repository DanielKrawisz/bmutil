// Copyright (c) 2015 Monetas
// Copyright 2016 Daniel Krawisz.
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package identity

import (
	"crypto/sha512"

	"github.com/DanielKrawisz/bmutil/hash"
	"github.com/DanielKrawisz/bmutil/wire/obj"
	"github.com/btcsuite/btcd/btcec"
	"golang.org/x/crypto/ripemd160"
)

// PublicKey contains the identity of the remote user, which includes public
// encryption and signing keys, and POW parameters.
type PublicKey struct {
	Verification *btcec.PublicKey
	Encryption   *btcec.PublicKey
}

// hashHelper exists for delegating the task of hash calculation
func hashHelper(signingKey []byte, decryptionKey []byte) []byte {
	sha := sha512.New()
	ripemd := ripemd160.New()

	sha.Write(signingKey)
	sha.Write(decryptionKey)

	ripemd.Write(sha.Sum(nil)) // take ripemd160 of required elements
	return ripemd.Sum(nil)     // Get the hash
}

// Hash returns the ripemd160 hash used in the address
func (id *PublicKey) Hash() *hash.Ripe {
	r, _ := hash.NewRipe(hashHelper(id.Verification.SerializeUncompressed(),
		id.Encryption.SerializeUncompressed()))
	return r
}

// NewPublicKey creates and initializes an *identity.Public object.
func NewPublicKey(verificationKey, encryptionKey *btcec.PublicKey) *PublicKey {
	return &PublicKey{
		Encryption:   encryptionKey,
		Verification: verificationKey,
	}
}

// ToPublic constructs the PublicKey object.
func ToPublic(pk *obj.PubKeyData) (*PublicKey, error) {
	// Check if embedded keys correspond to the address used to decrypt.
	vk, err := pk.Verification.ToBtcec()
	if err != nil {
		return nil, err
	}
	ek, err := pk.Encryption.ToBtcec()
	if err != nil {
		return nil, err
	}

	return &PublicKey{
		Verification: vk,
		Encryption:   ek,
	}, nil
}
