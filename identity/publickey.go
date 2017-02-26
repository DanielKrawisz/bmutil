// Copyright (c) 2015 Monetas
// Copyright 2016 Daniel Krawisz.
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package identity

import (
	"crypto/sha512"
	"fmt"

	"github.com/DanielKrawisz/bmutil/hash"
	"github.com/DanielKrawisz/bmutil/wire"
	"golang.org/x/crypto/ripemd160"
)

// PublicKey contains the identity of the remote user, which includes public
// encryption and signing keys, and POW parameters.
type PublicKey struct {
	Verification *PubKey
	Encryption   *PubKey
}

// Hash returns the ripemd160 hash used in the address
func (k *PublicKey) Hash() *hash.Ripe {
	sha := sha512.New()
	ripemd := ripemd160.New()

	sha.Write(k.Verification.uncompressed())
	sha.Write(k.Encryption.uncompressed())

	ripemd.Write(sha.Sum(nil)) // take ripemd160 of required elements

	// Get the hash
	r, _ := hash.NewRipe(ripemd.Sum(nil))
	return r
}

// String creates a human-readible string of a PublicKey.
func (k *PublicKey) String() string {
	return fmt.Sprintf("{VerificationKey: %s, EncryptionKey: %s}",
		k.Verification.String(), k.Encryption.String())
}

// NewPublicKey takes two wire.PubKeys and constructs a PublicKey.
func NewPublicKey(vk, ek *wire.PubKey) (*PublicKey, error) {
	vpk, err := NewPubKey(vk)
	if err != nil {
		return nil, err
	}
	epk, err := NewPubKey(ek)
	if err != nil {
		return nil, err
	}

	return &PublicKey{
		Verification: vpk,
		Encryption:   epk,
	}, nil
}
