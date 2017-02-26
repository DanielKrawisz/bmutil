// Copyright (c) 2015 Monetas
// Copyright 2016 Daniel Krawisz.
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package identity

import (
	"encoding/hex"

	"github.com/DanielKrawisz/bmutil/wire"
	"github.com/btcsuite/btcd/btcec"
)

// PubKey is used in several of the bitmessage messages and common structures.
// The first 32 bytes contain the X value and the other 32 contain the Y value.
type PubKey btcec.PublicKey

// Btcec converts PubKey to btcec.PublicKey so that it can be used for
// cryptographic operations like encryption/signature verification.
func (pubkey *PubKey) Btcec() *btcec.PublicKey {
	return (*btcec.PublicKey)(pubkey)
}

// uncompressed returns the uncompressed serialization of the PubKey.
// Used to calculate the hash of the PublicKey object.
func (pubkey *PubKey) uncompressed() []byte {
	return pubkey.Btcec().SerializeUncompressed()
}

// Bytes returns the bytes which represent the hash as a byte slice.
func (pubkey *PubKey) Bytes() []byte {
	return pubkey.uncompressed()[1:]
}

// Wire returns the PubKey in wire format.
func (pubkey *PubKey) Wire() *wire.PubKey {
	// There should be no error here because we should know that the key
	// is valid at the time it is created. It should never be necessary to
	// check for an error here, and if it is then the progarm is wrong.
	pk, _ := wire.NewPubKey(pubkey.Bytes())
	return pk
}

// String returns the PubKey as a hexadecimal string.
func (pubkey *PubKey) String() string {
	return hex.EncodeToString(pubkey.Bytes())
}

// IsEqual returns true if target is the same as the pubkey.
func (pubkey *PubKey) IsEqual(target *PubKey) bool {
	return pubkey.Btcec().IsEqual(target.Btcec())
}

// NewPubKey returns a new PubKey from a wire.PubKey. An error is returned if
// the number of bytes passed in is not PubKeySize.
func NewPubKey(pub *wire.PubKey) (*PubKey, error) {
	pubkey := make([]byte, wire.PubKeySize+1)
	copy(pubkey[1:], pub[0:wire.PubKeySize])

	pubkey[0] = 0x04 // uncompressed key

	// Check that we can parse a btcec public key from this.
	k, err := btcec.ParsePubKey(pubkey, btcec.S256())
	if err != nil {
		return nil, err
	}
	return (*PubKey)(k), nil
}
