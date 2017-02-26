// Copyright (c) 2015 Monetas
// Copyright 2016 Daniel Krawisz.
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package wire

import (
	"bytes"
	"encoding/hex"
	"fmt"

	"github.com/btcsuite/btcd/btcec"
)

// PubKeySize is the size of array used to store uncompressed public keys. Note
// that the first byte (0x04) is excluded when storing them.
const PubKeySize = 64

// MaxPubKeyStringSize is the maximum length of a PubKey string.
const MaxPubKeyStringSize = PubKeySize * 2

// ErrPubKeyStrSize describes an error that indicates the caller specified
// a PubKey string that does not have the right number of characters.
var ErrPubKeyStrSize = fmt.Errorf("string length must be %v chars", MaxPubKeyStringSize)

// PubKey is used in several of the bitmessage messages and common structures.
// The first 32 bytes contain the X value and the other 32 contain the Y value.
type PubKey [PubKeySize]byte

// String returns the PubKey as a hexadecimal string.
func (pubkey PubKey) String() string {
	return hex.EncodeToString(pubkey[:])
}

// Bytes returns the bytes which represent the hash as a byte slice.
func (pubkey *PubKey) Bytes() []byte {
	newPubkey := make([]byte, PubKeySize)
	copy(newPubkey, pubkey[:])

	return newPubkey
}

// setBytes sets the bytes which represent the hash. An error is returned if
// the number of bytes passed in is not PubKeySize.
func (pubkey *PubKey) setBytes(newPubkey []byte) error {
	nhlen := len(newPubkey)
	if nhlen != PubKeySize {
		return fmt.Errorf("invalid pub key length of %v, want %v", nhlen,
			PubKeySize)
	}
	copy(pubkey[:], newPubkey[0:PubKeySize])

	return nil
}

// IsEqual returns true if target is the same as the pubkey.
func (pubkey *PubKey) IsEqual(target *PubKey) bool {
	return bytes.Equal(pubkey[:], target[:])
}

// ToBtcec converts PubKey to btcec.PublicKey so that it can be used for
// cryptographic operations like encryption/signature verification.
func (pubkey *PubKey) ToBtcec() (key *btcec.PublicKey, err error) {
	b := make([]byte, PubKeySize+1)
	b[0] = 0x04 // uncompressed key
	copy(b[1:PubKeySize+1], pubkey.Bytes())

	return btcec.ParsePubKey(b, btcec.S256())
}

// NewPubKey returns a new PubKey from a byte slice. An error is returned if
// the number of bytes passed in is not PubKeySize.
func NewPubKey(newHash []byte) (*PubKey, error) {
	var pubkey PubKey
	err := pubkey.setBytes(newHash)
	if err != nil {
		return nil, err
	}
	return &pubkey, err
}

// NewPubKeyFromStr creates a PubKey from a hash string. The string should be
// the hexadecimal string of the PubKey.
func NewPubKeyFromStr(pubkey string) (*PubKey, error) {
	// Return error if PubKey string is not the right size.
	if len(pubkey) != MaxPubKeyStringSize {
		return nil, ErrPubKeyStrSize
	}

	// Convert string hash to bytes.
	buf, err := hex.DecodeString(pubkey)
	if err != nil {
		return nil, err
	}

	return NewPubKey(buf)
}
