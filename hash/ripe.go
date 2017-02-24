// Copyright (c) 2015 Monetas
// Copyright 2016 Daniel Krawisz.
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package hash

import (
	"bytes"
	"encoding/hex"
	"fmt"
)

// RipeSize is the size of array used to store ripe hashes.
const RipeSize = 20

// RipeHashStringSize is the maximum length of a Ripe hash string.
const RipeHashStringSize = RipeSize * 2

// ErrRipeHashStrSize describes an error that indicates the caller specified
// a hash string that does not have the right number of characters.
var ErrRipeHashStrSize = fmt.Errorf("string length must be %v chars", RipeHashStringSize)

// Ripe is used in several of the bitmessage messages and common
// structures. It typically represents the double sha512 of ripemd160
// of data.
type Ripe [RipeSize]byte

// String returns the Ripe as the hexadecimal string of the byte-reversed
// hash.
func (hash Ripe) String() string {
	return hex.EncodeToString(hash[:])
}

// Bytes returns the bytes which represent the hash as a byte slice.
func (hash *Ripe) Bytes() []byte {
	newHash := make([]byte, RipeSize)
	copy(newHash, hash[:])

	return newHash
}

// SetBytes sets the bytes which represent the hash. An error is returned if
// the number of bytes passed in is not RipeSize.
func (hash *Ripe) SetBytes(newHash []byte) error {
	nhlen := len(newHash)
	if nhlen != RipeSize {
		return fmt.Errorf("invalid ripe length of %v, want %v", nhlen,
			RipeSize)
	}
	copy(hash[:], newHash)

	return nil
}

// IsEqual returns true if target is the same as hash.
func (hash *Ripe) IsEqual(target *Ripe) bool {
	return bytes.Equal(hash[:], target[:])
}

// NewRipe returns a new Ripe from a byte slice. An error is returned if
// the number of bytes passed in is not RipeSize.
func NewRipe(newHash []byte) (*Ripe, error) {
	var ripe Ripe
	err := ripe.SetBytes(newHash)
	if err != nil {
		return nil, err
	}
	return &ripe, err
}

// NewRipeFromStr creates a Ripe from a hash string. The string should
// be the hexadecimal string of a byte hash.
func NewRipeFromStr(hash string) (*Ripe, error) {
	// Return error if hash string is not the right size.
	if len(hash) != RipeHashStringSize {
		return nil, ErrRipeHashStrSize
	}

	// Convert string hash to bytes.
	buf, err := hex.DecodeString(hash)
	if err != nil {
		return nil, err
	}
	return NewRipe(buf)
}
