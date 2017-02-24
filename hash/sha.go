// Originally derived from: btcsuite/btcd/wire/shahash.go
// Copyright (c) 2013-2015 Conformal Systems LLC.

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

// ShaSize is the size of the array used to store SHA hashes.
const ShaSize = 32

// HashStringSize is the maximum length of a ShaHash hash string.
const HashStringSize = ShaSize * 2

// ErrHashStrSize describes an error that indicates the caller specified a hash
// string that does not have the right number of characters.
var ErrHashStrSize = fmt.Errorf("string length must be %v chars", HashStringSize)

// Sha is used in several of the bitmessage messages and common structures.
// It typically represents a half of the double SHA512 of data.
type Sha [ShaSize]byte

// String returns the ShaHash as the hexadecimal string of the byte-reversed
// hash.
func (hash Sha) String() string {
	return hex.EncodeToString(hash[:])
}

// Bytes returns the bytes which represent the hash as a byte slice.
func (hash *Sha) Bytes() []byte {
	newHash := make([]byte, ShaSize)
	copy(newHash, hash[:])

	return newHash
}

// SetBytes sets the bytes which represent the hash. An error is returned if
// the number of bytes passed in is not ShaSize.
func (hash *Sha) SetBytes(newHash []byte) error {
	nhlen := len(newHash)
	if nhlen != ShaSize {
		return fmt.Errorf("invalid sha length of %v, want %v", nhlen,
			ShaSize)
	}
	copy(hash[:], newHash)

	return nil
}

// IsEqual returns true if target is the same as hash.
func (hash *Sha) IsEqual(target *Sha) bool {
	if target == nil {
		return false
	}
	return bytes.Equal(hash[:], target[:])
}

// NewSha returns a new ShaHash from a byte slice. An error is returned if
// the number of bytes passed in is not ShaHash.
func NewSha(newHash []byte) (*Sha, error) {
	var sh Sha
	err := sh.SetBytes(newHash)
	if err != nil {
		return nil, err
	}
	return &sh, err
}

// NewShaFromStr creates a ShaHash from a hash string. The string should be
// the hexadecimal string of a hash.
func NewShaFromStr(hash string) (*Sha, error) {
	// Return error if hash string is not the right size.
	if len(hash) != HashStringSize {
		return nil, ErrHashStrSize
	}

	// Convert string hash to bytes.
	buf, err := hex.DecodeString(hash)
	if err != nil {
		return nil, err
	}

	return NewSha(buf)
}

// InventoryHash takes double sha512 of the bytes and returns the first half.
// It calculates inventory hash of the object as required by the protocol.
func InventoryHash(stuff []byte) *Sha {
	hash, _ := NewSha(DoubleSha512(stuff)[:32])
	return hash
}
