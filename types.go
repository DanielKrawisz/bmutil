// Originally derived from: btcsuite/btcd/wire/common.go
// Copyright (c) 2013-2015 Conformal Systems LLC.

// Copyright (c) 2015 Monetas
// Copyright 2016 Daniel Krawisz.
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package bmutil

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
)

// Maximum size of a variable length integer.
const MaxVarIntSize = 9

// ReadVarInt reads a variable length integer from r and returns it as a uint64.
func ReadVarInt(r io.Reader) (uint64, error) {
	var b [8]byte
	_, err := io.ReadFull(r, b[0:1])
	if err != nil {
		return 0, err
	}

	var rv uint64
	discriminant := uint8(b[0])
	switch discriminant {
	case 0xff:
		_, err := io.ReadFull(r, b[:])
		if err != nil {
			return 0, err
		}
		rv = binary.BigEndian.Uint64(b[:])

	case 0xfe:
		_, err := io.ReadFull(r, b[0:4])
		if err != nil {
			return 0, err
		}
		rv = uint64(binary.BigEndian.Uint32(b[:]))

	case 0xfd:
		_, err := io.ReadFull(r, b[0:2])
		if err != nil {
			return 0, err
		}
		rv = uint64(binary.BigEndian.Uint16(b[:]))

	default:
		rv = uint64(discriminant)
	}

	return rv, nil
}

// WriteVarInt serializes val to w using a variable number of bytes depending
// on its value.
func WriteVarInt(w io.Writer, val uint64) error {
	if val < 0xfd {
		_, err := w.Write([]byte{uint8(val)})
		return err
	}

	if val <= math.MaxUint16 {
		var buf [3]byte
		buf[0] = 0xfd
		binary.BigEndian.PutUint16(buf[1:], uint16(val))
		_, err := w.Write(buf[:])
		return err
	}

	if val <= math.MaxUint32 {
		var buf [5]byte
		buf[0] = 0xfe
		binary.BigEndian.PutUint32(buf[1:], uint32(val))
		_, err := w.Write(buf[:])
		return err
	}

	var buf [9]byte
	buf[0] = 0xff
	binary.BigEndian.PutUint64(buf[1:], val)
	_, err := w.Write(buf[:])
	return err
}

// VarIntSerializeSize returns the number of bytes it would take to serialize
// val as a variable length integer.
func VarIntSerializeSize(val uint64) int {
	// The value is small enough to be represented by itself, so it's
	// just 1 byte.
	if val < 0xfd {
		return 1
	}

	// Discriminant 1 byte plus 2 bytes for the uint16.
	if val <= math.MaxUint16 {
		return 3
	}

	// Discriminant 1 byte plus 4 bytes for the uint32.
	if val <= math.MaxUint32 {
		return 5
	}

	// Discriminant 1 byte plus 8 bytes for the uint64.
	return 9
}

// ReadVarString reads a variable length string from r and returns it as a Go
// string. A varString is encoded as a varInt containing the length of the
// string, and the bytes that represent the string itself. An error is returned
// if the length is greater than the maximum block payload size, since it would
// not be possible to put a varString of that size into a block anyways and it
// also helps protect against memory exhaustion attacks and forced panics
// through malformed messages.
func ReadVarString(r io.Reader, maxAllowed int) (string, error) {
	count, err := ReadVarInt(r)
	if err != nil {
		return "", err
	}

	// Prevent variable length strings that are larger than the specified limit.
	// It would be possible to cause memory exhaustion and panics without a sane
	// upper bound on this count.
	if count > uint64(maxAllowed) {
		str := fmt.Sprintf("variable length string is too long "+
			"[count %d, max %d]", count, maxAllowed)
		return "", errors.New(str)
	}

	buf := make([]byte, count)
	_, err = io.ReadFull(r, buf)
	if err != nil {
		return "", err
	}
	return string(buf), nil
}

// WriteVarString serializes str to w as a varInt containing the length of the
// string followed by the bytes that represent the string itself.
func WriteVarString(w io.Writer, str string) error {
	err := WriteVarInt(w, uint64(len(str)))
	if err != nil {
		return err
	}
	_, err = w.Write([]byte(str))
	if err != nil {
		return err
	}
	return nil
}

// ReadVarBytes reads a variable length byte array. A byte array is encoded
// as a varInt containing the length of the array followed by the bytes
// themselves. An error is returned if the length is greater than the
// passed maxAllowed parameter which helps protect against memory exhuastion
// attacks and forced panics thorugh malformed messages. The fieldName
// parameter is only used for the error message so it provides more context in
// the error.
func ReadVarBytes(r io.Reader, maxAllowed int,
	fieldName string) ([]byte, error) {

	count, err := ReadVarInt(r)
	if err != nil {
		return nil, err
	}

	// Prevent byte array larger than the max message size.  It would
	// be possible to cause memory exhaustion and panics without a sane
	// upper bound on this count.
	if count > uint64(maxAllowed) {
		str := fmt.Sprintf("%s is larger than the max allowed size "+
			"[count %d, max %d]", fieldName, count, maxAllowed)
		return nil, errors.New(str)
	}

	b := make([]byte, count)
	_, err = io.ReadFull(r, b)
	if err != nil {
		return nil, err
	}
	return b, nil
}

// WriteVarBytes serializes a variable length byte array to w as a varInt
// containing the number of bytes, followed by the bytes themselves.
func WriteVarBytes(w io.Writer, bytes []byte) error {
	slen := uint64(len(bytes))
	err := WriteVarInt(w, slen)
	if err != nil {
		return err
	}

	_, err = w.Write(bytes)
	if err != nil {
		return err
	}
	return nil
}
