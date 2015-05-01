// Copyright (c) 2015 Monetas
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package bmutil

import (
	"bytes"
	"errors"

	"github.com/btcsuite/btcutil/base58"
)

var (
	// ErrChecksumMismatch describes an error where decoding failed due
	// to a bad checksum.
	ErrChecksumMismatch = errors.New("checksum mismatch")

	// ErrUnknownAddressType describes an error where an address cannot be
	// decoded as a specific address type due to the string encoding
	// begining with an invalid identifier byte or unsupported version.
	ErrUnknownAddressType = errors.New("unknown address type/version")
)

// Address represents a Bitmessage address.
type Address struct {
	Version uint64
	Stream  uint64
	Ripe    [20]byte
}

// Encode the address to a string that begins from BM- based on the hash.
// Output: [Varint(addressVersion) Varint(stream) ripe checksum] where the
// Varints are serialized. Then this byte array is base58 encoded to produce our
// needed address.
func (addr *Address) Encode() (string, error) {
	ripe := addr.Ripe[:]

	switch addr.Version {
	case 2:
		fallthrough
	case 3:
		if ripe[0] == 0x00 {
			ripe = ripe[1:] // exclude first byte
			if ripe[0] == 0x00 {
				ripe = ripe[1:] // exclude second byte as well
			}
		}
	case 4:
		ripe = bytes.TrimLeft(ripe, "\x00")
	default:
		return "", ErrUnknownAddressType
	}

	var binaryData bytes.Buffer
	WriteVarInt(&binaryData, addr.Version)
	WriteVarInt(&binaryData, addr.Stream)
	binaryData.Write(ripe)

	// calc checksum from 2 rounds of SHA512
	checksum := DoubleSha512(binaryData.Bytes())[:4]

	totalBin := append(binaryData.Bytes(), checksum...)

	return "BM-" + string(base58.Encode(totalBin)), nil // done
}

// DecodeAddress decodes the Bitmessage address. The assumption is that input
// address is properly formatted (according to specs).
func DecodeAddress(address string) (*Address, error) {
	if address[:3] == "BM-" { // Clients should accept addresses without BM-
		address = address[3:]
	}

	data := base58.Decode(address)
	if len(data) <= 12 { // rough lower bound, also don't want it to be empty
		return nil, ErrUnknownAddressType
	}

	hashData := data[:len(data)-4]
	checksum := data[len(data)-4:]

	if !bytes.Equal(checksum, DoubleSha512(hashData)[0:4]) {
		return nil, ErrChecksumMismatch
	}
	// create the address
	addr := new(Address)

	buf := bytes.NewReader(data)
	var err error

	addr.Version, err = ReadVarInt(buf) // read version
	if err != nil {
		return nil, err
	}

	addr.Stream, err = ReadVarInt(buf) // read stream
	if err != nil {
		return nil, err
	}

	ripe := make([]byte, buf.Len()-4) // exclude bytes already read and checksum
	n, err := buf.Read(ripe)
	if n != len(ripe) || err != nil {
		return nil, err
	}

	switch addr.Version {
	case 2:
		fallthrough
	case 3:
		if len(ripe) > 20 || len(ripe) < 18 { // improper size
			return nil, errors.New("version 3, the ripe length is invalid")
		}
	case 4:
		// encoded ripe data MUST have null bytes removed from front
		if ripe[0] == 0x00 {
			return nil, errors.New("version 4, ripe data has null bytes in" +
				" the beginning, not properly encoded")
		}
		if len(ripe) > 20 || len(ripe) < 4 { // improper size
			return nil, errors.New("version 4, the ripe length is invalid")
		}
	default:
		return nil, ErrUnknownAddressType
	}

	// prepend null bytes to make sure that the total ripe length is 20
	numPadding := 20 - len(ripe)
	ripe = append(make([]byte, numPadding), ripe...)
	copy(addr.Ripe[:], ripe)

	return addr, nil
}

// calcDoubleHash calculates the double sha512 sum of the address, the first
// half of which is used as private encryption key for the public key object
// and the second half is used as a tag.
func (addr *Address) calcDoubleHash() []byte {
	var b bytes.Buffer
	WriteVarInt(&b, addr.Version)
	WriteVarInt(&b, addr.Stream)
	b.Write(addr.Ripe[:])

	return DoubleSha512(b.Bytes())
}

// Tag calculates tag corresponding to the Bitmessage address. According to
// protocol specifications, it is the second half of the double SHA-512 hash
// of version, stream and ripe concatenated together.
func (addr *Address) Tag() []byte {
	var a = make([]byte, 32)
	copy(a, addr.calcDoubleHash()[32:])
	return a
}
