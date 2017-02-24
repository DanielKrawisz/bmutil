// Copyright (c) 2015 Monetas
// Copyright 2016 Daniel Krawisz.
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package bmutil

import (
	"bytes"
	"errors"

	"github.com/DanielKrawisz/bmutil/hash"
	"github.com/btcsuite/btcd/btcec"
	"github.com/btcsuite/btcutil/base58"
)

const (
	// DefaultAddressVersion is the address version that we use when we
	// create new addresses.
	DefaultAddressVersion = 4

	// DefaultStream is the only stream currently in use on the Bitmessage
	// network, which is 1.
	DefaultStream = 1
)

var (
	// ErrChecksumMismatch describes an error where decoding failed due
	// to a bad checksum.
	ErrChecksumMismatch = errors.New("checksum mismatch")

	// ErrUnknownAddressType describes an error where an address cannot be
	// decoded as a specific address type due to the string encoding
	// begining with an invalid identifier byte or unsupported version.
	ErrUnknownAddressType = errors.New("unknown address type/version")

	// ErrDepricatedAddressVersion is returned if we try to create a
	// new address with a version less than 4.
	ErrDepricatedAddressVersion = errors.New("Address versions below 4 are depricated.")

	// ErrInvalidStream is returned if someone tries to create an address
	// with stream other than 1.
	ErrInvalidStream = errors.New("Only stream 1 is currently in use.")
)

// Address represents a Bitmessage address.
type Address interface {
	Version() uint64
	Stream() uint64
	RipeHash() *hash.Ripe
	String() string
}

// addressV4 represents a version 4  Bitmessage address.
type addressV4 struct {
	stream uint64
	ripe   hash.Ripe
}

// NewAddress creates a new address. Currently supported parameters
// must be provided for the object to be created. That means version 4 only
// and stream 1.
func NewAddress(version, stream uint64, ripe *hash.Ripe) (Address, error) {
	if version > DefaultAddressVersion {
		return nil, ErrUnknownAddressType
	}
	if version < DefaultAddressVersion {
		return nil, ErrDepricatedAddressVersion
	}
	if stream != DefaultStream {
		return nil, ErrInvalidStream
	}
	return &addressV4{
		stream: stream,
		ripe:   *ripe,
	}, nil
}

func (addr *addressV4) Version() uint64 {
	return 4
}

func (addr *addressV4) Stream() uint64 {
	return addr.stream
}

func (addr *addressV4) RipeHash() *hash.Ripe {
	return &addr.ripe
}

// String outputs the address to a string that begins with BM-.
// Output: [Varint(addressVersion) Varint(stream) ripe checksum] where the
// Varints are serialized. Then this byte array is base58 encoded to produce our
// needed address.
func (addr *addressV4) String() string {

	ripe := bytes.TrimLeft(addr.ripe[:], "\x00")

	var binaryData bytes.Buffer
	WriteVarInt(&binaryData, addr.Version())
	WriteVarInt(&binaryData, addr.stream)
	binaryData.Write(ripe)

	// calc checksum from 2 rounds of SHA512
	checksum := hash.DoubleSha512(binaryData.Bytes())[:4]

	totalBin := append(binaryData.Bytes(), checksum...)

	return "BM-" + string(base58.Encode(totalBin))
}

// depricatedAddress represents a version 2 or 3 Bitmessage address.
type depricatedAddress struct {
	version uint64
	stream  uint64
	ripe    hash.Ripe
}

// NewDepricatedAddress creates a new depricated address.
func NewDepricatedAddress(version, stream uint64, ripe *hash.Ripe) (Address, error) {
	if version < 2 || version > 3 {
		return nil, ErrUnknownAddressType
	}
	return &depricatedAddress{
		version: version,
		stream:  stream,
		ripe:    *ripe,
	}, nil
}

func (addr *depricatedAddress) Version() uint64 {
	return addr.version
}

func (addr *depricatedAddress) Stream() uint64 {
	return addr.stream
}

func (addr *depricatedAddress) RipeHash() *hash.Ripe {
	return &addr.ripe
}

// String outputs the address to a string that begins with BM-.
// Output: [Varint(addressVersion) Varint(stream) ripe checksum] where the
// Varints are serialized. Then this byte array is base58 encoded to produce our
// needed address.
func (addr *depricatedAddress) String() string {
	ripe := addr.ripe[:]

	if ripe[0] == 0x00 {
		ripe = ripe[1:] // exclude first byte
		if ripe[0] == 0x00 {
			ripe = ripe[1:] // exclude second byte as well
		}
	}

	var binaryData bytes.Buffer
	WriteVarInt(&binaryData, addr.version)
	WriteVarInt(&binaryData, addr.stream)
	binaryData.Write(ripe)

	// calc checksum from 2 rounds of SHA512
	checksum := hash.DoubleSha512(binaryData.Bytes())[:4]

	totalBin := append(binaryData.Bytes(), checksum...)

	return "BM-" + string(base58.Encode(totalBin))
}

// DecodeAddress decodes the Bitmessage address into an Address object.
func DecodeAddress(addr string) (Address, error) {
	if len(addr) >= 3 && addr[:3] == "BM-" { // Clients should accept addresses without BM-
		addr = addr[3:]
	}

	data := base58.Decode(addr)
	if len(data) <= 12 { // rough lower bound, also don't want it to be empty
		return nil, ErrUnknownAddressType
	}

	hashData := data[:len(data)-4]
	checksum := data[len(data)-4:]

	if !bytes.Equal(checksum, hash.DoubleSha512(hashData)[0:4]) {
		return nil, ErrChecksumMismatch
	}

	buf := bytes.NewReader(data)
	var err error

	version, err := ReadVarInt(buf) // read version
	if err != nil {
		return nil, err
	}

	stream, err := ReadVarInt(buf) // read stream
	if err != nil {
		return nil, err
	}

	ripe := make([]byte, buf.Len()-4) // exclude bytes already read and checksum
	buf.Read(ripe)                    // this can never cause an error

	lenRipe := len(ripe)

	switch version {
	case 2:
		fallthrough
	case 3:
		if lenRipe > 19 || lenRipe < 18 { // improper size
			return nil, errors.New("version 3, the ripe length is invalid")
		}
		a := &depricatedAddress{
			version: version,
			stream:  stream,
		}
		// prepend null bytes to make sure that the total ripe length is 20
		copy(a.ripe[:], append(make([]byte, 20-lenRipe), ripe...))
		return a, nil
	case 4:
		// encoded ripe data MUST have null bytes removed from front
		if ripe[0] == 0x00 {
			return nil, errors.New("version 4, ripe data has null bytes in" +
				" the beginning, not properly encoded")
		}
		if lenRipe > 19 || lenRipe < 4 { // improper size
			return nil, errors.New("version 4, the ripe length is invalid")
		}
		a := &addressV4{
			stream: stream,
		}
		// prepend null bytes to make sure that the total ripe length is 20
		copy(a.ripe[:], append(make([]byte, 20-lenRipe), ripe...))
		return a, nil
	default:
		return nil, ErrUnknownAddressType
	}
}

// Sha512 calculates the sha512 sum of the address, the first half of
// which is used as private encryption key for v2 and v3 broadcasts.
func Sha512(addr Address) []byte {
	var b bytes.Buffer
	WriteVarInt(&b, addr.Version())
	WriteVarInt(&b, addr.Stream())
	b.Write(addr.RipeHash()[:])

	return hash.Sha512(b.Bytes())
}

// DoubleSha512 calculates the double sha512 sum of the address, the first
// half of which is used as private encryption key for the public key object
// and the second half is used as a tag.
func DoubleSha512(addr Address) []byte {
	return hash.Sha512(Sha512(addr))
}

// Tag calculates tag corresponding to the Bitmessage address. According to
// protocol specifications, it is the second half of the double SHA-512 hash
// of version, stream and ripe concatenated together.
func Tag(addr Address) []byte {
	var a = make([]byte, 32)
	copy(a, DoubleSha512(addr)[32:])
	return a
}

// V4BroadcastDecryptionKey generates the decryption private key used to decrypt v4
// broadcasts originating from the address. They are encrypted with the public
// key corresponding to this private key as the target key. It is the first half
// of the SHA-512 hash of version, stream and ripe concatenated together.
func V4BroadcastDecryptionKey(addr Address) *btcec.PrivateKey {
	pk := Sha512(addr)[:32]
	privKey, _ := btcec.PrivKeyFromBytes(btcec.S256(), pk)
	return privKey
}

// V5BroadcastDecryptionKey generates the decryption private key used
// to decrypt v4 pubkeys and v5 broadcasts originating from the address.
// Such objects are encrypted with the public key corresponding to this
// private key as the target key. It is the first half of the double SHA-512
// hash of version, stream and ripe concatenated together.
func V5BroadcastDecryptionKey(addr Address) *btcec.PrivateKey {
	pk := DoubleSha512(addr)[:32]
	privKey, _ := btcec.PrivKeyFromBytes(btcec.S256(), pk)
	return privKey
}
