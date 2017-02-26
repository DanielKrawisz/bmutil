// Copyright 2016 Daniel Krawisz.
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package cipher

import (
	"bytes"
	"crypto/sha512"
	"fmt"
	"io"
	"testing"
	"time"

	"github.com/btcsuite/btcutil/base58"
	"golang.org/x/crypto/ripemd160"

	. "github.com/DanielKrawisz/bmutil"
	"github.com/DanielKrawisz/bmutil/format"
	"github.com/DanielKrawisz/bmutil/hash"
	"github.com/DanielKrawisz/bmutil/identity"
	"github.com/DanielKrawisz/bmutil/pow"
	"github.com/DanielKrawisz/bmutil/wire"
	"github.com/DanielKrawisz/bmutil/wire/obj"
	"github.com/btcsuite/btcd/btcec"
)

var pubKey1 *wire.PubKey

var pubKey2 *wire.PubKey

var tag = &hash.Sha{
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
}

var encodedForEncryption2 = []byte{
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
}

var encodedForSigning1 = []byte{
	0x00, 0x00, 0x00, 0x00, 0x49, 0x5f, 0xab, 0x29,
	0x00, 0x00, 0x00, 0x01, 0x03, 0x01,

	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
}

var encodedForSigning2 = []byte{
	// Header
	0x00, 0x00, 0x00, 0x00, 0x49, 0x5f, 0xab, 0x29,
	0x00, 0x00, 0x00, 0x01, 0x04, 0x01,

	// Tag
	0x10, 0xe2, 0x64, 0xe3, 0x4f, 0x5c, 0xd3, 0x3f,
	0x9a, 0x21, 0xfe, 0x0e, 0xd4, 0x6d, 0xd4, 0x50,
	0xd9, 0xa5, 0xeb, 0x67, 0x1c, 0x0e, 0xd7, 0x90,
	0x3f, 0x69, 0x22, 0xb4, 0x28, 0x2f, 0x7f, 0x0a,

	// Body
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
}

// broadcastEncodedForEncryption is the data that is extracted from a broadcast
// message to be encrypted.
var broadcastEncodedForEncryption = []byte{
	0x03, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xfd, 0x04,
	0x00, 0xfd, 0x04, 0x00, 0x01, 0x20, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
}

// broadcastEncodedForSigning is the data that is signed in a broadcast.
var broadcastEncodedForSigning = []byte{
	0x00, 0x00, 0x00, 0x00, 0x49, 0x5f, 0xab, 0x29,
	0x00, 0x00, 0x00, 0x03, 0x05, 0x01, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00,

	0x03, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xfd, 0x04,
	0x00, 0xfd, 0x04, 0x00, 0x01, 0x20, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
}

var filledMsgEncodedForEncryption = []byte{
	0x04, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xfd, 0x04,
	0x00, 0xfd, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x01, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,
}

var filledMsgEncodedForSigning = []byte{
	0x00, 0x00, 0x00, 0x00, 0x49, 0x5f, 0xab, 0x29, // Timestamp
	0x00, 0x00, 0x00, 0x02, // ObjectType
	0x01, 0x01, 0x04, 0x01,
	0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0xfd, 0x04, 0x00, 0xfd,
	0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x20,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00,
}

// TstAddress implements Address but isn't as strict as the normal Address
// classes.
type TstAddress struct {
	version uint64
	stream  uint64
	ripe    *hash.Ripe
}

func (a *TstAddress) Version() uint64 {
	return a.version
}

func (a *TstAddress) Stream() uint64 {
	return a.stream
}

func (a *TstAddress) RipeHash() *hash.Ripe {
	return a.ripe
}

func (a *TstAddress) String() string {
	var ripe []byte

	if a.version > 3 {
		ripe = bytes.TrimLeft(a.ripe[:], "\x00")
	} else {
		ripe = a.ripe[:]

		if ripe[0] == 0x00 {
			ripe = ripe[1:] // exclude first byte
			if ripe[0] == 0x00 {
				ripe = ripe[1:] // exclude second byte as well
			}
		}
	}

	var binaryData bytes.Buffer
	WriteVarInt(&binaryData, a.Version())
	WriteVarInt(&binaryData, a.stream)
	binaryData.Write(ripe)

	// calc checksum from 2 rounds of SHA512
	checksum := hash.DoubleSha512(binaryData.Bytes())[:4]

	totalBin := append(binaryData.Bytes(), checksum...)

	return "BM-" + string(base58.Encode(totalBin))
}

// TestPublic implements the identity.Public interface and is used for
// testing purposes only.
type TstPublic struct {
	t       *testing.T
	version uint64
	stream  uint64
	data    *obj.PubKeyData
}

func NewTstPublic(t *testing.T, version, stream uint64, data *obj.PubKeyData) *TstPublic {
	return &TstPublic{
		t:       t,
		version: version,
		stream:  stream,
		data:    data,
	}
}

func (tp *TstPublic) Hash() *hash.Ripe {
	sha := sha512.New()
	ripemd := ripemd160.New()

	sha.Write(tp.data.Verification.Bytes())
	sha.Write(tp.data.Encryption.Bytes())

	ripemd.Write(sha.Sum(nil)) // take ripemd160 of required elements

	// Get the hash
	r, _ := hash.NewRipe(ripemd.Sum(nil))
	return r
}

func (tp *TstPublic) Key() *identity.PublicKey {
	p, err := identity.NewPublicKey(tp.data.Verification, tp.data.Encryption)
	if err != nil {
		tp.t.Fatal(err.Error())
	}
	return p
}

func (tp *TstPublic) Address() Address {
	return &TstAddress{
		tp.version,
		tp.stream,
		tp.Hash(),
	}
}

func (tp *TstPublic) Data() *obj.PubKeyData {
	return tp.data
}

func (tp *TstPublic) Behavior() uint32 {
	return tp.data.Behavior
}

func (tp *TstPublic) Pow() *pow.Data {
	return tp.data.Pow
}

func (tp *TstPublic) String() string {
	return fmt.Sprintf("tstpublic{version:%d, stream:%d, %s}", tp.version, tp.stream, tp.data.String())
}

func PrivAddr1() *identity.PrivateAddress {
	p, _ := identity.ImportWIF("BM-2cXm1jokUVp9Nn1kBtkeMjpxaLJuP3FwET",
		"5K3oNuMzVEWdrtyBAZXrPQwQTSmCGrAZS1groRDQVGDeccLim15",
		"5HzhkuimkuizxJyw9b7qnFEMtUrAXD25Y5AV1sZ964dSSXReKnb")
	return p
}

func PrivAddr2() *identity.PrivateAddress {
	p, _ := identity.ImportWIF("BM-2cTLMh1CufXWQ9co4CWzD9muDZP4a7N4MA",
		"5Jw6Gtjy8RCZ5BmTtyx3VykzdXvX4WyWsGu2wLrhfTv8zgKfo7C",
		"5JY8Lsf5cmNTrXXj1e7FkvCZVYgsK7tAiiocTDtVKLBvQm1EsFw")
	return p
}

func PrivID1() *identity.PrivateID {
	return identity.NewPrivateID(PrivAddr1(), identity.BehaviorAck,
		&pow.Default)
}

func PrivID2() *identity.PrivateID {
	return identity.NewPrivateID(PrivAddr2(), identity.BehaviorAck,
		&pow.Default)
}

func PrivKey1() *identity.PrivateKey {
	return PrivID1().PrivateKey()
}

func PrivKey2() *identity.PrivateKey {
	return PrivID2().PrivateKey()
}

var EncKey1, SignKey1, EncKey2, SignKey2 *wire.PubKey
var Tag1, Tag2 *hash.Sha

// Setup everything
func init() {
	var err error
	pubKey1, err = wire.NewPubKeyFromStr("fb369bf04e002ed58c50f54975b4747a108067196ffec7850859710e50e05f060a2d58cbc3a0375c218532e48adf04b498c7aaab5e69e3a8104c1332be95ca8a")
	pubKey2, err = wire.NewPubKeyFromStr("b64d7d66d18c4ae7df65f03b7d806fd6c154f3eea99fb611177b7eb4f505424f2607f47ae11ab5979773e3d017425f5c388520a52d1325540fdad362509bc2b5")

	copy(broadcastEncodedForEncryption[6:(6+64)], pubKey1.Bytes())
	copy(broadcastEncodedForEncryption[(6+64):(6+64+64)], pubKey2.Bytes())

	copy(broadcastEncodedForSigning[52:(52+64)], pubKey1.Bytes())
	copy(broadcastEncodedForSigning[(52+64):(52+64+64)], pubKey2.Bytes())

	copy(filledMsgEncodedForEncryption[6:(6+64)], pubKey1.Bytes())
	copy(filledMsgEncodedForEncryption[(6+64):(6+64+64)], pubKey2.Bytes())

	copy(filledMsgEncodedForSigning[20:(20+64)], pubKey1.Bytes())
	copy(filledMsgEncodedForSigning[(20+64):(20+64+64)], pubKey2.Bytes())

	copy(encodedForEncryption2[4:(4+64)], pubKey1.Bytes())
	copy(encodedForEncryption2[(4+64):(4+64+64)], pubKey2.Bytes())

	copy(encodedForSigning1[18:(18+64)], pubKey1.Bytes())
	copy(encodedForSigning1[(18+64):(18+64+64)], pubKey2.Bytes())

	copy(encodedForSigning2[50:(50+64)], pubKey1.Bytes())
	copy(encodedForSigning2[(50+64):(50+64+64)], pubKey2.Bytes())

	EncKey1, err = wire.NewPubKey(PrivKey1().Decryption.PubKey().SerializeUncompressed()[1:])
	SignKey1, err = wire.NewPubKey(PrivKey1().Signing.PubKey().SerializeUncompressed()[1:])

	EncKey2, err = wire.NewPubKey(PrivKey2().Decryption.PubKey().SerializeUncompressed()[1:])
	SignKey2, err = wire.NewPubKey(PrivKey2().Signing.PubKey().SerializeUncompressed()[1:])

	Tag1, err = hash.NewSha(Tag(PrivID1().Address()))
	Tag2, err = hash.NewSha(Tag(PrivID2().Address()))

	if err != nil {
		panic(err.Error())
	}
}

func TstGenerateForwardingData(key *wire.PubKey) []byte {
	var b bytes.Buffer
	attackPub := new(decryptedPubKey)
	attackPub.data = &obj.PubKeyData{
		Encryption:   key,
		Verification: key,
	}
	attackPub.EncodeForEncryption(&b)

	fd, err := btcec.Encrypt(V5BroadcastDecryptionKey(PrivID1().Address()).PubKey(),
		b.Bytes())
	if err != nil {
		panic("could not generate forwardingData")
	}

	return fd
}

func TstGenerateInvalidSig() []byte {
	var b bytes.Buffer
	attackPub := new(decryptedPubKey)
	attackPub.data = &obj.PubKeyData{}
	attackPub.data.Encryption, _ = wire.NewPubKey(PrivKey1().Decryption.PubKey().SerializeUncompressed()[1:])
	attackPub.data.Verification, _ = wire.NewPubKey(PrivKey1().Signing.PubKey().SerializeUncompressed()[1:])
	attackPub.signature = []byte{0x00}
	attackPub.EncodeForEncryption(&b)

	invalidSig, err := btcec.Encrypt(V5BroadcastDecryptionKey(PrivID1().Address()).PubKey(),
		b.Bytes())
	if err != nil {
		panic("could not generate invalidSig")
	}

	return invalidSig
}

func TstGenerateMismatchSig() []byte {
	var b bytes.Buffer
	attackPub := new(decryptedPubKey)
	attackPub.object = obj.NewEncryptedPubKey(0, time.Time{}, 0, Tag1, nil)
	attackPub.data = &obj.PubKeyData{}
	attackPub.data.Encryption, _ = wire.NewPubKey(PrivKey1().Decryption.PubKey().SerializeUncompressed()[1:])
	attackPub.data.Verification, _ = wire.NewPubKey(PrivKey1().Signing.PubKey().SerializeUncompressed()[1:])
	attackPub.EncodeForSigning(&b)
	// should actually be hash
	sig, _ := PrivKey1().Decryption.Sign(b.Bytes())
	attackPub.signature = sig.Serialize()

	b.Reset()
	attackPub.EncodeForEncryption(&b)

	mismatchSig, err := btcec.Encrypt(V5BroadcastDecryptionKey(PrivID1().Address()).PubKey(),
		b.Bytes())
	if err != nil {
		panic("could not generate mismatchedSig")
	}

	return mismatchSig
}

func (b *Broadcast) SetMessage(n *Broadcast) {
	b.msg = n.msg
}

func (b *Message) SetMessage(n *Message) {
	b.msg = n.msg
}

func tstNewExtendedPubKey(nonce pow.Nonce, expires time.Time, streamNumber uint64,
	behavior uint32, signingKey, encKey *wire.PubKey, nonceTrials,
	extraBytes uint64, signature []byte) *obj.ExtendedPubKey {

	return obj.NewExtendedPubKey(0, expires, streamNumber,
		&obj.PubKeyData{
			Behavior:     behavior,
			Verification: signingKey,
			Encryption:   encKey,
			Pow: &pow.Data{
				NonceTrialsPerByte: nonceTrials,
				ExtraBytes:         extraBytes,
			},
		}, signature)
}

func tstNewDecryptedPubKey(nonce pow.Nonce, expires time.Time, streamNumber uint64,
	behavior uint32, signingKey, encryptKey *wire.PubKey, nonceTrials,
	extraBytes uint64, signature []byte, tag *hash.Sha, encrypted []byte) *decryptedPubKey {
	return &decryptedPubKey{
		object: obj.NewEncryptedPubKey(nonce, expires, streamNumber, tag, encrypted),
		data: &obj.PubKeyData{
			Behavior:     behavior,
			Verification: signingKey,
			Encryption:   encryptKey,
			Pow: &pow.Data{
				NonceTrialsPerByte: nonceTrials,
				ExtraBytes:         extraBytes,
			},
		},
		signature: signature,
	}
}

func TstNewExtendedPubKey(nonce pow.Nonce, expires time.Time, streamNumber uint64,
	behavior uint32, signingKey, encKey *wire.PubKey, nonceTrials,
	extraBytes uint64, private *identity.PrivateKey) *obj.ExtendedPubKey {

	ep := tstNewExtendedPubKey(nonce, expires, streamNumber,
		behavior, signingKey, encKey, nonceTrials, extraBytes, nil)

	if private != nil {
		signExtendedPubKey(ep, private)
	}

	return ep
}

func TstNewDecryptedPubKey(nonce pow.Nonce, expires time.Time, streamNumber uint64,
	behavior uint32, signingKey, encKey *wire.PubKey, nonceTrials, extraBytes uint64,
	signature []byte, tag *hash.Sha, encrypted []byte, private *identity.PrivateID) PubKeyObject {

	dk := tstNewDecryptedPubKey(nonce, expires, streamNumber,
		behavior, signingKey, encKey, nonceTrials, extraBytes, signature, tag, encrypted)

	if encrypted == nil && private != nil {
		dk.signAndEncrypt(private)
	}

	return dk
}

type TstBroadcast struct {
	i         incompleteBroadcast
	Data      *Bitmessage
	Signature []byte
	Private   *identity.PrivateID
}

func (tb *TstBroadcast) EncodeForSigning(w io.Writer) error {
	return broadcastEncodeForSigning(w, tb.i, tb.Data)
}

func TstNewBroadcast(t *testing.T, nonce pow.Nonce, expires time.Time, streamNumber uint64,
	tag *hash.Sha, encrypted []byte, fromAddressVersion, fromStreamNumber uint64,
	behavior uint32, vk, ek *wire.PubKey, powData pow.Data,
	encoding uint64, message, signature []byte, private *identity.PrivateID) (*Broadcast, *TstBroadcast) {

	var stream uint64
	if private != nil {
		stream = private.Address().Stream()
	}

	var msg obj.Broadcast
	var i incompleteBroadcast
	if tag != nil {
		msg = obj.NewTaggedBroadcast(nonce, expires, streamNumber, tag, encrypted)
		i = &incompleteTaggedBroadcast{expires, stream, tag}
	} else {
		msg = obj.NewTaglessBroadcast(nonce, expires, streamNumber, encrypted)
		i = &incompleteTaglessBroadcast{expires, stream}
	}

	content, err := format.Read(encoding, message)
	if err != nil {
		panic(err.Error())
	}

	pk, err := identity.NewPublicKey(vk, ek)
	if err != nil {
		panic(err.Error())
	}

	public, err := identity.NewPublic(pk,
		fromAddressVersion,
		fromStreamNumber,
		behavior, &powData)
	if err != nil {
		t.Fatal(err.Error())
	}

	data := &Bitmessage{
		Public:  public,
		Content: content,
	}

	return &Broadcast{
			msg: msg,
			sig: signature,
			bm:  data,
		}, &TstBroadcast{
			i:         i,
			Data:      data,
			Signature: signature,
			Private:   private,
		}
}

func TstNewTstBroadcast(t *testing.T, nonce pow.Nonce, expires time.Time, streamNumber uint64,
	tag *hash.Sha, encrypted []byte, fromAddressVersion, fromStreamNumber uint64,
	behavior uint32, vk, ek *wire.PubKey, powData pow.Data,
	encoding uint64, message, signature []byte, private *identity.PrivateID) (*Broadcast, *TstBroadcast) {

	var stream uint64
	if private != nil {
		stream = private.Address().Stream()
	}

	var msg obj.Broadcast
	var i incompleteBroadcast
	if tag != nil {
		msg = obj.NewTaggedBroadcast(nonce, expires, streamNumber, tag, encrypted)
		i = &incompleteTaggedBroadcast{expires, stream, tag}
	} else {
		msg = obj.NewTaglessBroadcast(nonce, expires, streamNumber, encrypted)
		i = &incompleteTaglessBroadcast{expires, stream}
	}

	content, err := format.Read(encoding, message)
	if err != nil {
		panic(err.Error())
	}

	public := NewTstPublic(t,
		fromAddressVersion,
		fromStreamNumber,
		&obj.PubKeyData{
			Verification: vk,
			Encryption:   ek,
			Behavior:     behavior,
			Pow:          &powData,
		})

	data := &Bitmessage{
		Public:  public,
		Content: content,
	}

	return &Broadcast{
			msg: msg,
			sig: signature,
			bm:  data,
		}, &TstBroadcast{
			i:         i,
			Data:      data,
			Signature: signature,
			Private:   private,
		}
}

func TstBroadcastEncryptParams(t *testing.T, expires time.Time, streamNumber uint64,
	tag *hash.Sha, fromAddressVersion, fromStreamNumber uint64,
	behavior uint32, vk, ek *wire.PubKey, nonceTrials, extraBytes,
	encoding uint64, message []byte, private *identity.PrivateID) (time.Time, *Bitmessage, *hash.Sha, *identity.PrivateID) {

	content, err := format.Read(encoding, message)
	if err != nil {
		panic(err.Error())
	}

	pk, err := identity.NewPublicKey(vk, ek)
	if err != nil {
		t.Fatal(err.Error())
	}

	public, err := identity.NewPublic(pk,
		fromAddressVersion,
		fromStreamNumber,
		behavior,
		&pow.Data{
			NonceTrialsPerByte: nonceTrials,
			ExtraBytes:         extraBytes,
		})
	if err != nil {
		t.Fatal(err.Error())
	}

	return expires, &Bitmessage{
		Public:  public,
		Content: content,
	}, tag, private
}

func TstGenerateBroadcastErrorData(t *testing.T, validPubkey *wire.PubKey) (invSigningKey,
	invEncKey, forwardingData, invalidSig, mismatchSig []byte) {

	{
		var b bytes.Buffer
		attackB, _ := TstNewTstBroadcast(t, 0, time.Now().Add(time.Minute*5).Truncate(time.Second),
			1, Tag1, nil, 0, 0, 0, &wire.PubKey{}, validPubkey,
			pow.Data{0, 0},
			1, []byte{0x00}, nil, nil)
		attackB.encodeForEncryption(&b)
		invSigningKey, _ = btcec.Encrypt(V5BroadcastDecryptionKey(PrivID1().Address()).PubKey(),
			b.Bytes())
	}

	{
		var b bytes.Buffer
		attackB, _ := TstNewTstBroadcast(t, 0, time.Now().Add(time.Minute*5).Truncate(time.Second),
			1, Tag1, nil, 0, 0, 0, validPubkey, &wire.PubKey{},
			pow.Data{0, 0},
			1, []byte{0x00}, nil, nil)
		attackB.encodeForEncryption(&b)
		invEncKey, _ = btcec.Encrypt(V5BroadcastDecryptionKey(PrivID1().Address()).PubKey(),
			b.Bytes())
	}

	{
		var b bytes.Buffer
		attackB, _ := TstNewTstBroadcast(t, 0, time.Now().Add(time.Minute*5).Truncate(time.Second),
			1, Tag1, nil, 4, 1, 0, validPubkey, validPubkey,
			pow.Data{0, 0},
			1, []byte{0x00}, nil, nil)
		attackB.encodeForEncryption(&b)
		forwardingData, _ = btcec.Encrypt(V5BroadcastDecryptionKey(PrivID1().Address()).PubKey(),
			b.Bytes())
	}

	var attackB *Broadcast
	{
		var b bytes.Buffer
		sk, _ := wire.NewPubKey(PrivKey1().Signing.PubKey().SerializeUncompressed()[1:])
		ek, _ := wire.NewPubKey(PrivKey1().Decryption.PubKey().SerializeUncompressed()[1:])
		attackB, _ = TstNewTstBroadcast(t, 0, time.Now().Add(time.Minute*5).Truncate(time.Second),
			1, Tag1, nil, 4, 1, 0, sk, ek,
			pow.Data{0, 0},
			1, []byte{0x00}, nil, nil)
		attackB.encodeForEncryption(&b)
		invalidSig, _ = btcec.Encrypt(V5BroadcastDecryptionKey(PrivID1().Address()).PubKey(),
			b.Bytes())
	}

	{
		var b bytes.Buffer
		attackB.encodeForSigning(&b)
		// should actually be hash
		sig, _ := PrivKey1().Decryption.Sign(b.Bytes())
		attackB.sig = sig.Serialize()
		b.Reset()
		attackB.encodeForEncryption(&b)
		mismatchSig, _ = btcec.Encrypt(V5BroadcastDecryptionKey(PrivID1().Address()).PubKey(),
			b.Bytes())
	}

	return
}

func TstNewMessage(t *testing.T, nonce pow.Nonce, expires time.Time, streamNumber uint64,
	encrypted []byte, addressVersion, fromStreamNumber uint64, behavior uint32,
	vk, ek *wire.PubKey, powData *pow.Data,
	destination *hash.Ripe, encoding uint64,
	message, ack, signature []byte) *Message {

	msg := obj.NewMessage(nonce, expires, streamNumber, encrypted)

	content, err := format.Read(encoding, message)
	if err != nil {
		panic(err.Error())
	}

	if vk == nil || ek == nil {
		panic("pubkey is nil")
	}

	pk, err := identity.NewPublicKey(vk, ek)
	if err != nil {
		t.Fatal(err.Error())
	}

	public, err := identity.NewPublic(pk,
		addressVersion,
		fromStreamNumber,
		behavior,
		powData)
	if err != nil {
		t.Fatal(err.Error())
	}

	return &Message{
		msg: msg,
		bm: &Bitmessage{
			Public:      public,
			Destination: destination,
			Content:     content,
		},
		ack: ack,
		sig: signature,
	}
}

func TstNewTstMessage(t *testing.T, nonce pow.Nonce, expires time.Time, streamNumber uint64,
	encrypted []byte, addressVersion, fromStreamNumber uint64, behavior uint32,
	vk, ek *wire.PubKey, powData *pow.Data, destination *hash.Ripe, encoding uint64,
	message, ack, signature []byte) *Message {

	msg := obj.NewMessage(nonce, expires, streamNumber, encrypted)

	content, err := format.Read(encoding, message)
	if err != nil {
		panic(err.Error())
	}

	public := NewTstPublic(t,
		addressVersion,
		fromStreamNumber,
		&obj.PubKeyData{
			Behavior:     behavior,
			Verification: vk,
			Encryption:   ek,
			Pow:          powData,
		})

	return &Message{
		msg: msg,
		bm: &Bitmessage{
			Public:      public,
			Destination: destination,
			Content:     content,
		},
		ack: ack,
		sig: signature,
	}
}

func TstSignAndEncryptMessage(t *testing.T, nonce uint64, expires time.Time, streamNumber uint64,
	encrypted []byte, addressVersion, fromStreamNumber uint64, behavior uint32,
	vk, ek *wire.PubKey, powData *pow.Data,
	destination *hash.Ripe, encoding uint64, message, ack, signature []byte,
	privID *identity.PrivateKey, pubID *identity.PublicKey) (*Message, error) {

	if encrypted == nil && signature != nil {
		panic("Test setup err A")
	}

	if encrypted != nil && nonce != 0 {
		panic("Test setup err B")
	}

	if encrypted == nil && privID == nil {
		panic("Test setup err C")
	}

	if encrypted != nil {
		panic("Test setup err D")
	}

	content, err := format.Read(encoding, message)
	if err != nil {
		panic(err.Error())
	}

	pk, err := identity.NewPublicKey(vk, ek)
	if err != nil {
		panic(err)
	}

	public, err := identity.NewPublic(pk, addressVersion, fromStreamNumber, behavior, powData)

	data := &Bitmessage{
		Public:      public,
		Destination: destination,
		Content:     content,
	}

	return SignAndEncryptMessage(expires, streamNumber, data, ack, privID, pubID)
}

func TstGenerateMessageErrorData(t *testing.T, validPubkey *wire.PubKey) (invDest,
	invSigningKey, invalidSig, mismatchSig []byte) {

	{
		var b bytes.Buffer
		var err error
		attackB := TstNewTstMessage(t, 0, time.Now().Add(time.Minute*5).Truncate(time.Second),
			1, nil, 0, 0, 0, &wire.PubKey{}, &wire.PubKey{}, &pow.Data{0, 0},
			&hash.Ripe{}, 1, []byte{0x00}, []byte{}, nil)
		attackB.encodeForEncryption(&b)
		invDest, err = btcec.Encrypt(PrivKey1().Decryption.PubKey(), b.Bytes())
		if err != nil {
			panic(err)
		}
	}

	{
		var b bytes.Buffer
		var err error
		attackB := TstNewTstMessage(t, 0, time.Now().Add(time.Minute*5).Truncate(time.Second),
			1, nil, 0, 0, 0, &wire.PubKey{}, validPubkey, &pow.Data{0, 0},
			&hash.Ripe{}, 1, []byte{0x00}, []byte{}, nil)
		attackB.bm.Destination, _ = hash.NewRipe(PrivID1().Address().RipeHash()[:])
		attackB.encodeForEncryption(&b)
		invSigningKey, err = btcec.Encrypt(PrivKey1().Decryption.PubKey(), b.Bytes())
		if err != nil {
			panic(err)
		}
	}

	{
		var b bytes.Buffer
		var err error
		verification, err := wire.NewPubKey(PrivKey2().Signing.PubKey().SerializeUncompressed()[1:])
		encryption, err := wire.NewPubKey(PrivKey2().Decryption.PubKey().SerializeUncompressed()[1:])
		if err != nil {
			panic(err)
		}
		attackB := TstNewTstMessage(t, 0, time.Now().Add(time.Minute*5).Truncate(time.Second),
			1, nil, 0, 0, 0, verification, encryption, &pow.Data{0, 0},
			&hash.Ripe{}, 1, []byte{0x00}, []byte{}, nil)
		attackB.sig = []byte{0x00}
		attackB.encodeForEncryption(&b)
		invalidSig, _ = btcec.Encrypt(PrivKey1().Decryption.PubKey(), b.Bytes())
	}

	{
		var b bytes.Buffer
		var err error
		attackB := TstNewTstMessage(t, 0, time.Now().Add(time.Minute*5).Truncate(time.Second),
			1, nil, 0, 0, 0, &wire.PubKey{}, &wire.PubKey{}, &pow.Data{0, 0},
			&hash.Ripe{}, 1, []byte{0x00}, []byte{}, nil)
		attackB.encodeForSigning(&b)
		// should actually be hash
		sig, err := PrivKey1().Decryption.Sign(b.Bytes())
		if err != nil {
			panic(err)
		}
		attackB.sig = sig.Serialize()
		b.Reset()
		attackB.encodeForEncryption(&b)
		mismatchSig, _ = btcec.Encrypt(PrivKey1().Decryption.PubKey(), b.Bytes())
	}

	return
}
