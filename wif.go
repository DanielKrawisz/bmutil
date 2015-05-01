// Copyright (c) 2015 Monetas
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package bmutil

import (
	"bytes"
	"crypto/sha256"
	"errors"

	"github.com/btcsuite/btcd/btcec"
	"github.com/btcsuite/btcutil/base58"
)

// ErrMalformedPrivateKey describes an error where a WIF-encoded private
// key cannot be decoded due to being improperly formatted.  This may occur
// if the byte length is incorrect or an unexpected magic number was
// encountered.
var ErrMalformedPrivateKey = errors.New("malformed private key")

const wifPrefix = 0x80

// DecodeWIF creates a btcec.PrivateKey by decoding the string encoding of
// the import format. It only supports uncompressed keys.
//
// The WIF string must be a base58-encoded string of the following byte
// sequence:
//
//  * 1 byte to identify the network, must be 0x80
//  * 32 bytes of a binary-encoded, big-endian, zero-padded private key
//  * 4 bytes of checksum, must equal the first four bytes of the double SHA256
//    of every byte before the checksum in this sequence
//
// If the base58-decoded byte sequence does not match this, DecodeWIF will
// return a non-nil error. ErrMalformedPrivateKey is returned when the WIF
// is of an impossible length or the expected compressed pubkey magic number
// does not equal the expected value of 0x01. ErrChecksumMismatch is returned
// if the expected WIF checksum does not match the calculated checksum.
func DecodeWIF(wif string) (*btcec.PrivateKey, error) {
	decoded := base58.Decode(wif)
	decodedLen := len(decoded)

	// Length of base58 decoded WIF must be 32 bytes + 1 byte for netID +
	// 4 bytes of checksum.
	if decodedLen != 1+btcec.PrivKeyBytesLen+4 || decoded[0] != wifPrefix {
		return nil, ErrMalformedPrivateKey
	}

	// Checksum is first four bytes of double SHA256 of the identifier byte
	// and privKey.  Verify this matches the final 4 bytes of the decoded
	// private key.
	tosum := decoded[:1+btcec.PrivKeyBytesLen]

	cksum := doubleSha256(tosum)[:4]
	if !bytes.Equal(cksum, decoded[decodedLen-4:]) {
		return nil, ErrChecksumMismatch
	}

	privKeyBytes := decoded[1 : 1+btcec.PrivKeyBytesLen]
	privKey, _ := btcec.PrivKeyFromBytes(btcec.S256(), privKeyBytes)
	return privKey, nil
}

// EncodeWIF creates the Wallet Import Format string encoding of a WIF
// structure. See DecodeWIF for a detailed breakdown of the format and
// requirements of a valid WIF string.
func EncodeWIF(privKey *btcec.PrivateKey) string {
	// Precalculate size. Number of bytes before base58 encoding
	// is one byte for the network, 32 bytes of private key and four
	// bytes of checksum.
	a := make([]byte, 0, 1+btcec.PrivKeyBytesLen+4)
	a = append(a, wifPrefix)
	// Pad and append bytes manually, instead of using Serialize, to
	// avoid another call to make.
	a = paddedAppend(btcec.PrivKeyBytesLen, a, privKey.D.Bytes())
	cksum := doubleSha256(a)[:4]
	a = append(a, cksum...)
	return base58.Encode(a)
}

// paddedAppend appends the src byte slice to dst, returning the new slice.
// If the length of the source is smaller than the passed size, leading zero
// bytes are appended to the dst slice before appending src.
func paddedAppend(size uint, dst, src []byte) []byte {
	for i := 0; i < int(size)-len(src); i++ {
		dst = append(dst, 0)
	}
	return append(dst, src...)
}

// doubleSha256 returns the sha256^2 of the bytes
func doubleSha256(b []byte) []byte {
	h := sha256.New()
	h.Reset()
	h.Write(b)
	hash1 := h.Sum(nil) // first round
	h.Reset()
	h.Write(hash1)
	return h.Sum(nil) // second round
}
