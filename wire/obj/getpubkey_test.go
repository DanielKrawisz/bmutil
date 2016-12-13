// Copyright (c) 2015 Monetas
// Copyright 2016 Daniel Krawisz.
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package obj_test

import (
	"bytes"
	"io"
	"reflect"
	"testing"
	"time"

	"github.com/DanielKrawisz/bmutil/wire"
	"github.com/DanielKrawisz/bmutil/wire/fixed"
	"github.com/DanielKrawisz/bmutil/wire/obj"
	"github.com/davecgh/go-spew/spew"
)

// TestGetPubKeyWire tests the GetPubKey wire.encode and decode for various numbers
// of objectentory vectors and protocol versions.
func TestGetPubKeyWire(t *testing.T) {

	ripeBytes := make([]byte, 20)
	ripeBytes[0] = 1
	ripe, err := wire.NewRipeHash(ripeBytes)
	if err != nil {
		t.Fatalf("could not make a ripe hash %s", err)
	}

	expires := time.Unix(0x495fab29, 0) // 2009-01-03 12:15:05 -0600 CST)

	// empty tag, something in ripe
	msgRipe := obj.NewGetPubKey(83928, expires, 2, 1, ripe, nil)

	// empty ripe, something in tag
	tagBytes := make([]byte, wire.HashSize)
	tagBytes[0] = 1
	tag, err := wire.NewShaHash(tagBytes)
	if err != nil {
		t.Fatalf("could not make a tag hash %s", err)
	}
	msgTag := obj.NewGetPubKey(83928, expires, 4, 1, nil, tag)

	RipeEncoded := []byte{
		0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x47, 0xd8, // 83928 nonce
		0x00, 0x00, 0x00, 0x00, 0x49, 0x5f, 0xab, 0x29, // 64-bit timestamp
		0x00, 0x00, 0x00, 0x00, // object type (GETPUBKEY)
		0x02, // object version
		0x01, // stream number
		0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, // 20-byte ripemd
	}

	TagEncoded := []byte{
		0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x47, 0xd8, // 83928 nonce
		0x00, 0x00, 0x00, 0x00, 0x49, 0x5f, 0xab, 0x29, // 64-bit timestamp
		0x00, 0x00, 0x00, 0x00, // object type (GETPUBKEY)
		0x04, // object version
		0x01, // stream number
		0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 32-byte sha
	}

	tests := []struct {
		in  *obj.GetPubKey // Message to encode
		out *obj.GetPubKey // Expected decoded message
		buf []byte         // Wire encoding
	}{
		// Latest protocol version with multiple object vectors.
		{
			msgRipe,
			msgRipe,
			RipeEncoded,
		},
		{
			msgTag,
			msgTag,
			TagEncoded,
		},
	}

	t.Logf("Running %d tests", len(tests))
	for i, test := range tests {
		// Encode the message to wire.format.
		var buf bytes.Buffer
		err := test.in.Encode(&buf)
		if err != nil {
			t.Errorf("Encode #%d error %v", i, err)
			continue
		}
		if !bytes.Equal(buf.Bytes(), test.buf) {
			t.Errorf("Encode #%d\n got: %s want: %s", i,
				spew.Sdump(buf.Bytes()), spew.Sdump(test.buf))
			continue
		}

		// Decode the message from wire.format.
		var msg obj.GetPubKey
		rbuf := bytes.NewReader(test.buf)
		err = msg.Decode(rbuf)
		if err != nil {
			t.Errorf("Decode #%d error %v", i, err)
			continue
		}
		if !reflect.DeepEqual(&msg, test.out) {
			t.Errorf("Decode #%d\n got: %s want: %s", i,
				spew.Sdump(msg), spew.Sdump(test.out))
			continue
		}
	}
}

// TestGetPubKeyWireError tests the GetPubKey error paths
func TestGetPubKeyWireError(t *testing.T) {
	wireErr := &wire.MessageError{}

	baseGetPubKey := obj.TstBaseGetPubKey()
	tagGetPubKey := obj.TstTagGetPubKey()
	invalidGetPubKeyVersion := obj.TstInvalidGetPubKeyVersion()

	tests := []struct {
		in       *obj.GetPubKey // Value to encode
		buf      []byte         // Wire encoding
		max      int            // Max size of fixed buffer to induce errors
		writeErr error          // Expected write error
		readErr  error          // Expected read error
	}{
		// Force error in nonce
		{baseGetPubKey, baseGetPubKeyEncoded, 0, io.ErrShortWrite, io.EOF},
		// Force error in expirestime.
		{baseGetPubKey, baseGetPubKeyEncoded, 8, io.ErrShortWrite, io.EOF},
		// Force error in object type.
		{baseGetPubKey, baseGetPubKeyEncoded, 16, io.ErrShortWrite, io.EOF},
		// Force error in version.
		{baseGetPubKey, baseGetPubKeyEncoded, 20, io.ErrShortWrite, io.EOF},
		// Force error in stream number.
		{baseGetPubKey, baseGetPubKeyEncoded, 21, io.ErrShortWrite, io.EOF},
		// Force error in ripe.
		{baseGetPubKey, baseGetPubKeyEncoded, 22, io.ErrShortWrite, io.EOF},
		// Force error in tag.
		{tagGetPubKey, tagGetPubKeyEncoded, 22, io.ErrShortWrite, io.EOF},
		// Force error object type validation.
		{baseGetPubKey, basePubKeyEncoded, 22, io.ErrShortWrite, wireErr},
		// Force invalid pubkey version error.
		{invalidGetPubKeyVersion, invalidGetPubKeyVersionEncoded, 22, wireErr, wireErr},
	}

	t.Logf("Running %d tests", len(tests))
	for i, test := range tests {
		// Encode to wire.format.
		w := fixed.NewWriter(test.max)
		err := test.in.Encode(w)
		if reflect.TypeOf(err) != reflect.TypeOf(test.writeErr) {
			t.Errorf("Encode #%d wrong error got: %v, want: %v",
				i, err, test.writeErr)
			continue
		}

		// For errors which are not of type wire.MessageError, check
		// them for equality.
		if _, ok := err.(*wire.MessageError); !ok {
			if err != test.writeErr {
				t.Errorf("Encode #%d wrong error got: %v, "+
					"want: %v", i, err, test.writeErr)
				continue
			}
		}

		// Decode from wire.format.
		var msg obj.GetPubKey
		buf := bytes.NewBuffer(test.buf[0:test.max])
		err = msg.Decode(buf)
		if reflect.TypeOf(err) != reflect.TypeOf(test.readErr) {
			t.Errorf("Decode #%d wrong error got: %v, want: %v",
				i, err, test.readErr)
			continue
		}

		// For errors which are not of type wire.MessageError, check
		// them for equality.
		if _, ok := err.(*wire.MessageError); !ok {
			if err != test.readErr {
				t.Errorf("Decode #%d wrong error got: %v, "+
					"want: %v", i, err, test.readErr)
				continue
			}
		}
	}
}

// baseGetPubKeyEncoded is the wire.encoded bytes for baseGetPubKey
// using version 2 (pre-tag
var baseGetPubKeyEncoded = []byte{
	0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0xe0, 0xf3, // Nonce
	0x00, 0x00, 0x00, 0x00, 0x49, 0x5f, 0xab, 0x29, // 64-bit Timestamp
	0x00, 0x00, 0x00, 0x00, // object type
	0x03, // Version
	0x01, // Stream Number
	0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, // Ripe
}

// tagGetPubKeyEncoded is the wire.encoded bytes for a v4 pubkey which includes
// a tag.
var tagGetPubKeyEncoded = []byte{
	0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0xe0, 0xf3, // Nonce
	0x00, 0x00, 0x00, 0x00, 0x49, 0x5f, 0xab, 0x29, // 64-bit Timestamp
	0x00, 0x00, 0x00, 0x00, // object type
	0x04, // Version
	0x01, // Stream Number
	0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Ripe
}

// invalidVersionEncoded is an encoded getpubkey message with unsupported version
var invalidGetPubKeyVersionEncoded = []byte{
	0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0xe0, 0xf3, // Nonce
	0x00, 0x00, 0x00, 0x00, 0x49, 0x5f, 0xab, 0x29, // 64-bit Timestamp
	0x00, 0x00, 0x00, 0x00, // object type
	0x05, // Version
	0x01, // Stream Number
	0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, // Ripe
}
