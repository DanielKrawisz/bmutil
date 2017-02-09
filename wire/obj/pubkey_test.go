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

	"github.com/DanielKrawisz/bmutil/pow"
	"github.com/DanielKrawisz/bmutil/wire"
	"github.com/DanielKrawisz/bmutil/wire/fixed"
	"github.com/DanielKrawisz/bmutil/wire/obj"
	"github.com/davecgh/go-spew/spew"
)

// TestPubKey tests the MsgPubKey API.
func TestPubKey(t *testing.T) {

	now := time.Now()
	tests := []wire.Message{
		obj.NewSimplePubKey(83928, now, 1,
			&obj.PubKeyData{
				Behavior:        0,
				VerificationKey: pubKey1,
				EncryptionKey:   pubKey2,
			}),
		obj.NewExtendedPubKey(83928, now, 1,
			&obj.PubKeyData{
				Behavior:        0,
				VerificationKey: pubKey1,
				EncryptionKey:   pubKey2,
				Pow: &pow.Data{
					NonceTrialsPerByte: 0,
					ExtraBytes:         0,
				},
			}, []byte{0, 0, 0}),
		obj.NewEncryptedPubKey(83928, now, 1, tag, []byte{1, 1, 1}),
	}

	// Ensure max payload is expected value for latest protocol version.
	wantPayload := wire.MaxPayloadOfMsgObject

	for _, test := range tests {
		maxPayload := test.MaxPayloadLength()
		if maxPayload != wantPayload {
			t.Errorf("MaxPayloadLength: wrong max payload length for "+
				"- got %v, want %v", maxPayload, wantPayload)
		}

		// Ensure the command is expected value.
		cmd := test.Command()
		if cmd != "object" {
			t.Errorf("Wrong command returned: got %v, want %v", cmd, "object")
		}
	}

	return
}

// TestPubKeyWire tests the MsgPubKey wire.encode and decode for
// various versions.
func TestPubKeyWire(t *testing.T) {
	expires := time.Unix(0x495fab29, 0) // 2009-01-03 12:15:05 -0600 CST)
	sig := make([]byte, 64)
	encrypted := make([]byte, 512)
	msgBase := obj.NewSimplePubKey(83928, expires, 1,
		&obj.PubKeyData{0, pubKey1, pubKey2, nil})
	msgExpanded := obj.NewExtendedPubKey(83928, expires, 1,
		&obj.PubKeyData{
			Behavior:        0,
			VerificationKey: pubKey1,
			EncryptionKey:   pubKey2,
			Pow: &pow.Data{
				NonceTrialsPerByte: 0,
				ExtraBytes:         0,
			},
		}, sig)
	tagBytes := make([]byte, 32)
	tagBytes[0] = 1
	tag, err := wire.NewShaHash(tagBytes)
	if err != nil {
		t.Fatalf("could not make a tag hash %s", err)
	}
	msgEncrypted := obj.NewEncryptedPubKey(83928, expires, 1, tag, encrypted)

	tests := []struct {
		in   obj.Object // Message to encode
		out  obj.Object // Expected decoded message
		base obj.Object // Object to use to decode it.
		buf  []byte     // Wire encoding
	}{
		// Latest protocol version with multiple object vectors.
		{
			msgBase,
			msgBase,
			&obj.SimplePubKey{},
			basePubKeyEncoded,
		},
		{
			msgExpanded,
			msgExpanded,
			&obj.ExtendedPubKey{},
			expandedPubKeyEncoded,
		},
		{
			msgEncrypted,
			msgEncrypted,
			&obj.EncryptedPubKey{},
			encryptedPubKeyEncoded,
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
		rbuf := bytes.NewReader(test.buf)
		err = test.base.Decode(rbuf)
		if err != nil {
			t.Errorf("Decode #%d error %v", i, err)
			continue
		}
		if !reflect.DeepEqual(test.base, test.out) {
			t.Errorf("Decode #%d\n got: %s want: %s", i,
				spew.Sdump(test.base), spew.Sdump(test.out))
			continue
		}
	}
}

// TestPubKeyWireError tests the MsgPubKey error paths
func TestPubKeyWireError(t *testing.T) {
	wireErr := &wire.MessageError{}

	wrongObjectTypeEncoded := make([]byte, len(basePubKeyEncoded))
	copy(wrongObjectTypeEncoded, basePubKeyEncoded)
	wrongObjectTypeEncoded[19] = 0

	basePubKey := obj.TstBasePubKey(pubKey1, pubKey2)
	expandedPubKey := obj.TstExpandedPubKey(pubKey1, pubKey2)
	encryptedPubKey := obj.TstEncryptedPubKey(tag)

	tests := []struct {
		base     obj.Object // Value to decode
		in       obj.Object // Value to encode
		buf      []byte     // Wire encoding
		max      int        // Max size of fixed buffer to induce errors
		writeErr error      // Expected write error
		readErr  error      // Expected read error
	}{
		// Force error in nonce
		{&obj.SimplePubKey{}, basePubKey, basePubKeyEncoded, 0, io.ErrShortWrite, io.EOF},
		// Force error in expirestime.
		{&obj.SimplePubKey{}, basePubKey, basePubKeyEncoded, 8, io.ErrShortWrite, io.EOF},
		// Force error in object type.
		{&obj.SimplePubKey{}, basePubKey, basePubKeyEncoded, 16, io.ErrShortWrite, io.EOF},
		// Force error in version.
		{&obj.SimplePubKey{}, basePubKey, basePubKeyEncoded, 20, io.ErrShortWrite, io.EOF},
		// Force error in stream number.
		{&obj.SimplePubKey{}, basePubKey, basePubKeyEncoded, 21, io.ErrShortWrite, io.EOF},
		// Force error object type validation.
		{&obj.SimplePubKey{}, basePubKey, wrongObjectTypeEncoded, 52, io.ErrShortWrite, wireErr},
		// Force error in Tag
		{&obj.EncryptedPubKey{}, basePubKey, encryptedPubKeyEncoded, 22, io.ErrShortWrite, io.EOF},
		// Force error in Sig Length
		{&obj.ExtendedPubKey{}, expandedPubKey, expandedPubKeyEncoded, 156, io.ErrShortWrite, io.EOF},
		// Force error in writing tag
		{&obj.SimplePubKey{}, encryptedPubKey, basePubKeyEncoded, 22, io.ErrShortWrite, io.EOF},
		// Force error in writing tag
		{&obj.SimplePubKey{}, expandedPubKey, basePubKeyEncoded, 22, io.ErrShortWrite, io.EOF},
	}

	t.Logf("Running %d tests", len(tests))
	for i, test := range tests {
		//fmt.Printf("%d: %+v\n", i, *test.in)
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
		buf := bytes.NewBuffer(test.buf[0:test.max])
		err = test.base.Decode(buf)
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

	// Test error for binary message with a pubkey that is too long.
	expandedPubKeyEncoded[156] = 90
	buf := bytes.NewBuffer(expandedPubKeyEncoded)
	var msg obj.ExtendedPubKey
	err := msg.Decode(buf)
	if reflect.TypeOf(err) != reflect.TypeOf(&wire.MessageError{Func: "", Description: ""}) {
		t.Errorf("%s", err.Error())
	}
	// Return expandedPubKeyEncoded to its original form.
	expandedPubKeyEncoded[156] = 40
}

var pubKey1 = &wire.PubKey{
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
}

var pubKey2 = &wire.PubKey{
	1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
}

var tag = &wire.ShaHash{
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
}

// basePubKeyEncoded is the wire.encoded bytes for obj.BasePubKey(pubKey1, pubKey2)
// using version 2 (pre-tag)
var basePubKeyEncoded = []byte{
	0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x47, 0xd8, // 83928 nonce
	0x00, 0x00, 0x00, 0x00, 0x49, 0x5f, 0xab, 0x29, // 64-bit Timestamp
	0x00, 0x00, 0x00, 0x01, // Object Type
	0x02,                   // Version
	0x01,                   // Stream Number
	0x00, 0x00, 0x00, 0x00, // Behavior
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Signing Key
	0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Encrypt Key
}

var expandedPubKeyEncoded = []byte{
	0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x47, 0xd8, // 83928 nonce
	0x00, 0x00, 0x00, 0x00, 0x49, 0x5f, 0xab, 0x29, // 64-bit Timestamp
	0x00, 0x00, 0x00, 0x01, // Object Type
	0x03,                   // Version
	0x01,                   // Stream Number
	0x00, 0x00, 0x00, 0x00, // Behavior
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Signing Key
	0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Encrypt Key
	0x00, // nonce trials per byte
	0x00, // extra bytes
	0x40, // sig length
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // sig
}

var encryptedPubKeyEncoded = []byte{
	0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x47, 0xd8, // 83928 nonce
	0x00, 0x00, 0x00, 0x00, 0x49, 0x5f, 0xab, 0x29, // 64-bit Timestamp
	0x00, 0x00, 0x00, 0x01, // Object Type
	0x04, // Version
	0x01, // Stream Number
	0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // tag
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // encrypted
}

var invalidPubKeyVersionEncoded = []byte{
	0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x47, 0xd8, // 83928 nonce
	0x00, 0x00, 0x00, 0x00, 0x49, 0x5f, 0xab, 0x29, // 64-bit Timestamp
	0x00, 0x00, 0x00, 0x01, // Object Type
	0x05, // Version
	0x01, // Stream Number
}
