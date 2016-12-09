// Copyright (c) 2015 Monetas.
// Copyright 2016 Daniel Krawisz.
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package cipher

import (
	"bytes"
	"reflect"
	"testing"
	"time"

	"github.com/DanielKrawisz/bmutil/wire"
	"github.com/DanielKrawisz/bmutil/wire/fixed"
	"github.com/davecgh/go-spew/spew"
)

// TestMessageEncryption tests encoding and decoding for encryption.
func TestMessageEncryption(t *testing.T) {
	expires := time.Unix(0x495fab29, 0) // 2009-01-03 12:15:05 -0600 CST)
	enc := make([]byte, 128)
	ripeBytes := make([]byte, 20)
	ripe, err := wire.NewRipeHash(ripeBytes)
	if err != nil {
		t.Fatalf("could not make a ripe hash %s", err)
	}
	m := make([]byte, 32)
	a := make([]byte, 8)
	s := make([]byte, 16)
	msgFilled := TstNewMessage(83928, expires, 1, enc, 5, 1, 1, pubKey1, pubKey2, 512, 512, ripe, 1, m, a, s)

	tests := []struct {
		in  *Message // Message to encode
		out *Message // Expected decoded message
		buf []byte   // Wire encoding
	}{
		{
			msgFilled,
			msgFilled,
			filledMsgEncodedForEncryption,
		},
	}

	t.Logf("Running %d tests", len(tests))
	for i, test := range tests {
		// Encode the message to wire.format.
		var buf bytes.Buffer
		err := test.in.encodeForEncryption(&buf)
		if err != nil {
			t.Errorf("Encode #%d error %v", i, err)
			continue
		}
		if !bytes.Equal(buf.Bytes(), test.buf) {
			t.Errorf("EncodeForEncryption #%d\n got: %s want: %s", i,
				spew.Sdump(buf.Bytes()), spew.Sdump(test.buf))
			continue
		}

		// Decode the message from wire format.
		msg := &Message{}

		rbuf := bytes.NewReader(test.buf)
		err = msg.decodeFromDecrypted(rbuf)
		if err != nil {
			t.Errorf("decodeFromDecrypted #%d error %v", i, err)
			continue
		}

		// Copy the fields that are not written by decodeFromDecrypted
		msg.SetMessage(test.in)

		if !reflect.DeepEqual(msg, test.out) {
			t.Errorf("decodeFromDecrypted #%d\n got: %s want: %s", i,
				spew.Sdump(msg), spew.Sdump(test.out))
			continue
		}
	}
}

// TestMessageEncryptError tests the MsgMsg encrypt error paths
func TestMessageEncryptError(t *testing.T) {

	wrongObjectTypeEncoded := make([]byte, len(baseMsgEncoded))
	copy(wrongObjectTypeEncoded, baseMsgEncoded)
	wrongObjectTypeEncoded[19] = 0

	expires := time.Unix(0x495fab29, 0) // 2009-01-03 12:15:05 -0600 CST)
	ripeBytes := make([]byte, 20)
	enc := make([]byte, 128)
	ripe, _ := wire.NewRipeHash(ripeBytes)
	m := make([]byte, 32)
	a := make([]byte, 8)
	s := make([]byte, 16)
	msgFilled := TstNewMessage(83928, expires, 1, enc, 5, 1, 1, pubKey1, pubKey2, 512, 512, ripe, 1, m, a, s)

	tests := []struct {
		in  *Message // Value to encode
		buf []byte   // Wire encoding
		max int      // Max size of fixed buffer to induce errors
	}{
		// Force error in FromAddressVersion
		{msgFilled, filledMsgEncodedForEncryption, 0},
		// Force error FromStreamNumber.
		{msgFilled, filledMsgEncodedForEncryption, 1},
		// Force error Behavior.
		{msgFilled, filledMsgEncodedForEncryption, 8},
		// Force error in NonceTrials
		{msgFilled, filledMsgEncodedForEncryption, 134},
		// Force error in ExtraBytes
		{msgFilled, filledMsgEncodedForEncryption, 137},
		// Force error in Destination
		{msgFilled, filledMsgEncodedForEncryption, 152},
		// Force error in encoding.
		{msgFilled, filledMsgEncodedForEncryption, 160},
		// Force error in message length.
		{msgFilled, filledMsgEncodedForEncryption, 161},
		// Force error in message.
		{msgFilled, filledMsgEncodedForEncryption, 168},
		// Force error in acklength
		{msgFilled, filledMsgEncodedForEncryption, 194},
		// Force error in ack.
		{msgFilled, filledMsgEncodedForEncryption, 195},
		// Force error in siglength
		{msgFilled, filledMsgEncodedForEncryption, 203},
		// Force error in sig.
		{msgFilled, filledMsgEncodedForEncryption, 204},
	}

	t.Logf("Running %d tests", len(tests))
	for i, test := range tests {
		// encodeForEncryption.
		w := fixed.NewWriter(test.max)
		err := test.in.encodeForEncryption(w)
		if err == nil {
			t.Errorf("encodeForEncryption #%d no error returned", i)
			continue
		}

		// decodeFromDecrypted.
		var msg Message
		buf := bytes.NewBuffer(test.buf[0:test.max])
		err = msg.decodeFromDecrypted(buf)
		if err == nil {
			t.Errorf("decodeFromDecrypted #%d no error returned", i)
			continue
		}
	}

	// Try to decode too long a message.
	var msg Message
	filledMsgEncodedForEncryption[161] = 0xff
	filledMsgEncodedForEncryption[162] = 200
	filledMsgEncodedForEncryption[163] = 200
	buf := bytes.NewBuffer(filledMsgEncodedForEncryption)
	err := msg.decodeFromDecrypted(buf)
	if err == nil {
		t.Error("EncodeForEncryption should have returned an error for too long a message length.")
	}
	filledMsgEncodedForEncryption[161] = 32
	filledMsgEncodedForEncryption[162] = 0
	filledMsgEncodedForEncryption[163] = 0

	// Try to decode too long an ack.
	filledMsgEncodedForEncryption[194] = 0xff
	filledMsgEncodedForEncryption[195] = 200
	filledMsgEncodedForEncryption[196] = 200
	buf = bytes.NewBuffer(filledMsgEncodedForEncryption)
	err = msg.decodeFromDecrypted(buf)
	if err == nil {
		t.Error("EncodeForEncryption should have returned an error for too long an ack length.")
	}
	filledMsgEncodedForEncryption[194] = 8
	filledMsgEncodedForEncryption[195] = 0
	filledMsgEncodedForEncryption[196] = 0

	// Try to decode a message with too long of a signature.
	filledMsgEncodedForEncryption[203] = 0xff
	filledMsgEncodedForEncryption[204] = 200
	filledMsgEncodedForEncryption[205] = 200
	buf = bytes.NewBuffer(filledMsgEncodedForEncryption)
	err = msg.decodeFromDecrypted(buf)
	if err == nil {
		t.Error("EncodeForEncryption should have returned an error for too long a signature length.")
	}
	filledMsgEncodedForEncryption[203] = 16
	filledMsgEncodedForEncryption[204] = 0
	filledMsgEncodedForEncryption[205] = 0
}

// TestMessageSigning encoding for signing.
func TestMessageSigning(t *testing.T) {
	expires := time.Unix(0x495fab29, 0) // 2009-01-03 12:15:05 -0600 CST)
	enc := make([]byte, 128)
	ripeBytes := make([]byte, 20)
	ripe, err := wire.NewRipeHash(ripeBytes)
	if err != nil {
		t.Fatalf("could not make a ripe hash %s", err)
	}
	m := make([]byte, 32)
	a := make([]byte, 8)
	s := make([]byte, 16)
	msgFilled := TstNewMessage(83928, expires, 1, enc, 5, 1, 1, pubKey1, pubKey2, 512, 512, ripe, 1, m, a, s)

	tests := []struct {
		in  *Message // Message to encode
		buf []byte   // Wire encoding
	}{
		{
			msgFilled,
			filledMsgEncodedForSigning,
		},
	}

	t.Logf("Running %d tests", len(tests))
	for i, test := range tests {
		// Encode the message to wire.format.
		var buf bytes.Buffer
		err := test.in.encodeForSigning(&buf)
		if err != nil {
			t.Errorf("Encode #%d error %v", i, err)
			continue
		}
		if !bytes.Equal(buf.Bytes(), test.buf) {
			t.Errorf("encodeForSigning #%d\n got: %s want: %s", i,
				spew.Sdump(buf.Bytes()), spew.Sdump(test.buf))
			continue
		}
	}
}

// TestMessageSigningError tests the MsgMsg encrypt error paths
func TestMessageSigningError(t *testing.T) {

	wrongObjectTypeEncoded := make([]byte, len(baseMsgEncoded))
	copy(wrongObjectTypeEncoded, baseMsgEncoded)
	wrongObjectTypeEncoded[19] = 0

	expires := time.Unix(0x495fab29, 0) // 2009-01-03 12:15:05 -0600 CST)
	ripeBytes := make([]byte, 20)
	enc := make([]byte, 128)
	ripe, _ := wire.NewRipeHash(ripeBytes)
	m := make([]byte, 32)
	a := make([]byte, 8)
	s := make([]byte, 16)
	msgFilled := TstNewMessage(83928, expires, 1, enc, 5, 1, 1, pubKey1, pubKey2, 512, 512, ripe, 1, m, a, s)

	tests := []struct {
		in  *Message // Value to encode
		max int      // Max size of fixed buffer to induce errors
	}{
		// Force error in the header.
		{msgFilled, -10},
		// Force error in FromAddressVersion
		{msgFilled, 0},
		// Force error FromStreamNumber.
		{msgFilled, 1},
		// Force error Behavior.
		{msgFilled, 8},
		// Force error in NonceTrials
		{msgFilled, 134},
		// Force error in ExtraBytes
		{msgFilled, 137},
		// Force error in Destination
		{msgFilled, 152},
		// Force error in encoding.
		{msgFilled, 160},
		// Force error in message length.
		{msgFilled, 161},
		// Force error in message.
		{msgFilled, 168},
		// Force error in acklength
		{msgFilled, 194},
		// Force error in ack.
		{msgFilled, 195},
	}

	t.Logf("Running %d tests", len(tests))
	for i, test := range tests {
		// EncodeForEncryption.
		w := fixed.NewWriter(test.max + 14)
		err := test.in.encodeForSigning(w)
		if err == nil {
			t.Errorf("EncodeForEncryption #%d no error returned", i)
			continue
		}
	}
}

// baseMsgEncoded is the wire.encoded bytes for baseMsg (just encrypted data)
var baseMsgEncoded = []byte{
	0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x47, 0xd8, // 83928 nonce
	0x00, 0x00, 0x00, 0x00, 0x49, 0x5f, 0xab, 0x29, // 64-bit Timestamp
	0x00, 0x00, 0x00, 0x02, // Object Type
	0x01, // Version
	0x01, // Stream Number
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Encrypted Data
}

var filledMsgEncodedForEncryption = []byte{
	0x05, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00,
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
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xfd, 0x02,
	0x00, 0xfd, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00,
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
	0x01, 0x01, 0x05, 0x01,
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
	0x00, 0x00, 0x00, 0x00, 0xfd, 0x02, 0x00, 0xfd,
	0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x20,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00,
}
