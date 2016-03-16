// Copyright (c) 2015 Monetas
// Copyright 2016 Daniel Krawisz.
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package wire_test

import (
	"bytes"
	"io"
	"reflect"
	"testing"
	"time"

	"github.com/davecgh/go-spew/spew"
	"github.com/DanielKrawisz/bmutil/wire"
)

// TestBroadcast tests the MsgBroadcast API.
func TestBroadcast(t *testing.T) {

	// Ensure the command is expected value.
	wantCmd := "object"
	now := time.Now()
	enc := make([]byte, 99)
	msg := wire.NewMsgBroadcast(83928, now, 2, 1, nil, enc, 0, 0, 0, nil, nil, 0, 0, 0, nil, nil)
	if cmd := msg.Command(); cmd != wantCmd {
		t.Errorf("NewMsgBroadcast: wrong command - got %v want %v",
			cmd, wantCmd)
	}

	// Ensure max payload is expected value for latest protocol version.
	wantPayload := wire.MaxPayloadOfMsgObject
	maxPayload := msg.MaxPayloadLength()
	if maxPayload != wantPayload {
		t.Errorf("MaxPayloadLength: wrong max payload length for "+
			"- got %v, want %v", maxPayload, wantPayload)
	}

	str := msg.String()
	if str[:9] != "broadcast" {
		t.Errorf("String representation: got %v, want %v", str[:9], "broadcast")
	}

	return
}

// TestBroadcastWire tests the MsgBroadcast wire.encode and decode for
// various versions.
func TestBroadcastWire(t *testing.T) {
	expires := time.Unix(0x495fab29, 0) // 2009-01-03 12:15:05 -0600 CST)
	enc := make([]byte, 128)
	msgBase := wire.NewMsgBroadcast(83928, expires, 2, 1, nil, enc, 0, 0, 0, nil, nil, 0, 0, 0, nil, nil)

	m := make([]byte, 32)
	a := make([]byte, 8)
	tagBytes := make([]byte, 32)
	tag, err := wire.NewShaHash(tagBytes)
	if err != nil {
		t.Fatalf("could not make a sha hash %s", err)
	}
	msgTagged := wire.NewMsgBroadcast(83928, expires, 5, 1, tag, enc, 1, 1, 1, pubKey1, pubKey2, 512, 512, 0, m, a)
	msgBaseAndTag := wire.NewMsgBroadcast(83928, expires, 5, 1, tag, enc, 0, 0, 0, nil, nil, 0, 0, 0, nil, nil)

	tests := []struct {
		in  *wire.MsgBroadcast // Message to encode
		out *wire.MsgBroadcast // Expected decoded message
		buf []byte             // Wire encoding
	}{
		// Latest protocol version with multiple object vectors.
		{
			msgBase,
			msgBase,
			baseBroadcastEncoded,
		},
		{
			msgTagged,
			msgBaseAndTag,
			tagBroadcastEncoded,
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
		var msg wire.MsgBroadcast
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

// TestBroadcastWireError tests the MsgBroadcast error paths
func TestBroadcastWireError(t *testing.T) {
	wireErr := &wire.MessageError{}

	wrongObjectTypeEncoded := make([]byte, len(baseMsgEncoded))
	copy(wrongObjectTypeEncoded, baseMsgEncoded)
	wrongObjectTypeEncoded[19] = 0

	tests := []struct {
		in       *wire.MsgBroadcast // Value to encode
		buf      []byte             // Wire encoding
		max      int                // Max size of fixed buffer to induce errors
		writeErr error              // Expected write error
		readErr  error              // Expected read error
	}{
		// Force error in nonce
		{baseBroadcast, baseBroadcastEncoded, 0, io.ErrShortWrite, io.EOF},
		// Force error in expirestime.
		{baseBroadcast, baseBroadcastEncoded, 8, io.ErrShortWrite, io.EOF},
		// Force error in object type.
		{baseBroadcast, baseBroadcastEncoded, 16, io.ErrShortWrite, io.EOF},
		// Force error in version.
		{baseBroadcast, baseBroadcastEncoded, 20, io.ErrShortWrite, io.EOF},
		// Force error in stream number.
		{baseBroadcast, baseBroadcastEncoded, 21, io.ErrShortWrite, io.EOF},
		// Force error object type validation.
		{baseBroadcast, wrongObjectTypeEncoded, 52, io.ErrShortWrite, wireErr},
		// Force error in tag.
		{taggedBroadcast, tagBroadcastEncoded, 22, io.ErrShortWrite, io.EOF},
	}

	t.Logf("Running %d tests", len(tests))
	for i, test := range tests {
		// Encode to wire.format.
		w := newFixedWriter(test.max)
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
		var msg wire.MsgBroadcast
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

// TestBroadcastEnrcypt tests the MsgBroadcast wire.EncodeForEncryption and
// DecodeForEncryption for various versions.
func TestBroadcastEncrypt(t *testing.T) {
	expires := time.Unix(0x495fab29, 0) // 2009-01-03 12:15:05 -0600 CST)
	enc := make([]byte, 128)

	m := make([]byte, 32)
	a := make([]byte, 8)
	tagBytes := make([]byte, 32)
	tag, err := wire.NewShaHash(tagBytes)
	if err != nil {
		t.Fatalf("could not make a sha hash %s", err)
	}
	msgTagged := wire.NewMsgBroadcast(83928, expires, 5, 1, tag, enc, 3, 1, 1, pubKey1, pubKey2, 512, 512, 0, m, a)

	tests := []struct {
		in  *wire.MsgBroadcast // Message to encode
		out *wire.MsgBroadcast // Expected decoded message
		buf []byte             // Wire encoding
	}{
		// Latest protocol version with multiple object vectors.
		{
			msgTagged,
			msgTagged,
			broadcastEncodedForEncryption,
		},
	}

	t.Logf("Running %d tests", len(tests))
	for i, test := range tests {
		// Encode the message to wire.format.
		var buf bytes.Buffer
		err := test.in.EncodeForEncryption(&buf)
		if err != nil {
			t.Errorf("Encode #%d error %v", i, err)
			continue
		}
		if !bytes.Equal(buf.Bytes(), test.buf) {
			t.Errorf("EncodeForEncryption #%d\n got: %s want: %s", i,
				spew.Sdump(buf.Bytes()), spew.Sdump(test.buf))
			continue
		}

		// Decode the message from wire.format.
		var msg wire.MsgBroadcast
		rbuf := bytes.NewReader(test.buf)
		err = msg.DecodeFromDecrypted(rbuf)
		if err != nil {
			t.Errorf("DecodeFromDecrypted #%d error %v", i, err)
			continue
		}

		// Copy the fields that are not written by DecodeFromDecrypted
		msg.Nonce = test.in.Nonce
		msg.ExpiresTime = test.in.ExpiresTime
		msg.ObjectType = test.in.ObjectType
		msg.Version = test.in.Version
		msg.StreamNumber = test.in.StreamNumber
		msg.Tag = test.in.Tag
		msg.Encrypted = test.in.Encrypted

		if !reflect.DeepEqual(&msg, test.out) {
			t.Errorf("DecodeFromDecrypted #%d\n got: %s want: %s", i,
				spew.Sdump(&msg), spew.Sdump(test.out))
			continue
		}
	}
}

// TestBroadcastEncryptError tests the MsgBroadcast error paths
func TestBroadcastEncryptError(t *testing.T) {
	expires := time.Unix(0x495fab29, 0) // 2009-01-03 12:15:05 -0600 CST)
	enc := make([]byte, 128)

	m := make([]byte, 32)
	a := make([]byte, 8)
	tagBytes := make([]byte, 32)
	tag, err := wire.NewShaHash(tagBytes)
	if err != nil {
		t.Fatalf("could not make a sha hash %s", err)
	}
	msgTagged := wire.NewMsgBroadcast(83928, expires, 5, 1, tag, enc, 3, 1, 1, pubKey1, pubKey2, 512, 512, 0, m, a)

	tests := []struct {
		in  *wire.MsgBroadcast // Value to encode
		buf []byte             // Wire encoding
		max int                // Max size of fixed buffer to induce errors
	}{
		// Force error in FromAddressVersion
		{msgTagged, broadcastEncodedForEncryption, 0},
		// Force error in FromSteamNumber
		{msgTagged, broadcastEncodedForEncryption, 1},
		// Force error in behavior.
		{msgTagged, broadcastEncodedForEncryption, 8},
		// Force error in NonceTrials.
		{msgTagged, broadcastEncodedForEncryption, 134},
		// Force error in ExtraBytes.
		{msgTagged, broadcastEncodedForEncryption, 137},
		// Force error in Encoding.
		{msgTagged, broadcastEncodedForEncryption, 140},
		// Force error in message length.
		{msgTagged, broadcastEncodedForEncryption, 141},
		// Force error in message.
		{msgTagged, broadcastEncodedForEncryption, 142},
		// Force error in sig length.
		{msgTagged, broadcastEncodedForEncryption, 174},
		// Force error in signature.
		{msgTagged, broadcastEncodedForEncryption, 175},
	}

	t.Logf("Running %d tests", len(tests))
	for i, test := range tests {
		// EncodeForEncryption.
		w := newFixedWriter(test.max)
		err := test.in.EncodeForEncryption(w)
		if err == nil {
			t.Errorf("EncodeForEncryption #%d no error returned", i)
			continue
		}

		// DecodeFromDecrypted.
		var msg wire.MsgBroadcast
		buf := bytes.NewBuffer(test.buf[0:test.max])
		err = msg.DecodeFromDecrypted(buf)
		if err == nil {
			t.Errorf("DecodeFromDecrypted #%d no error returned", i)
			continue
		}
	}

	// Try to decode too long a message.
	var msg wire.MsgBroadcast
	broadcastEncodedForEncryption[141] = 0xff
	broadcastEncodedForEncryption[142] = 200
	broadcastEncodedForEncryption[143] = 200
	buf := bytes.NewBuffer(broadcastEncodedForEncryption)
	err = msg.DecodeFromDecrypted(buf)
	if err == nil {
		t.Error("EncodeForEncryption should have returned an error for too long a message length.")
	}
	broadcastEncodedForEncryption[141] = 32
	broadcastEncodedForEncryption[142] = 0
	broadcastEncodedForEncryption[143] = 0

	// Try to decode a message with too long of a signature.
	broadcastEncodedForEncryption[174] = 0xff
	broadcastEncodedForEncryption[175] = 200
	broadcastEncodedForEncryption[176] = 200
	buf = bytes.NewBuffer(broadcastEncodedForEncryption)
	err = msg.DecodeFromDecrypted(buf)
	if err == nil {
		t.Error("EncodeForEncryption should have returned an error for too long a message length.")
	}
	broadcastEncodedForEncryption[174] = 8
	broadcastEncodedForEncryption[175] = 0
	broadcastEncodedForEncryption[176] = 0
}

// TestBroadcastEnrcypt tests the MsgBroadcast wire.EncodeForEncryption and
// DecodeForEncryption for various versions.
func TestBroadcastEncodeForSigning(t *testing.T) {
	expires := time.Unix(0x495fab29, 0) // 2009-01-03 12:15:05 -0600 CST)
	enc := make([]byte, 128)

	m := make([]byte, 32)
	a := make([]byte, 8)
	tagBytes := make([]byte, 32)
	tag, err := wire.NewShaHash(tagBytes)
	if err != nil {
		t.Fatalf("could not make a sha hash %s", err)
	}
	msgTagged := wire.NewMsgBroadcast(83928, expires, 5, 1, tag, enc, 3, 1, 1, pubKey1, pubKey2, 512, 512, 0, m, a)

	tests := []struct {
		in  *wire.MsgBroadcast // Message to encode
		buf []byte             // Wire encoding
	}{
		// Latest protocol version with multiple object vectors.
		{
			msgTagged,
			broadcastEncodedForSigning,
		},
	}

	t.Logf("Running %d tests", len(tests))
	for i, test := range tests {
		// Encode the message to wire.format.
		var buf bytes.Buffer
		err := test.in.EncodeForSigning(&buf)
		if err != nil {
			t.Errorf("Encode #%d error %v", i, err)
			continue
		}
		if !bytes.Equal(buf.Bytes(), test.buf) {
			t.Errorf("EncodeForSigning #%d\n got: %s want: %s", i,
				spew.Sdump(buf.Bytes()), spew.Sdump(test.buf))
			continue
		}
	}
}

// TestBroadcastEncryptError tests the MsgBroadcast error paths
func TestBroadcastEncodeForSigningError(t *testing.T) {
	expires := time.Unix(0x495fab29, 0) // 2009-01-03 12:15:05 -0600 CST)
	enc := make([]byte, 128)

	m := make([]byte, 32)
	a := make([]byte, 8)
	tagBytes := make([]byte, 32)
	tag, err := wire.NewShaHash(tagBytes)
	if err != nil {
		t.Fatalf("could not make a sha hash %s", err)
	}
	msgTagged := wire.NewMsgBroadcast(83928, expires, 5, 1, tag, enc, 3, 1, 1, pubKey1, pubKey2, 512, 512, 0, m, a)

	tests := []struct {
		in  *wire.MsgBroadcast // Value to encode
		max int                // Max size of fixed buffer to induce errors
	}{
		// Force error in Tag
		{msgTagged, -40},
		// Force error in Tag
		{msgTagged, -10},
		// Force error in FromAddressVersion
		{msgTagged, 0},
		// Force error in FromSteamNumber
		{msgTagged, 1},
		// Force error in behavior.
		{msgTagged, 8},
		// Force error in NonceTrials.
		{msgTagged, 134},
		// Force error in ExtraBytes.
		{msgTagged, 137},
		// Force error in Encoding.
		{msgTagged, 140},
		// Force error in message length.
		{msgTagged, 141},
		// Force error in message.
		{msgTagged, 142},
	}

	t.Logf("Running %d tests", len(tests))
	for i, test := range tests {
		// EncodeForEncryption.
		w := newFixedWriter(test.max + 46)
		err := test.in.EncodeForSigning(w)
		if err == nil {
			t.Errorf("EncodeForSigning #%d no error returned", i)
			continue
		}
	}
}

// baseBroadcast is used in the various tests as a baseline MsgBroadcast.
var baseBroadcast = &wire.MsgBroadcast{
	Nonce:        123123,                   // 0x1e0f3
	ExpiresTime:  time.Unix(0x495fab29, 0), // 2009-01-03 12:15:05 -0600 CST)
	ObjectType:   wire.ObjectTypeBroadcast,
	Version:      2,
	StreamNumber: 1,
	Encrypted: []byte{
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	},
}

// baseBroadcast is a broadcast from a v4 address (includes a tag).
var taggedBroadcast = &wire.MsgBroadcast{
	Nonce:        123123,                   // 0x1e0f3
	ExpiresTime:  time.Unix(0x495fab29, 0), // 2009-01-03 12:15:05 -0600 CST)
	ObjectType:   wire.ObjectTypeBroadcast,
	Version:      5,
	StreamNumber: 1,
	Tag: &wire.ShaHash{
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	},
	Encrypted: []byte{
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	},
}

// baseBroadcastEncoded is the wire.encoded bytes for baseBroadcast (just encrypted data)
var baseBroadcastEncoded = []byte{
	0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x47, 0xd8, // 83928 nonce
	0x00, 0x00, 0x00, 0x00, 0x49, 0x5f, 0xab, 0x29, // 64-bit Timestamp
	0x00, 0x00, 0x00, 0x03, // Object Type
	0x02, // Version
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

// tagBroadcastEncoded is the wire.encoded bytes for broadcast from a v4 address
// (includes a tag).
var tagBroadcastEncoded = []byte{
	0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x47, 0xd8, // 83928 nonce
	0x00, 0x00, 0x00, 0x00, 0x49, 0x5f, 0xab, 0x29, // 64-bit Timestamp
	0x00, 0x00, 0x00, 0x03, // Object Type
	0x05, // Version
	0x01, // Stream Number
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Tag
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
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xfd, 0x02,
	0x00, 0xfd, 0x02, 0x00, 0x00, 0x20, 0x00, 0x00,
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
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xfd, 0x02,
	0x00, 0xfd, 0x02, 0x00, 0x00, 0x20, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
}
