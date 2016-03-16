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

// TestMsg tests the MsgMsg API.
func TestMsg(t *testing.T) {

	// Ensure the command is expected value.
	wantCmd := "object"
	now := time.Now()
	enc := make([]byte, 99)
	msg := wire.NewMsgMsg(83928, now, 2, 1, enc, 0, 0, 0, nil, nil, 0, 0, nil, 0, nil, nil, nil)
	if cmd := msg.Command(); cmd != wantCmd {
		t.Errorf("NewMsgMsg: wrong command - got %v want %v",
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
	if str[:3] != "msg" {
		t.Errorf("String representation: got %v, want %v", str[:3], "msg")
	}

	return
}

// TestMsgWire tests the MsgMsg wire.encode and decode for various versions.
func TestMsgWire(t *testing.T) {
	expires := time.Unix(0x495fab29, 0) // 2009-01-03 12:15:05 -0600 CST)
	enc := make([]byte, 128)
	msgBase := wire.NewMsgMsg(83928, expires, 2, 1, enc, 0, 0, 0, nil, nil, 0, 0, nil, 0, nil, nil, nil)
	ripeBytes := make([]byte, 20)
	ripe, err := wire.NewRipeHash(ripeBytes)
	if err != nil {
		t.Fatalf("could not make a ripe hash %s", err)
	}
	m := make([]byte, 32)
	a := make([]byte, 8)
	s := make([]byte, 16)
	msgFilled := wire.NewMsgMsg(83928, expires, 2, 1, enc, 5, 1, 1, pubKey1, pubKey2, 512, 512, ripe, 0, m, a, s)

	tests := []struct {
		in  *wire.MsgMsg // Message to encode
		out *wire.MsgMsg // Expected decoded message
		buf []byte       // Wire encoding
	}{
		{
			msgBase,
			msgBase,
			baseMsgEncoded,
		},
		{
			msgFilled,
			msgBase,
			baseMsgEncoded,
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
		var msg wire.MsgMsg
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

// TestMsgWireError tests the MsgMsg error paths
func TestMsgWireError(t *testing.T) {
	wireErr := &wire.MessageError{}

	wrongObjectTypeEncoded := make([]byte, len(baseMsgEncoded))
	copy(wrongObjectTypeEncoded, baseMsgEncoded)
	wrongObjectTypeEncoded[19] = 0

	tests := []struct {
		in       *wire.MsgMsg // Value to encode
		buf      []byte       // Wire encoding
		max      int          // Max size of fixed buffer to induce errors
		writeErr error        // Expected write error
		readErr  error        // Expected read error
	}{
		// Force error in nonce
		{baseMsg, baseMsgEncoded, 0, io.ErrShortWrite, io.EOF},
		// Force error in expirestime.
		{baseMsg, baseMsgEncoded, 8, io.ErrShortWrite, io.EOF},
		// Force error in object type.
		{baseMsg, baseMsgEncoded, 16, io.ErrShortWrite, io.EOF},
		// Force error in version.
		{baseMsg, baseMsgEncoded, 20, io.ErrShortWrite, io.EOF},
		// Force error in stream number.
		{baseMsg, baseMsgEncoded, 21, io.ErrShortWrite, io.EOF},
		// Force error object type validation.
		{baseMsg, wrongObjectTypeEncoded, 52, io.ErrShortWrite, wireErr},
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
		var msg wire.MsgMsg
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

// TestMsgMsgEncryption tests encoding and decoding for encryption.
func TestMsgMsgEncryption(t *testing.T) {
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
	msgFilled := wire.NewMsgMsg(83928, expires, 2, 1, enc, 5, 1, 1, pubKey1, pubKey2, 512, 512, ripe, 0, m, a, s)

	tests := []struct {
		in  *wire.MsgMsg // Message to encode
		out *wire.MsgMsg // Expected decoded message
		buf []byte       // Wire encoding
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
		var msg wire.MsgMsg

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
		msg.Encrypted = test.in.Encrypted

		if !reflect.DeepEqual(&msg, test.out) {
			t.Errorf("DecodeFromDecrypted #%d\n got: %s want: %s", i,
				spew.Sdump(msg), spew.Sdump(test.out))
			continue
		}
	}
}

// TestMsgEncryptError tests the MsgMsg encrypt error paths
func TestMsgEncryptError(t *testing.T) {

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
	msgFilled := wire.NewMsgMsg(83928, expires, 2, 1, enc, 5, 1, 1, pubKey1, pubKey2, 512, 512, ripe, 0, m, a, s)

	tests := []struct {
		in  *wire.MsgMsg // Value to encode
		buf []byte       // Wire encoding
		max int          // Max size of fixed buffer to induce errors
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
		// EncodeForEncryption.
		w := newFixedWriter(test.max)
		err := test.in.EncodeForEncryption(w)
		if err == nil {
			t.Errorf("EncodeForEncryption #%d no error returned", i)
			continue
		}

		// DecodeFromDecrypted.
		var msg wire.MsgMsg
		buf := bytes.NewBuffer(test.buf[0:test.max])
		err = msg.DecodeFromDecrypted(buf)
		if err == nil {
			t.Errorf("DecodeFromDecrypted #%d no error returned", i)
			continue
		}
	}

	// Try to decode too long a message.
	var msg wire.MsgMsg
	filledMsgEncodedForEncryption[161] = 0xff
	filledMsgEncodedForEncryption[162] = 200
	filledMsgEncodedForEncryption[163] = 200
	buf := bytes.NewBuffer(filledMsgEncodedForEncryption)
	err := msg.DecodeFromDecrypted(buf)
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
	err = msg.DecodeFromDecrypted(buf)
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
	err = msg.DecodeFromDecrypted(buf)
	if err == nil {
		t.Error("EncodeForEncryption should have returned an error for too long a signature length.")
	}
	filledMsgEncodedForEncryption[203] = 16
	filledMsgEncodedForEncryption[204] = 0
	filledMsgEncodedForEncryption[205] = 0
}

// TestMsgMsgSigning tests encoding for signing.
func TestMsgMsgEncodeForSigning(t *testing.T) {
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
	msgFilled := wire.NewMsgMsg(83928, expires, 2, 1, enc, 5, 1, 1, pubKey1, pubKey2, 512, 512, ripe, 0, m, a, s)

	tests := []struct {
		in  *wire.MsgMsg // Message to encode
		buf []byte       // Wire encoding
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

// TestMsgEncryptError tests the MsgMsg encrypt error paths
func TestMsgEncodeForSigningError(t *testing.T) {

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
	msgFilled := wire.NewMsgMsg(83928, expires, 2, 1, enc, 5, 1, 1, pubKey1, pubKey2, 512, 512, ripe, 0, m, a, s)

	tests := []struct {
		in  *wire.MsgMsg // Value to encode
		max int          // Max size of fixed buffer to induce errors
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
		w := newFixedWriter(test.max + 14)
		err := test.in.EncodeForSigning(w)
		if err == nil {
			t.Errorf("EncodeForEncryption #%d no error returned", i)
			continue
		}
	}
}

// baseMsg is used in the various tests as a baseline MsgMsg.
var baseMsg = &wire.MsgMsg{
	Nonce:        123123,                   // 0x1e0f3
	ExpiresTime:  time.Unix(0x495fab29, 0), // 2009-01-03 12:15:05 -0600 CST)
	ObjectType:   wire.ObjectTypeMsg,
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

// baseMsgEncoded is the wire.encoded bytes for baseMsg (just encrypted data)
var baseMsgEncoded = []byte{
	0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x47, 0xd8, // 83928 nonce
	0x00, 0x00, 0x00, 0x00, 0x49, 0x5f, 0xab, 0x29, // 64-bit Timestamp
	0x00, 0x00, 0x00, 0x02, // Object Type
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

// baseMsgEncoded is the wire.encoded bytes for baseMsg (just encrypted data)
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
	0x00, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,
}

// baseMsgEncoded is the wire.encoded bytes for baseMsg (just encrypted data)
var filledMsgEncodedForSigning = []byte{
	0x00, 0x00, 0x00, 0x00, 0x49, 0x5f, 0xab, 0x29,
	0x00, 0x00, 0x00, 0x02, 0x02, 0x01, 0x05, 0x01,
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
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x20,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00,
}
