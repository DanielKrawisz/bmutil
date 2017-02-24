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

	"github.com/DanielKrawisz/bmutil/hash"
	"github.com/DanielKrawisz/bmutil/wire/fixed"
	"github.com/davecgh/go-spew/spew"
)

// TestBroadcastEnrcypt tests the broadcastEncodeForEncryption and
// decodeFromDecrypted methods for various versions.
func TestBroadcastEncrypt(t *testing.T) {
	expires := time.Unix(0x495fab29, 0) // 2009-01-03 12:15:05 -0600 CST)
	enc := make([]byte, 128)

	m := make([]byte, 32)
	a := make([]byte, 8)
	tagBytes := make([]byte, 32)
	tag, err := hash.NewSha(tagBytes)
	if err != nil {
		t.Fatalf("could not make a sha hash %s", err)
	}
	msgTagged, _ := TstNewBroadcast(83928, expires, 1, tag, enc, 3, 1, 1, pubKey1, pubKey2, 512, 512, 1, m, a, nil)

	tests := []struct {
		in  *Broadcast // Message to encode
		out *Broadcast // Expected decoded message
		buf []byte     // Wire encoding
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

		// Decode the message from wire.format.
		var msg Broadcast
		rbuf := bytes.NewReader(test.buf)
		err = msg.decodeFromDecrypted(rbuf)
		if err != nil {
			t.Errorf("DecodeFromDecrypted #%d error %v", i, err)
			continue
		}

		// Copy the fields that are not written by DecodeFromDecrypted
		msg.SetMessage(test.out)

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
	tag, err := hash.NewSha(tagBytes)
	if err != nil {
		t.Fatalf("could not make a sha hash %s", err)
	}
	msgTagged, _ := TstNewBroadcast(83928, expires, 1, tag, enc, 3, 1, 1, pubKey1, pubKey2, 512, 512, 1, m, a, nil)

	tests := []struct {
		in  *Broadcast // Value to encode
		buf []byte     // Wire encoding
		max int        // Max size of fixed buffer to induce errors
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
		w := fixed.NewWriter(test.max)
		err := test.in.encodeForEncryption(w)
		if err == nil {
			t.Errorf("EncodeForEncryption #%d no error returned", i)
			continue
		}

		// DecodeFromDecrypted.
		var msg Broadcast
		buf := bytes.NewBuffer(test.buf[0:test.max])
		err = msg.decodeFromDecrypted(buf)
		if err == nil {
			t.Errorf("DecodeFromDecrypted #%d no error returned", i)
			continue
		}
	}

	// Try to decode too long a message.
	var msg Broadcast
	broadcastEncodedForEncryption[141] = 0xff
	broadcastEncodedForEncryption[142] = 200
	broadcastEncodedForEncryption[143] = 200
	buf := bytes.NewBuffer(broadcastEncodedForEncryption)
	err = msg.decodeFromDecrypted(buf)
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
	err = msg.decodeFromDecrypted(buf)
	if err == nil {
		t.Error("EncodeForEncryption should have returned an error for too long a message length.")
	}
	broadcastEncodedForEncryption[174] = 8
	broadcastEncodedForEncryption[175] = 0
	broadcastEncodedForEncryption[176] = 0
}

// TestBroadcastEnrcypt tests the MsgBroadcast wire.EncodeForEncryption and
// DecodeForEncryption for various versions.
func TestBroadcastencodeForSigning(t *testing.T) {
	expires := time.Unix(0x495fab29, 0) // 2009-01-03 12:15:05 -0600 CST)
	enc := make([]byte, 128)

	m := make([]byte, 32)
	a := make([]byte, 8)
	tagBytes := make([]byte, 32)
	tag, err := hash.NewSha(tagBytes)
	if err != nil {
		t.Fatalf("could not make a sha hash %s", err)
	}
	msgTagged, _ := TstNewBroadcast(83928, expires, 1, tag, enc, 3, 1, 1, pubKey1, pubKey2, 512, 512, 1, m, a, nil)

	tests := []struct {
		in  *Broadcast // Message to encode
		buf []byte     // Wire encoding
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

// TestBroadcastEncryptError tests the MsgBroadcast error paths
func TestBroadcastencodeForSigningError(t *testing.T) {
	expires := time.Unix(0x495fab29, 0) // 2009-01-03 12:15:05 -0600 CST)
	enc := make([]byte, 128)

	m := make([]byte, 32)
	a := make([]byte, 8)
	tagBytes := make([]byte, 32)
	tag, err := hash.NewSha(tagBytes)
	if err != nil {
		t.Fatalf("could not make a sha hash %s", err)
	}
	_, tstTagged := TstNewBroadcast(83928, expires, 1, tag, enc, 3, 1, 1, pubKey1, pubKey2, 512, 512, 1, m, a, nil)

	tests := []struct {
		in  *TstBroadcast // Value to encode
		max int           // Max size of fixed buffer to induce errors
	}{
		// Force error in Tag
		{tstTagged, 6},
		// Force error in Tag
		{tstTagged, 36},
		// Force error in FromAddressVersion
		{tstTagged, 46},
		// Force error in FromSteamNumber
		{tstTagged, 47},
		// Force error in behavior.
		{tstTagged, 52},
		// Force error in NonceTrials.
		{tstTagged, 180},
		// Force error in ExtraBytes.
		{tstTagged, 183},
		// Force error in Encoding.
		{tstTagged, 186},
		// Force error in message length.
		{tstTagged, 187},
		// Force error in message.
		{tstTagged, 188},
	}

	t.Logf("Running %d tests", len(tests))
	for i, test := range tests {
		// EncodeForEncryption.
		w := fixed.NewWriter(test.max)
		err := test.in.EncodeForSigning(w)
		if err == nil {
			t.Errorf("encodeForSigning #%d no error returned", i)
			continue
		}
	}
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
	0x00, 0xfd, 0x02, 0x00, 0x01, 0x20, 0x00, 0x00,
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
	0x00, 0xfd, 0x02, 0x00, 0x01, 0x20, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
}
