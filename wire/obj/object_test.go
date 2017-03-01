// Copyright 2016 Daniel Krawisz.
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package obj_test

import (
	"bytes"
	"net"
	"reflect"
	"testing"
	"time"

	"github.com/DanielKrawisz/bmutil/hash"
	"github.com/DanielKrawisz/bmutil/pow"
	"github.com/DanielKrawisz/bmutil/wire"
	"github.com/DanielKrawisz/bmutil/wire/obj"
	"github.com/davecgh/go-spew/spew"
)

// TestObject tests the Read/WriteMessage and Read/WriteMessageN API.
func TestObject(t *testing.T) {
	// Create the various types of messages to test.

	// MsgVersion.
	addrYou := &net.TCPAddr{IP: net.ParseIP("192.168.0.1"), Port: 8333}
	you, err := wire.NewNetAddress(addrYou, 1, wire.SFNodeNetwork)
	if err != nil {
		t.Errorf("NewNetAddress: %v", err)
	}
	you.Timestamp = time.Time{} // Version message has zero value timestamp.
	addrMe := &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 8333}
	me, err := wire.NewNetAddress(addrMe, 1, wire.SFNodeNetwork)
	if err != nil {
		t.Errorf("NewNetAddress: %v", err)
	}
	// A version message that is decoded comes out a little different than
	// the original data structure, so we need to create a slightly different
	// message to test against.
	me.Timestamp = time.Time{} // Version message has zero value timestamp.
	youExpected, err := wire.NewNetAddress(addrYou, 0, wire.SFNodeNetwork)
	if err != nil {
		t.Errorf("NewNetAddress: %v", err)
	}
	youExpected.Timestamp = time.Time{} // Version message has zero value timestamp.
	meExpected, err := wire.NewNetAddress(addrMe, 0, wire.SFNodeNetwork)
	if err != nil {
		t.Errorf("NewNetAddress: %v", err)
	}
	meExpected.Timestamp = time.Time{} // Version message has zero value timestamp.

	// ripe-based getpubkey message
	ripeBytes := make([]byte, 20)
	ripeBytes[0] = 1
	expires := time.Unix(0x495fab29, 0) // 2009-01-03 12:15:05 -0600 CST)
	msgGetPubKey := obj.NewGetPubKey(123123, expires, obj.MakeAddress(t, 2, 1, ripeBytes))

	pub1Bytes, pub2Bytes := make([]byte, 64), make([]byte, 64)
	pub2Bytes[0] = 1
	pub1, err := wire.NewPubKey(pub1Bytes)
	if err != nil {
		t.Fatalf("could not create a pubkey %s", err)
	}
	pub2, err := wire.NewPubKey(pub2Bytes)
	if err != nil {
		t.Fatalf("could not create a pubkey %s", err)
	}
	var tag hash.Sha
	msgSimplePubKey := obj.NewSimplePubKey(123123, expires, 1, 0, pub1, pub2)
	msgExtendedPubKey := obj.NewExtendedPubKey(123123, expires, 1,
		&obj.PubKeyData{
			Behavior:     0,
			Verification: pub1,
			Encryption:   pub2,
			Pow: &pow.Data{
				NonceTrialsPerByte: 4,
				ExtraBytes:         5,
			},
		}, []byte{1, 2, 3})
	msgEncryptedPubKey := obj.NewEncryptedPubKey(123123, expires, 1, &tag, []byte{1, 2, 3, 4, 5})

	enc := make([]byte, 99)
	msgMsg := obj.NewMessage(123123, expires, 1, enc)

	msgTaglessBroadcast := obj.NewTaglessBroadcast(123123, expires, 1, enc)
	msgTaggedBroadcast := obj.NewTaggedBroadcast(123123, expires, 1, &tag, enc)

	tests := []struct {
		in    obj.Object         // Value to encode
		out   obj.Object         // Expected decoded value
		bmnet wire.BitmessageNet // Network to use for wire.encoding
		bytes int                // Expected num bytes read/written
	}{
		{msgGetPubKey, msgGetPubKey, wire.MainNet, 66},
		{msgSimplePubKey, msgSimplePubKey, wire.MainNet, 178},
		{msgExtendedPubKey, msgExtendedPubKey, wire.MainNet, 178 + 6},
		{msgEncryptedPubKey, msgEncryptedPubKey, wire.MainNet, 83},
		{msgMsg, msgMsg, wire.MainNet, 145},
		{msgTaglessBroadcast, msgTaglessBroadcast, wire.MainNet, 145},
		{msgTaggedBroadcast, msgTaggedBroadcast, wire.MainNet, 145 + 32},
	}

	t.Logf("Running %d tests", len(tests))
	for i, test := range tests {
		// Encode to wire.format.
		var buf bytes.Buffer
		nw, err := wire.WriteMessageN(&buf, test.in, test.bmnet)
		if err != nil {
			t.Errorf("WriteMessage #%d error %v", i, err)
			continue
		}

		// Ensure the number of bytes written match the expected value.
		if nw != test.bytes {
			t.Errorf("WriteMessage #%d unexpected num bytes "+
				"written - got %d, want %d", i, nw, test.bytes)
		}

		// Decode from wire.format.
		rbuf := bytes.NewReader(buf.Bytes())
		nr, msg, _, err := wire.ReadMessageN(rbuf, test.bmnet)
		if err != nil {
			t.Errorf("ReadMessage #%d error %v, msg %v", i, err,
				spew.Sdump(msg))
			continue
		}
		if !reflect.DeepEqual(wire.Encode(msg), wire.Encode(test.out)) {
			t.Errorf("ReadMessage #%d\n got: %v want: %v", i,
				spew.Sdump(msg), spew.Sdump(test.out))
			continue
		}

		// Ensure the number of bytes read match the expected value.
		if nr != test.bytes {
			t.Errorf("ReadMessage #%d unexpected num bytes read - "+
				"got %d, want %d", i, nr, test.bytes)
		}
	}

	// Do the same thing for Read/WriteMessage, but ignore the bytes since
	// they don't return them.
	t.Logf("Running %d tests", len(tests))
	for i, test := range tests {
		// Encode to wire.format.
		var buf bytes.Buffer
		err := wire.WriteMessage(&buf, test.in, test.bmnet)
		if err != nil {
			t.Errorf("WriteMessage #%d error %v", i, err)
			continue
		}

		// Decode from wire.format.
		rbuf := bytes.NewReader(buf.Bytes())
		msg, _, err := wire.ReadMessage(rbuf, test.bmnet)
		if err != nil {
			t.Errorf("ReadMessage #%d error %v, msg %v", i, err,
				spew.Sdump(msg))
			continue
		}
		if !reflect.DeepEqual(wire.Encode(msg), wire.Encode(test.out)) {
			t.Errorf("ReadMessage #%d\n got: %v want: %v", i,
				spew.Sdump(msg), spew.Sdump(test.out))
			continue
		}
	}
}
