// Originally derived from: btcsuite/btcd/wire/message_test.go
// Copyright (c) 2013-2015 Conformal Systems LLC.

// Copyright (c) 2015 Monetas
// Copyright 2016 Daniel Krawisz.
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package wire_test

import (
	"bytes"
	"encoding/binary"
	"io"
	"net"
	"reflect"
	"testing"
	"time"

	"github.com/DanielKrawisz/bmutil/wire"
	"github.com/DanielKrawisz/bmutil/wire/fixed"
	"github.com/DanielKrawisz/bmutil/wire/obj"
	"github.com/davecgh/go-spew/spew"
)

// makeHeader is a convenience function to make a message header in the form of
// a byte slice.  It is used to force errors when reading messages.
func makeHeader(bmnet wire.BitmessageNet, command string,
	payloadLen uint32, checksum uint32) []byte {

	// The length of a bitmessage message header is 24 bytes.
	// 4 byte magic number of the bitmessage network + 12 byte command + 4 byte
	// payload length + 4 byte checksum.
	buf := make([]byte, 24)
	binary.BigEndian.PutUint32(buf, uint32(bmnet))
	copy(buf[4:], []byte(command))
	binary.BigEndian.PutUint32(buf[16:], payloadLen)
	binary.BigEndian.PutUint32(buf[20:], checksum)
	return buf
}

// TestMessage tests the Read/WriteMessage and Read/WriteMessageN API.
func TestMessage(t *testing.T) {
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
	msgVersion := wire.NewMsgVersion(me, you, 123123, []uint32{1})
	msgVersionExpected := wire.NewMsgVersion(meExpected, youExpected, 123123, []uint32{1})

	msgVerack := wire.NewMsgVerAck()
	msgPong := wire.NewMsgPong()
	msgAddr := wire.NewMsgAddr()
	msgInv := wire.NewMsgInv()
	msgGetData := wire.NewMsgGetData()

	// ripe-based getpubkey message
	ripeBytes := make([]byte, 20)
	ripeBytes[0] = 1
	ripe, err := wire.NewRipeHash(ripeBytes)
	if err != nil {
		t.Fatalf("could not make a ripe hash %s", err)
	}
	expires := time.Unix(0x495fab29, 0) // 2009-01-03 12:15:05 -0600 CST)
	msgGetPubKey := obj.NewGetPubKey(123123, expires, 2, 1, ripe, nil)

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
	msgPubKey := obj.NewSimplePubKey(123123, expires, 1, 0, pub1, pub2)

	enc := make([]byte, 99)
	msgMsg := obj.NewMessage(123123, expires, 2, 1, enc, 0, 0, 0, nil, nil, 0, 0, nil, 0, nil, nil, nil)

	msgBroadcast := obj.NewBroadcast(123123, expires, 2, 1, nil, enc, 0, 0, 0, nil, nil, 0, 0, 0, nil, nil)

	tests := []struct {
		in    wire.Message       // Value to encode
		out   wire.Message       // Expected decoded value
		bmnet wire.BitmessageNet // Network to use for wire.encoding
		bytes int                // Expected num bytes read/written
	}{
		{msgVersion, msgVersionExpected, wire.MainNet, 119},
		{msgVerack, msgVerack, wire.MainNet, 24},
		{msgPong, msgPong, wire.MainNet, 24},
		{msgAddr, msgAddr, wire.MainNet, 25},
		{msgInv, msgInv, wire.MainNet, 25},
		{msgGetData, msgGetData, wire.MainNet, 25},
		{msgGetPubKey.MsgObject(), msgGetPubKey.MsgObject(), wire.MainNet, 66},
		{msgPubKey.MsgObject(), msgPubKey.MsgObject(), wire.MainNet, 178},
		{msgMsg.MsgObject(), msgMsg.MsgObject(), wire.MainNet, 145},
		{msgBroadcast.MsgObject(), msgBroadcast.MsgObject(), wire.MainNet, 145},
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
		if !reflect.DeepEqual(msg, test.out) {
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
		if !reflect.DeepEqual(msg, test.out) {
			t.Errorf("ReadMessage #%d\n got: %v want: %v", i,
				spew.Sdump(msg), spew.Sdump(test.out))
			continue
		}
	}
}

// TestReadMessageWireErrors performs negative tests against wire.decoding into
// concrete messages to confirm error paths work correctly.
func TestReadMessageWireErrors(t *testing.T) {
	bmnet := wire.MainNet

	// Ensure message errors are as expected with no function specified.
	wantErr := "something bad happened"
	testErr := wire.MessageError{Description: wantErr}
	if testErr.Error() != wantErr {
		t.Errorf("MessageError: wrong error - got %v, want %v",
			testErr.Error(), wantErr)
	}

	// Ensure message errors are as expected with a function specified.
	wantFunc := "foo"
	testErr = wire.MessageError{Func: wantFunc, Description: wantErr}
	if testErr.Error() != wantFunc+": "+wantErr {
		t.Errorf("MessageError: wrong error - got %v, want %v",
			testErr.Error(), wantErr)
	}

	// Wire encoded bytes for a message that exceeds max overall message
	// length.
	mpl := uint32(wire.MaxMessagePayload)
	exceedMaxPayloadBytes := makeHeader(bmnet, "addr", mpl+1, 0)

	// Wire encoded bytes for a command which is invalid utf-8.
	badCommandBytes := makeHeader(bmnet, "bogus", 0, 0)
	badCommandBytes[4] = 0x81

	// A second test of bad command bytes to test discardInput.
	badCommandBytes2 := makeHeader(bmnet, "spoon", 12000, 0)
	badCommandBytes2[4] = 0x81
	badCommandBytes2 = append(badCommandBytes2, 0x1)

	// Wire encoded bytes for a command which is valid, but not supported.
	unsupportedCommandBytes := makeHeader(bmnet, "bogus", 0, 0)

	// Wire encoded bytes for a message which exceeds the max payload for
	// a specific message type.
	exceedTypePayloadBytes := makeHeader(bmnet, "verack", 1, 0)

	// Wire encoded bytes for a message which does not deliver the full
	// payload according to the header length.
	shortPayloadBytes := makeHeader(bmnet, "version", 115, 0)

	// Wire encoded bytes for a message with a bad checksum.
	badChecksumBytes := makeHeader(bmnet, "version", 2, 0xbeef)
	badChecksumBytes = append(badChecksumBytes, []byte{0x0, 0x0}...)

	// Wire encoded bytes for a message which has a valid header, but is
	// the wrong format.  An addr starts with a varint of the number of
	// contained in the message.  Claim there is two, but don't provide
	// them.  At the same time, forge the header fields so the message is
	// otherwise accurate.
	badMessageBytes := makeHeader(bmnet, "addr", 1, 0xfab848c9)
	badMessageBytes = append(badMessageBytes, 0x2)

	// Wire encoded bytes for a message which the header claims has 15k
	// bytes of data to discard.
	discardBytes := makeHeader(bmnet, "bogus", 15*1024, 0)

	// wrong network bytes
	wrongNetBytes := makeHeader(0x09090909, "", 0, 0)

	// wrong number of payload bytes within object command
	badReadBytes := makeHeader(bmnet, "object", 10, 0)

	// no actual object payload
	badPayloadBytes := makeHeader(bmnet, "object", 0, 0)

	// unknown object
	unknownObjectBytes := makeHeader(bmnet, "object", 20, 0)
	unknownObjectBytes = append(unknownObjectBytes, []byte{
		0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 5,
	}...)

	// too long object
	tooLongObjectBytes := makeHeader(bmnet, "object", 1<<18+1, 0)
	tooLongObjectBytes = append(tooLongObjectBytes, make([]byte, 1<<18+1)...)

	tests := []struct {
		buf     []byte             // Wire encoding
		bmnet   wire.BitmessageNet // Bitmessage network for wire.encoding
		max     int                // Max size of fixed buffer to induce errors
		readErr error              // Expected read error
		bytes   int                // Expected num bytes read
	}{
		// Latest protocol version with intentional read errors.

		// Short header.
		{
			[]byte{},
			bmnet,
			0,
			io.EOF,
			0,
		},

		// Wrong network.  Want MainNet, but giving wrong network.
		{
			wrongNetBytes,
			bmnet,
			len(wrongNetBytes),
			&wire.MessageError{},
			24,
		},

		// Exceed max overall message payload length.
		{
			exceedMaxPayloadBytes,
			bmnet,
			len(exceedMaxPayloadBytes),
			&wire.MessageError{},
			24,
		},

		// Invalid UTF-8 command.
		{
			badCommandBytes,
			bmnet,
			len(badCommandBytes),
			&wire.MessageError{},
			24,
		},

		// Invalid UTF-8 command to test discardInput.
		{
			badCommandBytes2,
			bmnet,
			len(badCommandBytes2),
			&wire.MessageError{},
			24,
		},

		// Valid, but unsupported command.
		{
			unsupportedCommandBytes,
			bmnet,
			len(unsupportedCommandBytes),
			&wire.MessageError{},
			24,
		},

		// Exceed max allowed payload for a message of a specific type.
		{
			exceedTypePayloadBytes,
			bmnet,
			len(exceedTypePayloadBytes),
			io.EOF,
			24,
		},

		// Message with a payload shorter than the header indicates.
		{
			shortPayloadBytes,
			bmnet,
			len(shortPayloadBytes),
			io.EOF,
			24,
		},

		// Message with a bad checksum.
		{
			badChecksumBytes,
			bmnet,
			len(badChecksumBytes),
			&wire.MessageError{},
			26,
		},

		// Message with a valid header, but wrong format.
		{
			badMessageBytes,
			bmnet,
			len(badMessageBytes),
			io.EOF,
			25,
		},

		// 15k bytes of data
		{
			discardBytes,
			bmnet,
			len(discardBytes),
			io.EOF,
			24,
		},

		// object type message without enough payload
		{
			badReadBytes,
			bmnet,
			len(badReadBytes),
			io.EOF,
			24,
		},

		// object type message without actual payload
		{
			badPayloadBytes,
			bmnet,
			len(badPayloadBytes),
			&wire.MessageError{},
			24,
		},

		// object type message with unknown object
		{
			unknownObjectBytes,
			bmnet,
			len(unknownObjectBytes),
			&wire.MessageError{},
			44,
		},

		// object type message that's too long
		{
			tooLongObjectBytes,
			bmnet,
			len(tooLongObjectBytes),
			&wire.MessageError{},
			1<<18 + 1 + 24,
		},
	}

	t.Logf("Running %d tests", len(tests))
	for i, test := range tests {
		// Decode from wire.format.
		r := fixed.NewReader(test.max, test.buf)
		nr, _, _, err := wire.ReadMessageN(r, test.bmnet)
		if reflect.TypeOf(err) != reflect.TypeOf(test.readErr) {
			t.Errorf("ReadMessage #%d wrong error got: %v <%T>, "+
				"want: %T", i, err, err, test.readErr)
			continue
		}

		// Ensure the number of bytes written match the expected value.
		if nr != test.bytes {
			t.Errorf("ReadMessage #%d unexpected num bytes read - "+
				"got %d, want %d", i, nr, test.bytes)
		}

		// For errors which are not of type wire.MessageError, check
		// them for equality.
		if _, ok := err.(*wire.MessageError); !ok {
			if err != test.readErr {
				t.Errorf("ReadMessage #%d wrong error got: %v <%T>, "+
					"want: %v <%T>", i, err, err,
					test.readErr, test.readErr)
				continue
			}
		}
	}
}

// TestWriteMessageWireErrors performs negative tests against wire.encoding from
// concrete messages to confirm error paths work correctly.
func TestWriteMessageWireErrors(t *testing.T) {
	bmnet := wire.MainNet
	wireErr := &wire.MessageError{}

	// Fake message with a command that is too long.
	badCommandMsg := &fakeMessage{command: "somethingtoolong"}

	// Fake message with a problem during encoding
	encodeErrMsg := &fakeMessage{forceEncodeErr: true}

	// Fake message that has payload which exceeds max overall message size.
	exceedOverallPayload := make([]byte, wire.MaxMessagePayload+1)
	exceedOverallPayloadErrMsg := &fakeMessage{payload: exceedOverallPayload}

	// Fake message that has payload which exceeds max allowed per message.
	exceedPayload := make([]byte, 1)
	exceedPayloadErrMsg := &fakeMessage{payload: exceedPayload, forceLenErr: true}

	// Fake message that is used to force errors in the header and payload
	// writes.
	bogusPayload := []byte{0x01, 0x02, 0x03, 0x04}
	bogusMsg := &fakeMessage{command: "bogus", payload: bogusPayload}

	tests := []struct {
		msg   wire.Message       // Message to encode
		bmnet wire.BitmessageNet // Bitmessage network for wire.encoding
		max   int                // Max size of fixed buffer to induce errors
		err   error              // Expected error
		bytes int                // Expected num bytes written
	}{
		// Command too long.
		{badCommandMsg, bmnet, 0, wireErr, 0},
		// Force error in payload encode.
		{encodeErrMsg, bmnet, 0, wireErr, 0},
		// Force error due to exceeding max overall message payload size.
		{exceedOverallPayloadErrMsg, bmnet, 0, wireErr, 0},
		// Force error due to exceeding max payload for message type.
		{exceedPayloadErrMsg, bmnet, 0, wireErr, 0},
		// Force error in header write.
		{bogusMsg, bmnet, 0, io.ErrShortWrite, 0},
		// Force error in payload write.
		{bogusMsg, bmnet, 24, io.ErrShortWrite, 24},
	}

	t.Logf("Running %d tests", len(tests))
	for i, test := range tests {
		// Encode wire.format.
		w := fixed.NewWriter(test.max)
		nw, err := wire.WriteMessageN(w, test.msg, test.bmnet)
		if reflect.TypeOf(err) != reflect.TypeOf(test.err) {
			t.Errorf("WriteMessage #%d wrong error got: %v <%T>, "+
				"want: %T", i, err, err, test.err)
			continue
		}

		// Ensure the number of bytes written match the expected value.
		if nw != test.bytes {
			t.Errorf("WriteMessage #%d unexpected num bytes "+
				"written - got %d, want %d", i, nw, test.bytes)
		}

		// For errors which are not of type wire.MessageError, check
		// them for equality.
		if _, ok := err.(*wire.MessageError); !ok {
			if err != test.err {
				t.Errorf("ReadMessage #%d wrong error got: %v <%T>, "+
					"want: %v <%T>", i, err, err,
					test.err, test.err)
				continue
			}
		}
	}
}

func TestEncodeMessageAndMessageHash(t *testing.T) {
	expires := time.Unix(3640198677, 0)

	tests := []struct {
		obj          obj.Object
		expectedData []byte
		expectedHash wire.ShaHash
	}{
		{ // pub key object message.
			// We don't need to try every different kind of message since they have their own
			// individual Encode methods.
			obj.NewEncryptedPubKey(543, expires, 1, &shahash, []byte{11, 12, 13, 14, 15, 16, 17, 18}),
			[]byte{
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x1f,
				0x00, 0x00, 0x00, 0x00, 0xd8, 0xf9, 0x06, 0x15,
				0x00, 0x00, 0x00, 0x01, 0x04, 0x01, 0x62, 0x63,
				0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6a, 0x6b,
				0x6c, 0x6d, 0x6e, 0x6f, 0x70, 0x71, 0x72, 0x73,
				0x74, 0x75, 0x76, 0x77, 0x78, 0x79, 0x7a, 0x7b,
				0x7c, 0x7d, 0x7e, 0x7f, 0x80, 0x81, 0x0b, 0x0c,
				0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12},
			wire.ShaHash([wire.HashSize]byte{
				0xaa, 0xa5, 0x88, 0xd4, 0x7a, 0xa2, 0x50, 0xfb,
				0x64, 0x46, 0x38, 0x08, 0x57, 0xa0, 0x6f, 0x9b,
				0xf7, 0x56, 0xf8, 0xb2, 0xd2, 0xe8, 0x59, 0xdf,
				0xc7, 0x4b, 0x64, 0x85, 0x47, 0x96, 0xe2, 0x80}),
		},
	}

	for i, test := range tests {
		obj := test.obj.MsgObject()
		encoded := wire.EncodeMessage(obj)

		if !bytes.Equal(test.expectedData, encoded) {
			t.Errorf("On test case %d, expected %v, got %v: ", i, spew.Sdump(test.expectedData), spew.Sdump(encoded))
		}

		if !test.expectedHash.IsEqual(obj.InventoryHash()) {
			t.Errorf("On test case %d, expected %v, got %v: ", i, spew.Sdump(test.expectedHash), spew.Sdump(obj.InventoryHash()))
		}
	}
}
