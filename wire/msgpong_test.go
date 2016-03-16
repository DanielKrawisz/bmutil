// Copyright (c) 2015 Monetas
// Copyright 2016 Daniel Krawisz.
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package wire_test

import (
	"bytes"
	"reflect"
	"testing"

	"github.com/davecgh/go-spew/spew"
	"github.com/DanielKrawisz/bmutil/wire"
)

// TestPong tests the MsgPong API.
func TestPong(t *testing.T) {
	// Ensure the command is expected value.
	wantCmd := "pong"
	msg := wire.NewMsgPong()
	if cmd := msg.Command(); cmd != wantCmd {
		t.Errorf("NewMsgPong: wrong command - got %v want %v",
			cmd, wantCmd)
	}

	// Ensure max payload is expected value.
	wantPayload := 0
	maxPayload := msg.MaxPayloadLength()
	if maxPayload != wantPayload {
		t.Errorf("MaxPayloadLength: wrong max payload length, "+
			"got %v, want %v", maxPayload, wantPayload)
	}

	return
}

// TestPongWire tests the MsgPong wire.encode and decode for various
// protocol versions.
func TestPongWire(t *testing.T) {
	msgPong := wire.NewMsgPong()
	msgPongEncoded := []byte{}

	tests := []struct {
		in  *wire.MsgPong // Message to encode
		out *wire.MsgPong // Expected decoded message
		buf []byte        // Wire encoding
	}{
		// Latest protocol version.
		{
			msgPong,
			msgPong,
			msgPongEncoded,
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
		var msg wire.MsgPong
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
