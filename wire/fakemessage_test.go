// Originally derived from: btcsuite/btcd/wire/fakemessage_test.go
// Copyright (c) 2013-2015 Conformal Systems LLC.

// Copyright (c) 2015 Monetas
// Copyright 2016 Daniel Krawisz.
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package wire_test

import (
	"io"

	"github.com/DanielKrawisz/bmutil/wire"
)

// fakeMessage implements the wire.Message interface and is used to force
// encode errors in messages.
type fakeMessage struct {
	command        string
	payload        []byte
	forceEncodeErr bool
	forceLenErr    bool
}

// Decode doesn't do anything.  It just satisfies the wire.Message
// interface.
func (msg *fakeMessage) Decode(r io.Reader) error {
	return nil
}

// Encode writes the payload field of the fake message or forces an error
// if the forceEncodeErr flag of the fake message is set.  It also satisfies the
// wire.Message interface.
func (msg *fakeMessage) Encode(w io.Writer) error {
	if msg.forceEncodeErr {
		err := &wire.MessageError{
			Func:        "fakeMessage.Encode",
			Description: "intentional error",
		}
		return err
	}

	_, err := w.Write(msg.payload)
	return err
}

// Command returns the command field of the fake message and satisfies the
// wire.Message interface.
func (msg *fakeMessage) Command() string {
	return msg.command
}

// MaxPayloadLength returns the length of the payload field of fake message
// or a smaller value if the forceLenErr flag of the fake message is set.  It
// satisfies the wire.Message interface.
func (msg *fakeMessage) MaxPayloadLength() int {
	lenp := len(msg.payload)
	if msg.forceLenErr {
		return lenp - 1
	}

	return lenp
}
