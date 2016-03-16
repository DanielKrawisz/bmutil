// Copyright (c) 2015 Monetas
// Copyright 2016 Daniel Krawisz.
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package wire

import (
	"io"
)

// MsgPong defines a bitmessage pong message which is used by a peer to ensure
// that the connection between itself and another peer doesn't time out due to
// inactivity. It implements the Message interface.
//
// This message has no payload.
type MsgPong struct{}

// Decode decodes r using the bitmessage protocol encoding into the receiver.
// This is part of the Message interface implementation.
func (msg *MsgPong) Decode(r io.Reader) error {
	return nil
}

// Encode encodes the receiver to w using the bitmessage protocol encoding.
// This is part of the Message interface implementation.
func (msg *MsgPong) Encode(w io.Writer) error {
	return nil
}

// Command returns the protocol command string for the message. This is part
// of the Message interface implementation.
func (msg *MsgPong) Command() string {
	return CmdPong
}

// MaxPayloadLength returns the maximum length the payload can be for the
// receiver. This is part of the Message interface implementation.
func (msg *MsgPong) MaxPayloadLength() int {
	return 0
}

// NewMsgPong returns a new bitmessage verack message that conforms to the
// Message interface.
func NewMsgPong() *MsgPong {
	return &MsgPong{}
}
