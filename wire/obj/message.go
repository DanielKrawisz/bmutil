// Copyright (c) 2015 Monetas
// Copyright 2016 Daniel Krawisz.
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package obj

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"io"
	"io/ioutil"
	"time"

	"github.com/DanielKrawisz/bmutil/pow"
	"github.com/DanielKrawisz/bmutil/wire"
)

// MessageVersion is the standard version number for message objects.
const MessageVersion = 1

// Message implements the Object and Message interfaces and represents a
// message sent between two addresses. It can be decrypted only by those
// that have the private encryption key that corresponds to the
// destination address.
type Message struct {
	header    *wire.ObjectHeader
	Encrypted []byte
}

// Decode decodes r using the bitmessage protocol encoding into the receiver.
// This is part of the Message interface implementation.
func (msg *Message) Decode(r io.Reader) error {
	var err error
	msg.header, err = wire.DecodeObjectHeader(r)
	if err != nil {
		return err
	}

	if msg.header.ObjectType != wire.ObjectTypeMsg {
		str := fmt.Sprintf("Object Type should be %d, but is %d",
			wire.ObjectTypeMsg, msg.header.ObjectType)
		return wire.NewMessageError("Decode", str)
	}

	msg.Encrypted, err = ioutil.ReadAll(r)

	return err
}

// Encode encodes the receiver to w using the bitmessage protocol encoding.
// This is part of the Message interface implementation.
func (msg *Message) Encode(w io.Writer) error {
	err := msg.header.Encode(w)
	if err != nil {
		return err
	}

	_, err = w.Write(msg.Encrypted)
	return err
}

// MaxPayloadLength returns the maximum length the payload can be for the
// receiver. This is part of the Message interface implementation.
func (msg *Message) MaxPayloadLength() int {
	return wire.MaxPayloadOfMsgObject
}

func (msg *Message) String() string {
	return fmt.Sprintf("Message{%s, %s}",
		msg.header.String(),
		hex.EncodeToString(msg.Encrypted))
}

// Command returns the protocol command string for the message. This is part
// of the Message interface implementation.
func (msg *Message) Command() string {
	return wire.CmdObject
}

// Header returns the object header.
func (msg *Message) Header() *wire.ObjectHeader {
	return msg.header
}

// Payload return the object payload of the message.
func (msg *Message) Payload() []byte {
	return msg.Encrypted
}

// MsgObject transforms the PubKeyObject to a *MsgObject.
func (msg *Message) MsgObject() *wire.MsgObject {
	return wire.NewMsgObject(msg.header, msg.Encrypted)
}

// InventoryHash returns the inventory hash of the message.
func (msg *Message) InventoryHash() *wire.ShaHash {
	return msg.MsgObject().InventoryHash()
}

// NewMessage returns a new object message that conforms to the Message interface
// using the passed parameters and defaults for the remaining fields.
func NewMessage(nonce pow.Nonce, expiration time.Time, streamNumber uint64, encrypted []byte) *Message {
	return &Message{
		header: wire.NewObjectHeader(
			nonce,
			expiration,
			wire.ObjectTypeMsg,
			MessageVersion,
			streamNumber,
		),
		Encrypted: encrypted,
	}
}

// DecodeMessage takes a byte array and turns it into a message object.
func DecodeMessage(obj []byte) (*Message, error) {
	// Make sure that object type specific checks happen first.
	var msg *Message
	err := msg.Decode(bytes.NewReader(obj))
	if err != nil {
		return nil, err
	}

	return msg, nil
}
