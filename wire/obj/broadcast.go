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

	"github.com/DanielKrawisz/bmutil/wire"
)

const (
	// TaglessBroadcastVersion is the broadcast version which does not contain
	// a tag.
	TaglessBroadcastVersion = 4

	// TaggedBroadcastVersion is the broadcast version from which tags for light
	// clients started being added at the beginning of the broadcast message.
	TaggedBroadcastVersion = 5
)

// Broadcast represents either kind of broadcast.
type Broadcast interface {
	Object
	Encrypted() []byte
	EncodeForSigning(io.Writer) error
}

// TaglessBroadcast implements the Object and Message interfaces and
// represents a broadcast message in tagless format that can be decrypted by
// all the clients that know the address of the sender.
type TaglessBroadcast struct {
	header    *wire.ObjectHeader
	encrypted []byte
}

// EncodeForSigning encodes the information in a TaglessBroadcast that
// is supposed to be signed. That's just the header.
func (msg *TaglessBroadcast) EncodeForSigning(w io.Writer) error {
	err := msg.header.EncodeForSigning(w)
	if err != nil {
		return err
	}

	return nil
}

func (msg *TaglessBroadcast) decodePayload(r io.Reader) error {
	var err error
	msg.encrypted, err = ioutil.ReadAll(r)

	return err
}

// Decode decodes r using the bitmessage protocol encoding into the receiver.
// This is part of the Message interface implementation.
func (msg *TaglessBroadcast) Decode(r io.Reader) error {
	var err error
	msg.header, err = wire.DecodeObjectHeader(r)
	if err != nil {
		return err
	}

	if msg.header.ObjectType != wire.ObjectTypeBroadcast {
		str := fmt.Sprintf("Object Type should be %d, but is %d",
			wire.ObjectTypeBroadcast, msg.header.ObjectType)
		return wire.NewMessageError("Decode", str)
	}

	if msg.header.Version != TaglessBroadcastVersion {
		str := fmt.Sprintf("Object Version should be %d, but is %d",
			TaglessBroadcastVersion, msg.header.Version)
		return wire.NewMessageError("Decode", str)
	}

	return msg.decodePayload(r)
}

func (msg *TaglessBroadcast) encodePayload(w io.Writer) (err error) {
	_, err = w.Write(msg.encrypted)
	return err
}

// Encode encodes the receiver to w using the bitmessage protocol encoding.
// This is part of the Message interface implementation.
func (msg *TaglessBroadcast) Encode(w io.Writer) error {
	err := msg.header.Encode(w)
	if err != nil {
		return err
	}

	return msg.encodePayload(w)
}

// MaxPayloadLength returns the maximum length the payload can be for the
// receiver. This is part of the Message interface implementation.
func (msg *TaglessBroadcast) MaxPayloadLength() int {
	return wire.MaxPayloadOfMsgObject
}

// String creates a human-readable string that with information
// about the broadcast.
func (msg *TaglessBroadcast) String() string {
	return fmt.Sprintf("Broadcast{%s, %s}",
		msg.header.String(), hex.EncodeToString(msg.encrypted))
}

// Header returns the object header.
func (msg *TaglessBroadcast) Header() *wire.ObjectHeader {
	return msg.header
}

// Payload return the object payload of the message.
func (msg *TaglessBroadcast) Payload() []byte {
	w := &bytes.Buffer{}
	msg.encodePayload(w)
	return w.Bytes()
}

// MsgObject transforms the PubKeyObject to a *MsgObject.
func (msg *TaglessBroadcast) MsgObject() *wire.MsgObject {
	return wire.NewMsgObject(msg.header, msg.Payload())
}

// InventoryHash returns the inv hash of the message.
func (msg *TaglessBroadcast) InventoryHash() *wire.ShaHash {
	return msg.MsgObject().InventoryHash()
}

// Command returns the protocol command string for the message. This is part
// of the Message interface implementation.
func (msg *TaglessBroadcast) Command() string {
	return wire.CmdObject
}

// Encrypted returns the encrypted data in this Broadcast.
func (msg *TaglessBroadcast) Encrypted() []byte {
	return msg.encrypted
}

// TaggedBroadcast implements the Object and Message interfaces and
// represents a broadcast message in tagged format that can be decrypted by
// all the clients that know the address of the sender.
type TaggedBroadcast struct {
	header    *wire.ObjectHeader
	Tag       *wire.ShaHash
	encrypted []byte
}

// EncodeForSigning encodes the information in the TaggedBroadcast required
// for signing. This is just the header and tag.
func (msg *TaggedBroadcast) EncodeForSigning(w io.Writer) error {
	err := msg.header.EncodeForSigning(w)
	if err != nil {
		return err
	}

	err = wire.WriteElement(w, msg.Tag)
	if err != nil {
		return err
	}

	return nil
}

// Decode decodes r using the bitmessage protocol encoding into the receiver.
// This is part of the Message interface implementation.
func (msg *TaggedBroadcast) decodePayload(r io.Reader) error {
	var err error
	msg.Tag = &wire.ShaHash{}

	err = wire.ReadElements(r, msg.Tag)
	if err != nil {
		return err
	}

	msg.encrypted, err = ioutil.ReadAll(r)

	return err
}

// Decode decodes r using the bitmessage protocol encoding into the receiver.
// This is part of the Message interface implementation.
func (msg *TaggedBroadcast) Decode(r io.Reader) error {
	var err error
	msg.header, err = wire.DecodeObjectHeader(r)
	if err != nil {
		return err
	}

	if msg.header.ObjectType != wire.ObjectTypeBroadcast {
		str := fmt.Sprintf("Object Type should be %d, but is %d",
			wire.ObjectTypeBroadcast, msg.header.ObjectType)
		return wire.NewMessageError("Decode", str)
	}

	if msg.header.Version != TaggedBroadcastVersion {
		str := fmt.Sprintf("Object Version should be %d, but is %d",
			TaggedBroadcastVersion, msg.header.Version)
		return wire.NewMessageError("Decode", str)
	}

	return msg.decodePayload(r)
}

func (msg *TaggedBroadcast) encodePayload(w io.Writer) (err error) {
	if err = wire.WriteElement(w, msg.Tag); err != nil {
		return err
	}

	_, err = w.Write(msg.encrypted)
	return err
}

// Encode encodes the receiver to w using the bitmessage protocol encoding.
// This is part of the Message interface implementation.
func (msg *TaggedBroadcast) Encode(w io.Writer) error {
	err := msg.header.Encode(w)
	if err != nil {
		return err
	}

	return msg.encodePayload(w)
}

// MaxPayloadLength returns the maximum length the payload can be for the
// receiver. This is part of the Message interface implementation.
func (msg *TaggedBroadcast) MaxPayloadLength() int {
	return wire.MaxPayloadOfMsgObject
}

func (msg *TaggedBroadcast) String() string {
	return fmt.Sprintf("Broadcast{%s, Tag:%s, %s}",
		msg.header.String(),
		hex.EncodeToString(msg.Tag.Bytes()),
		hex.EncodeToString(msg.encrypted))
}

// Header returns the object header.
func (msg *TaggedBroadcast) Header() *wire.ObjectHeader {
	return msg.header
}

// Payload return the object payload of the message.
func (msg *TaggedBroadcast) Payload() []byte {
	w := &bytes.Buffer{}
	msg.encodePayload(w)
	return w.Bytes()
}

// MsgObject transforms the PubKeyObject to a *MsgObject.
func (msg *TaggedBroadcast) MsgObject() *wire.MsgObject {
	return wire.NewMsgObject(msg.header, msg.Payload())
}

// InventoryHash returns the inv hash of the message.
func (msg *TaggedBroadcast) InventoryHash() *wire.ShaHash {
	return msg.MsgObject().InventoryHash()
}

// Command returns the protocol command string for the message. This is part
// of the Message interface implementation.
func (msg *TaggedBroadcast) Command() string {
	return wire.CmdObject
}

// Encrypted returns the encrypted data in this Broadcast.
func (msg *TaggedBroadcast) Encrypted() []byte {
	return msg.encrypted
}

// NewTaglessBroadcast returns a new object message that conforms to the
// Object interface using the passed parameters and defaults for the remaining
// fields.
func NewTaglessBroadcast(nonce uint64, expiration time.Time, streamNumber uint64,
	encrypted []byte) *TaglessBroadcast {
	return &TaglessBroadcast{
		header: wire.NewObjectHeader(
			nonce,
			expiration,
			wire.ObjectTypeBroadcast,
			TaglessBroadcastVersion,
			streamNumber,
		),
		encrypted: encrypted,
	}
}

// NewTaggedBroadcast returns a new object message that conforms to the
// Object interface using the passed parameters and defaults for the remaining
// fields.
func NewTaggedBroadcast(nonce uint64, expiration time.Time, streamNumber uint64,
	tag *wire.ShaHash, encrypted []byte) *TaggedBroadcast {
	return &TaggedBroadcast{
		header: wire.NewObjectHeader(
			nonce,
			expiration,
			wire.ObjectTypeBroadcast,
			TaggedBroadcastVersion,
			streamNumber,
		),
		Tag:       tag,
		encrypted: encrypted,
	}
}

// DecodeBroadcast takes a byte array and turns it into a broadcast object.
func DecodeBroadcast(obj []byte) (Broadcast, error) {
	r := bytes.NewReader(obj)
	header, err := wire.DecodeObjectHeader(r)
	if err != nil {
		return nil, err
	}

	switch header.Version {
	case TaggedBroadcastVersion:
		b := &TaggedBroadcast{header: header}
		return b, b.decodePayload(r)
	case TaglessBroadcastVersion:
		b := &TaglessBroadcast{header: header}
		return b, b.decodePayload(r)
	default:
		return nil, ErrInvalidVersion
	}
}
