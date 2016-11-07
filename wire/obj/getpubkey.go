// Copyright (c) 2015 Monetas
// Copyright 2016 Daniel Krawisz.
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package obj

import (
	"bytes"
	"fmt"
	"io"
	"time"

	"github.com/DanielKrawisz/bmutil/wire"
)

const (
	// TagGetPubKeyVersion specifies the version of GetPubKey from which
	// tags started being encoded in messages and not ripe. This was done to
	// thwart any public key/address harvesting attempts.
	TagGetPubKeyVersion = 4
)

// GetPubKey implements the Message interface and represents a request for a
// public key. If Version <= TagGetPubKeyVersion, tag is encoded in message and
// not ripe.
type GetPubKey struct {
	wire.ObjectHeader
	Ripe *wire.RipeHash
	Tag  *wire.ShaHash
}

// Decode decodes r using the bitmessage protocol encoding into the receiver.
// This is part of the Message interface implementation.
func (msg *GetPubKey) Decode(r io.Reader) error {
	var err error
	msg.ObjectHeader, err = wire.DecodeMsgObjectHeader(r)
	if err != nil {
		return err
	}

	if msg.ObjectType != wire.ObjectTypeGetPubKey {
		str := fmt.Sprintf("Object Type should be %d, but is %d",
			wire.ObjectTypeGetPubKey, msg.ObjectType)
		return wire.NewMessageError("Decode", str)
	}

	switch msg.Version {
	case TagGetPubKeyVersion:
		msg.Tag, _ = wire.NewShaHash(make([]byte, wire.HashSize))
		if err = wire.ReadElement(r, msg.Tag); err != nil {
			return err
		}
	case SimplePubKeyVersion, ExtendedPubKeyVersion:
		msg.Ripe, _ = wire.NewRipeHash(make([]byte, 20))
		if err = wire.ReadElement(r, msg.Ripe); err != nil {
			return err
		}
	default:
		return wire.NewMessageError("GetPubKey.Decode", "unsupported pubkey version")
	}

	return err
}

func (msg *GetPubKey) encodePayload(w io.Writer) (err error) {
	switch msg.Version {
	case TagGetPubKeyVersion:
		if err = wire.WriteElement(w, msg.Tag); err != nil {
			return err
		}
	case SimplePubKeyVersion, ExtendedPubKeyVersion:
		if err = wire.WriteElement(w, msg.Ripe); err != nil {
			return err
		}
	default:
		return wire.NewMessageError("GetPubKey.Decode", "unsupported pubkey version")
	}

	return
}

// Encode encodes the receiver to w using the bitmessage protocol encoding.
// This is part of the Message interface implementation.
func (msg *GetPubKey) Encode(w io.Writer) error {
	err := msg.ObjectHeader.Encode(w)
	if err != nil {
		return err
	}

	return msg.encodePayload(w)
}

// MaxPayloadLength returns the maximum length the payload can be for the
// receiver. This is part of the Message interface implementation.
func (msg *GetPubKey) MaxPayloadLength() int {
	return 70
}

func (msg *GetPubKey) String() string {
	return fmt.Sprintf("getpubkey: v%d %d %s %d %x %x", msg.Version, msg.Nonce, msg.ExpiresTime, msg.StreamNumber, msg.Ripe, msg.Tag)
}

// Header returns the object header.
func (msg *GetPubKey) Header() *wire.ObjectHeader {
	return &msg.ObjectHeader
}

// Payload return the object payload of the message.
func (msg *GetPubKey) Payload() []byte {
	w := &bytes.Buffer{}
	msg.encodePayload(w)
	return w.Bytes()
}

// MsgObject transforms the PubKeyObject to a *MsgObject.
func (msg *GetPubKey) MsgObject() *wire.MsgObject {
	return wire.NewMsgObject(msg.ObjectHeader.Nonce,
		msg.ObjectHeader.ExpiresTime, msg.ObjectHeader.ObjectType,
		msg.ObjectHeader.Version, msg.ObjectHeader.StreamNumber, msg.Payload())
}

func (msg *GetPubKey) InventoryHash() *wire.ShaHash {
	return msg.MsgObject().InventoryHash()
}

// NewGetPubKey returns a new object message that conforms to the
// Message interface using the passed parameters and defaults for the remaining
// fields.
func NewGetPubKey(nonce uint64, expires time.Time, version, streamNumber uint64,
	ripe *wire.RipeHash, tag *wire.ShaHash) *GetPubKey {

	// Limit the timestamp to one second precision since the protocol
	// doesn't support better.
	return &GetPubKey{
		ObjectHeader: wire.ObjectHeader{
			Nonce:        nonce,
			ExpiresTime:  expires,
			ObjectType:   wire.ObjectTypeGetPubKey,
			Version:      version,
			StreamNumber: streamNumber,
		},
		Ripe: ripe,
		Tag:  tag,
	}
}
