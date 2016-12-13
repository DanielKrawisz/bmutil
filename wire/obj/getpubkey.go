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
	"time"

	"github.com/DanielKrawisz/bmutil/pow"
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
	header *wire.ObjectHeader
	Ripe   *wire.RipeHash
	Tag    *wire.ShaHash
}

func (msg *GetPubKey) decodePayload(r io.Reader) error {
	var err error
	switch msg.header.Version {
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

// Decode decodes r using the bitmessage protocol encoding into the receiver.
// This is part of the Message interface implementation.
func (msg *GetPubKey) Decode(r io.Reader) error {
	var err error
	msg.header, err = wire.DecodeObjectHeader(r)
	if err != nil {
		return err
	}

	if msg.header.ObjectType != wire.ObjectTypeGetPubKey {
		str := fmt.Sprintf("Object Type should be %d, but is %d",
			wire.ObjectTypeGetPubKey, msg.header.ObjectType)
		return wire.NewMessageError("Decode", str)
	}

	return msg.decodePayload(r)
}

func (msg *GetPubKey) encodePayload(w io.Writer) (err error) {
	switch msg.header.Version {
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
	err := msg.header.Encode(w)
	if err != nil {
		return err
	}

	return msg.encodePayload(w)
}

// String returns a human-readible string representation of the GetPubKey.
func (msg *GetPubKey) String() string {
	var hash string
	if msg.Ripe == nil {
		hash = hex.EncodeToString(msg.Tag.Bytes())
	} else {
		hash = hex.EncodeToString(msg.Ripe.Bytes())
	}
	return fmt.Sprintf("GetPubKey{%s, %s}", msg.header.String(), hash)
}

// Command returns the protocol command string for the message. This is part
// of the Message interface implementation.
func (msg *GetPubKey) Command() string {
	return wire.CmdObject
}

// MaxPayloadLength returns the maximum length the payload can be for the
// receiver. This is part of the Message interface implementation.
func (msg *GetPubKey) MaxPayloadLength() int {
	return wire.MaxPayloadOfMsgObject
}

// Header returns the object header.
func (msg *GetPubKey) Header() *wire.ObjectHeader {
	return msg.header
}

// Payload return the object payload of the message.
func (msg *GetPubKey) Payload() []byte {
	w := &bytes.Buffer{}
	msg.encodePayload(w)
	return w.Bytes()
}

// MsgObject transforms the PubKeyObject to a *MsgObject.
func (msg *GetPubKey) MsgObject() *wire.MsgObject {
	return wire.NewMsgObject(msg.header, msg.Payload())
}

// InventoryHash returns the inv hash of the message.
func (msg *GetPubKey) InventoryHash() *wire.ShaHash {
	return msg.MsgObject().InventoryHash()
}

// NewGetPubKey returns a new object message that conforms to the
// Message interface using the passed parameters and defaults for the remaining
// fields.
func NewGetPubKey(nonce pow.Nonce, expiration time.Time, version, streamNumber uint64,
	ripe *wire.RipeHash, tag *wire.ShaHash) *GetPubKey {

	// Limit the timestamp to one second precision since the protocol
	// doesn't support better.
	return &GetPubKey{
		header: wire.NewObjectHeader(
			nonce,
			expiration,
			wire.ObjectTypeGetPubKey,
			version,
			streamNumber),
		Ripe: ripe,
		Tag:  tag,
	}
}
