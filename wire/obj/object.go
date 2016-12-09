// Copyright 2016 Daniel Krawisz.
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package obj

import (
	"bytes"
	"errors"
	"io"

	"github.com/DanielKrawisz/bmutil/wire"
)

// ErrInvalidVersion is returned when a message is decoded with an
// unrecognized or invalid version.
var ErrInvalidVersion = errors.New("Invalid version")

// Object is an interface an object message. Object messages can represent
// many different things, and therefore we might want many different
// internal representations for them. Therefore we use an interface.
type Object interface {
	Decode(io.Reader) error
	Encode(io.Writer) error
	MsgObject() *wire.MsgObject
	Header() *wire.ObjectHeader
	Payload() []byte
	InventoryHash() *wire.ShaHash
	String() string
}

// ReadObject tries to convert a MsgObject into an an Object.
func ReadObject(o *wire.MsgObject) Object {
	encoded := bytes.NewReader(wire.EncodeMessage(o))

	var obj Object
	switch o.Header().ObjectType {
	case wire.ObjectTypeGetPubKey:
		obj = &GetPubKey{}
	case wire.ObjectTypePubKey:
		switch o.Header().Version {
		case SimplePubKeyVersion:
			obj = &SimplePubKey{}
		case ExtendedPubKeyVersion:
			obj = &ExtendedPubKey{}
		case EncryptedPubKeyVersion:
			obj = &EncryptedPubKey{}
		default:
			return o
		}
	case wire.ObjectTypeMsg:
		obj = &Message{}
	case wire.ObjectTypeBroadcast:
		switch o.Header().Version {
		case TaggedBroadcastVersion:
			obj = &TaggedBroadcast{}
		case TaglessBroadcastVersion:
			obj = &TaglessBroadcast{}
		default:
			return o
		}
	default:
		return o
	}

	err := obj.Decode(encoded)
	if err != nil {
		return o
	}
	return obj
}
