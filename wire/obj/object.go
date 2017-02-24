// Copyright 2016 Daniel Krawisz.
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package obj

import (
	"bytes"
	"errors"
	"io"
	"io/ioutil"

	"github.com/DanielKrawisz/bmutil/hash"
	"github.com/DanielKrawisz/bmutil/wire"
)

// ErrInvalidVersion is returned when a message is decoded with an
// unrecognized or invalid version.
var ErrInvalidVersion = errors.New("Invalid version")

// Object is an interface an object message. Object messages can represent
// many different things, and therefore we might want many different
// internal representations for them. Therefore we use an interface.
type Object interface {
	wire.Message
	Header() *wire.ObjectHeader
	Payload() []byte
	String() string
}

type decodableObject interface {
	Object
	decodePayload(io.Reader) error
}

// InventoryHash returns the hash of the object, as defined by the
// Bitmessage protocol.
func InventoryHash(obj Object) *hash.Sha {
	return hash.InventoryHash(wire.Encode(obj))
}

// DecodeObject tries to convert a MsgObject into an an Object.
func DecodeObject(r io.Reader) (Object, error) {
	header, err := wire.DecodeObjectHeader(r)
	if err != nil {
		return nil, err
	}

	var obj decodableObject
	switch header.ObjectType {
	case wire.ObjectTypeGetPubKey:
		obj = &GetPubKey{header: header}
	case wire.ObjectTypePubKey:
		switch header.Version {
		case SimplePubKeyVersion:
			obj = &SimplePubKey{header: header}
		case ExtendedPubKeyVersion:
			obj = &ExtendedPubKey{header: header}
		case EncryptedPubKeyVersion:
			obj = &EncryptedPubKey{header: header}
		}
	case wire.ObjectTypeMsg:
		obj = &Message{header: header}
	case wire.ObjectTypeBroadcast:
		switch header.Version {
		case TaggedBroadcastVersion:
			obj = &TaggedBroadcast{header: header}
		case TaglessBroadcastVersion:
			obj = &TaglessBroadcast{header: header}
		}
	}

	if obj != nil {
		err := obj.decodePayload(r)
		if err == nil {
			return obj, nil
		}
	}

	payload, err := ioutil.ReadAll(r)
	if err != nil {
		return nil, err
	}

	return wire.NewMsgObject(header, payload), nil
}

// ReadObject tries to convert a MsgObject into an an Object.
func ReadObject(obj []byte) (Object, error) {
	r := bytes.NewReader(obj)
	return DecodeObject(r)
}
