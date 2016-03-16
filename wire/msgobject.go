// Copyright (c) 2015 Monetas
// Copyright 2016 Daniel Krawisz.
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package wire

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"time"

	"github.com/DanielKrawisz/bmutil"
)

const (
	// MaxPayloadOfMsgObject is the the maximum payload of object message = 2^18 bytes.
	// (not to be confused with the object payload)
	MaxPayloadOfMsgObject = 262144
)

// ObjectType represents the type of object than an object message contains.
// Objects in bitmessage are things on the network that get propagated. This can
// include requests/responses for pubkeys, messages and broadcasts.
type ObjectType uint32

// There are five types of objects in bitmessage.
//  - GetPubKey: requests for public keys.
//  - PubKey: public keys sent in response.
//  - Msg: bitmessage messages.
//  - Broadcast: broadcast messages.
// An ObjectType can also take on other values representing unknown message types.
const (
	ObjectTypeGetPubKey ObjectType = 0
	ObjectTypePubKey    ObjectType = 1
	ObjectTypeMsg       ObjectType = 2
	ObjectTypeBroadcast ObjectType = 3
)

// obStrings is a map of service flags back to their constant names for pretty
// printing.
var obStrings = map[ObjectType]string{
	ObjectTypeGetPubKey: "Getpubkey",
	ObjectTypePubKey:    "Pubkey",
	ObjectTypeMsg:       "Msg",
	ObjectTypeBroadcast: "Broadcast",
}

func (t ObjectType) String() string {
	if t >= ObjectType(4) {
		return "Unknown"
	}

	return obStrings[t]
}

// EncodeMsgObjectHeader encodes the object header to the given writer. Object
// header consists of Nonce, ExpiresTime, ObjectType, Version and Stream, in
// that order. Read Protocol Specifications for more information.
func EncodeMsgObjectHeader(w io.Writer, nonce uint64, expiresTime time.Time,
	objectType ObjectType, version uint64, streamNumber uint64) error {
	err := writeElements(w, nonce)
	if err != nil {
		return err
	}

	return EncodeMsgObjectSignatureHeader(w, expiresTime, objectType, version,
		streamNumber)
}

// EncodeMsgObjectSignatureHeader encodes the object header used for signing.
// It consists of everything in the normal object header except for nonce.
func EncodeMsgObjectSignatureHeader(w io.Writer, expiresTime time.Time,
	objectType ObjectType, version uint64, streamNumber uint64) error {
	err := writeElements(w, expiresTime, objectType)
	if err != nil {
		return err
	}
	if err = bmutil.WriteVarInt(w, version); err != nil {
		return err
	}
	if err = bmutil.WriteVarInt(w, streamNumber); err != nil {
		return err
	}
	return nil
}

// DecodeMsgObjectHeader decodes the object header from given reader. Object
// header consists of Nonce, ExpiresTime, ObjectType, Version and Stream, in
// that order. Read Protocol Specifications for more information.
func DecodeMsgObjectHeader(r io.Reader) (nonce uint64, expiresTime time.Time,
	objectType ObjectType, version uint64, streamNumber uint64, err error) {

	err = readElements(r, &nonce, &expiresTime, &objectType)
	if err != nil {
		return
	}

	if version, err = bmutil.ReadVarInt(r); err != nil {
		return
	}

	if streamNumber, err = bmutil.ReadVarInt(r); err != nil {
		return
	}
	return
}

// MsgObject implements the Message interface and represents a generic object.
type MsgObject struct {
	Nonce        uint64
	ExpiresTime  time.Time
	ObjectType   ObjectType
	Version      uint64
	StreamNumber uint64
	Payload      []byte
	invHash      *ShaHash
}

// Decode decodes r using the bitmessage protocol encoding into the receiver.
// This is part of the Message interface implementation.
func (msg *MsgObject) Decode(r io.Reader) error {
	var err error
	msg.Nonce, msg.ExpiresTime, msg.ObjectType, msg.Version,
		msg.StreamNumber, err = DecodeMsgObjectHeader(r)
	if err != nil {
		return err
	}

	msg.Payload, err = ioutil.ReadAll(r)

	return err
}

// Encode encodes the receiver to w using the bitmessage protocol encoding.
// This is part of the Message interface implementation.
func (msg *MsgObject) Encode(w io.Writer) error {
	err := EncodeMsgObjectHeader(w, msg.Nonce, msg.ExpiresTime, msg.ObjectType,
		msg.Version, msg.StreamNumber)
	if err != nil {
		return err
	}

	_, err = w.Write(msg.Payload)
	return err
}

// Command returns the protocol command string for the message. This is part
// of the Message interface implementation.
func (msg *MsgObject) Command() string {
	return CmdObject
}

// MaxPayloadLength returns the maximum length the payload can be for the
// receiver. This is part of the Message interface implementation.
func (msg *MsgObject) MaxPayloadLength() int {
	return MaxPayloadOfMsgObject
}

func (msg *MsgObject) String() string {
	return fmt.Sprintf("object: %s v%d, expires: %s, nonce: %d, stream: %d",
		msg.ObjectType, msg.Version, msg.ExpiresTime, msg.Nonce, msg.StreamNumber)
}

// InventoryHash takes double sha512 of the bytes and returns the first half.
// It calculates inventory hash of the object as required by the protocol.
func (msg *MsgObject) InventoryHash() *ShaHash {
	if msg.invHash == nil {
		hash, _ := NewShaHash(bmutil.DoubleSha512(EncodeMessage(msg))[:32])
		msg.invHash = hash
	}
	return msg.invHash
}

// Copy creates a new MsgObject identical to the original after a deep copy.
func (msg *MsgObject) Copy() *MsgObject {
	newMsg := *msg

	newMsg.Payload = make([]byte, len(msg.Payload))
	copy(newMsg.Payload, msg.Payload)

	newMsg.invHash = nil // can be recalculated

	return &newMsg
}

// DecodeMsgObject takes a byte array and turns it into an object message.
func DecodeMsgObject(obj []byte) (*MsgObject, error) {
	// Make sure that object type specific checks happen first.
	msg, err := detectMessageType(obj, CmdObject)
	if err != nil {
		return nil, err
	}
	err = msg.Decode(bytes.NewReader(obj))
	if err != nil {
		return nil, err
	}

	// Object is good, so make it MsgObject.
	msgObj := &MsgObject{}
	msgObj.Decode(bytes.NewReader(obj)) // no error
	return msgObj, err
}

// ToMsgObject converts a Message to the MsgObject concrete type.
func ToMsgObject(msg Message) (*MsgObject, error) {
	switch msg.(type) {
	case *MsgObject, *MsgGetPubKey, *MsgPubKey, *MsgMsg, *MsgBroadcast, *MsgUnknownObject:
		return DecodeMsgObject(EncodeMessage(msg))

	default:
		return nil, errors.New("Invalid message type")
	}
}

// NewMsgObject returns a new object message that conforms to the Message
// interface using the passed parameters and defaults for the remaining fields.
func NewMsgObject(nonce uint64, expires time.Time, objectType ObjectType, version, streamNumber uint64, payload []byte) *MsgObject {
	return &MsgObject{
		Nonce:        nonce,
		ExpiresTime:  expires,
		ObjectType:   objectType,
		Version:      version,
		StreamNumber: streamNumber,
		Payload:      payload,
	}
}
