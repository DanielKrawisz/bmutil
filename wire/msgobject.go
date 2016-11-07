// Copyright (c) 2015 Monetas
// Copyright 2016 Daniel Krawisz.
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package wire

import (
	"bytes"
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

// MsgObject implements the Message interface and represents a generic object.
type MsgObject struct {
	ObjectHeader
	payload []byte
	invHash *ShaHash
}

// Decode decodes r using the bitmessage protocol encoding into the receiver.
// This is part of the Message interface implementation.
func (msg *MsgObject) Decode(r io.Reader) error {
	var err error
	msg.ObjectHeader, err = DecodeMsgObjectHeader(r)
	if err != nil {
		return err
	}

	msg.payload, err = ioutil.ReadAll(r)

	return err
}

// Encode encodes the receiver to w using the bitmessage protocol encoding.
// This is part of the Message interface implementation.
func (msg *MsgObject) Encode(w io.Writer) error {
	err := msg.ObjectHeader.Encode(w)
	if err != nil {
		return err
	}

	_, err = w.Write(msg.payload)
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

// Header returns the object header.
func (msg *MsgObject) Header() *ObjectHeader {
	return &msg.ObjectHeader
}

// ObjectPayload return the object payload of the message.
func (msg *MsgObject) Payload() []byte {
	return msg.payload
}

// MsgObject transforms the PubKeyObject to a *MsgObject.
func (msg *MsgObject) MsgObject() *MsgObject {
	return msg
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
	newMsg := &MsgObject{}

	newMsg.payload = make([]byte, len(msg.payload))
	copy(newMsg.payload, msg.payload)

	newMsg.invHash = nil // can be recalculated

	return newMsg
}

// DecodeMsgObject takes a byte array and turns it into an object message.
func DecodeMsgObject(obj []byte) (*MsgObject, error) {
	// Object is good, so make it MsgObject.
	msgObj := &MsgObject{}
	err := msgObj.Decode(bytes.NewReader(obj)) // no error
	if err != nil {
		return nil, err
	}
	return msgObj, nil
}

// NewMsgObject returns a new object message that conforms to the Message
// interface using the passed parameters and defaults for the remaining fields.
func NewMsgObject(nonce uint64, expires time.Time, objectType ObjectType, version, streamNumber uint64, payload []byte) *MsgObject {
	return &MsgObject{
		ObjectHeader: ObjectHeader{
			Nonce:        nonce,
			ExpiresTime:  expires,
			ObjectType:   objectType,
			Version:      version,
			StreamNumber: streamNumber,
		},
		payload: payload,
	}
}
