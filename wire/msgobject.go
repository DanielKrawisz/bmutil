// Copyright (c) 2015 Monetas
// Copyright 2016 Daniel Krawisz.
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package wire

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"io/ioutil"
	"time"

	"github.com/DanielKrawisz/bmutil"
	"github.com/DanielKrawisz/bmutil/pow"
)

const (
	// MaxPayloadOfMsgObject is the the maximum payload of object message = 2^18 bytes.
	// (not to be confused with the object payload)
	MaxPayloadOfMsgObject = 262144
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
	header  *ObjectHeader
	payload []byte
}

// Decode decodes r using the bitmessage protocol encoding into the receiver.
// This is part of the Message interface implementation.
func (msg *MsgObject) Decode(r io.Reader) error {
	var err error
	msg.header, err = DecodeObjectHeader(r)
	if err != nil {
		return err
	}

	msg.payload, err = ioutil.ReadAll(r)

	return err
}

// Encode encodes the receiver to w using the bitmessage protocol encoding.
// This is part of the Message interface implementation.
func (msg *MsgObject) Encode(w io.Writer) error {
	err := msg.header.Encode(w)
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
	return fmt.Sprintf("Object{%s, Payload: %s}", msg.header, hex.EncodeToString(msg.payload))
}

// Header returns the object header.
func (msg *MsgObject) Header() *ObjectHeader {
	return msg.header
}

// Payload return the object payload of the message.
func (msg *MsgObject) Payload() []byte {
	return msg.payload
}

// Check checks if the POW that was done for an object message is sufficient.
// obj is a byte slice containing the object message.
func (msg *MsgObject) CheckPow(data pow.Data, refTime time.Time) bool {
	// calculate ttl from bytes 8-16 that contain ExpiresTime
	ttl := uint64(msg.Header().Expiration().Unix() - refTime.Unix())

	obj := Encode(msg)
	msgHash := bmutil.Sha512(obj[8:]) // exclude nonce value in the beginning
	payloadLength := uint64(len(obj))

	hashData := make([]byte, 8+len(msgHash))
	copy(hashData[:8], obj[:8]) // nonce
	copy(hashData[8:], msgHash)
	resultHash := bmutil.DoubleSha512(hashData)

	powValue := binary.BigEndian.Uint64(resultHash[0:8])

	target := pow.CalculateTarget(payloadLength, ttl, data)

	return powValue <= target
}

// Copy creates a new MsgObject identical to the original after a deep copy.
func (msg *MsgObject) Copy() *MsgObject {
	newMsg := &MsgObject{}

	newMsg.payload = make([]byte, len(msg.payload))
	copy(newMsg.payload, msg.payload)
	newMsg.header = msg.header

	return newMsg
}

// DecodeMsgObject takes a byte array and turns it into an object message.
func DecodeMsgObject(obj []byte) (*MsgObject, error) {
	msgObj := &MsgObject{}
	err := msgObj.Decode(bytes.NewReader(obj)) // no error
	if err != nil {
		return nil, err
	}
	return msgObj, nil
}

// NewMsgObject returns a new object message that conforms to the Message
// interface using the passed parameters and defaults for the remaining fields.
func NewMsgObject(header *ObjectHeader, payload []byte) *MsgObject {
	return &MsgObject{
		header:  header,
		payload: payload,
	}
}
