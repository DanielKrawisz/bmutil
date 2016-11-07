// Copyright (c) 2015 Monetas
// Copyright 2016 Daniel Krawisz.
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package obj

import (
	"bytes"
	"fmt"
	"io"
	"io/ioutil"
	"time"

	"github.com/DanielKrawisz/bmutil"
	"github.com/DanielKrawisz/bmutil/wire"
)

// Message implements the Message interface and represents a message sent between
// two addresses. It can be decrypted only by those that have the private
// encryption key that corresponds to the destination address.
type Message struct {
	wire.ObjectHeader
	Encrypted          []byte
	FromAddressVersion uint64
	FromStreamNumber   uint64
	Behavior           uint32
	SigningKey         *wire.PubKey
	EncryptionKey      *wire.PubKey
	NonceTrials        uint64
	ExtraBytes         uint64
	Destination        *wire.RipeHash
	Encoding           uint64
	Message            []byte
	Ack                []byte
	Signature          []byte
}

// Decode decodes r using the bitmessage protocol encoding into the receiver.
// This is part of the Message interface implementation.
func (msg *Message) Decode(r io.Reader) error {
	var err error
	msg.ObjectHeader, err = wire.DecodeMsgObjectHeader(r)
	if err != nil {
		return err
	}

	if msg.ObjectType != wire.ObjectTypeMsg {
		str := fmt.Sprintf("Object Type should be %d, but is %d",
			wire.ObjectTypeMsg, msg.ObjectType)
		return wire.NewMessageError("Decode", str)
	}

	msg.Encrypted, err = ioutil.ReadAll(r)

	return err
}

// Encode encodes the receiver to w using the bitmessage protocol encoding.
// This is part of the Message interface implementation.
func (msg *Message) Encode(w io.Writer) error {
	err := msg.ObjectHeader.Encode(w)
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
	return fmt.Sprintf("msg: v%d %d %s %d %x", msg.Version, msg.Nonce, msg.ExpiresTime, msg.StreamNumber, msg.Encrypted)
}

// EncodeForSigning encodes Message so that it can be hashed and signed.
func (msg *Message) EncodeForSigning(w io.Writer) error {
	err := msg.ObjectHeader.EncodeForSigning(w)
	if err != nil {
		return err
	}
	if err = bmutil.WriteVarInt(w, msg.FromAddressVersion); err != nil {
		return err
	}
	if err = bmutil.WriteVarInt(w, msg.FromStreamNumber); err != nil {
		return err
	}
	err = wire.WriteElements(w, msg.Behavior, msg.SigningKey, msg.EncryptionKey)
	if err != nil {
		return err
	}
	if msg.FromAddressVersion >= 3 {
		if err = bmutil.WriteVarInt(w, msg.NonceTrials); err != nil {
			return err
		}
		if err = bmutil.WriteVarInt(w, msg.ExtraBytes); err != nil {
			return err
		}
	}
	err = wire.WriteElement(w, msg.Destination)
	if err != nil {
		return err
	}
	if err = bmutil.WriteVarInt(w, msg.Encoding); err != nil {
		return err
	}
	msgLength := uint64(len(msg.Message))
	if err = bmutil.WriteVarInt(w, msgLength); err != nil {
		return err
	}
	if _, err := w.Write(msg.Message); err != nil {
		return err
	}
	ackLength := uint64(len(msg.Ack))
	if err = bmutil.WriteVarInt(w, ackLength); err != nil {
		return err
	}
	if _, err := w.Write(msg.Ack); err != nil {
		return err
	}
	return nil
}

// EncodeForEncryption encodes Message so that it can be encrypted.
func (msg *Message) EncodeForEncryption(w io.Writer) error {
	if err := bmutil.WriteVarInt(w, msg.FromAddressVersion); err != nil {
		return err
	}
	if err := bmutil.WriteVarInt(w, msg.FromStreamNumber); err != nil {
		return err
	}
	err := wire.WriteElements(w, msg.Behavior, msg.SigningKey, msg.EncryptionKey)
	if err != nil {
		return err
	}
	if msg.FromAddressVersion >= 3 {
		if err = bmutil.WriteVarInt(w, msg.NonceTrials); err != nil {
			return err
		}
		if err = bmutil.WriteVarInt(w, msg.ExtraBytes); err != nil {
			return err
		}
	}
	if err = wire.WriteElement(w, msg.Destination); err != nil {
		return err
	}
	if err = bmutil.WriteVarInt(w, msg.Encoding); err != nil {
		return err
	}
	msgLength := uint64(len(msg.Message))
	if err = bmutil.WriteVarInt(w, msgLength); err != nil {
		return err
	}
	if _, err := w.Write(msg.Message); err != nil {
		return err
	}
	ackLength := uint64(len(msg.Ack))
	if err = bmutil.WriteVarInt(w, ackLength); err != nil {
		return err
	}
	if _, err := w.Write(msg.Ack); err != nil {
		return err
	}
	sigLength := uint64(len(msg.Signature))
	if err = bmutil.WriteVarInt(w, sigLength); err != nil {
		return err
	}
	if _, err = w.Write(msg.Signature); err != nil {
		return err
	}
	return nil
}

// DecodeFromDecrypted decodes Message from its decrypted form.
func (msg *Message) DecodeFromDecrypted(r io.Reader) error {
	var err error
	if msg.FromAddressVersion, err = bmutil.ReadVarInt(r); err != nil {
		return err
	}
	if msg.FromStreamNumber, err = bmutil.ReadVarInt(r); err != nil {
		return err
	}
	msg.SigningKey = &wire.PubKey{}
	msg.EncryptionKey = &wire.PubKey{}
	err = wire.ReadElements(r, &msg.Behavior, msg.SigningKey, msg.EncryptionKey)
	if err != nil {
		return err
	}
	if msg.FromAddressVersion >= 3 {
		if msg.NonceTrials, err = bmutil.ReadVarInt(r); err != nil {
			return err
		}
		if msg.ExtraBytes, err = bmutil.ReadVarInt(r); err != nil {
			return err
		}
	}
	msg.Destination = &wire.RipeHash{}
	if err = wire.ReadElement(r, msg.Destination); err != nil {
		return err
	}
	if msg.Encoding, err = bmutil.ReadVarInt(r); err != nil {
		return err
	}
	var msgLength uint64
	if msgLength, err = bmutil.ReadVarInt(r); err != nil {
		return err
	}
	if msgLength > wire.MaxPayloadOfMsgObject {
		str := fmt.Sprintf("message length exceeds max length - "+
			"indicates %d, but max length is %d",
			msgLength, wire.MaxPayloadOfMsgObject)
		return wire.NewMessageError("DecodeFromDecrypted", str)
	}
	msg.Message = make([]byte, msgLength)
	_, err = io.ReadFull(r, msg.Message)
	if err != nil {
		return err
	}
	var ackLength uint64
	if ackLength, err = bmutil.ReadVarInt(r); err != nil {
		return err
	}
	if ackLength > wire.MaxPayloadOfMsgObject {
		str := fmt.Sprintf("ack length exceeds max length - "+
			"indicates %d, but max length is %d",
			msgLength, wire.MaxPayloadOfMsgObject)
		return wire.NewMessageError("DecodeFromDecrypted", str)
	}
	msg.Ack = make([]byte, ackLength)
	_, err = io.ReadFull(r, msg.Ack)
	if err != nil {
		return err
	}
	var sigLength uint64
	if sigLength, err = bmutil.ReadVarInt(r); err != nil {
		return err
	}
	if sigLength > signatureMaxLength {
		str := fmt.Sprintf("signature length exceeds max length - "+
			"indicates %d, but max length is %d",
			sigLength, signatureMaxLength)
		return wire.NewMessageError("DecodeFromDecrypted", str)
	}
	msg.Signature = make([]byte, sigLength)
	_, err = io.ReadFull(r, msg.Signature)
	return err
}

// Header returns the object header.
func (msg *Message) Header() *wire.ObjectHeader {
	return &msg.ObjectHeader
}

// Payload return the object payload of the message.
func (msg *Message) Payload() []byte {
	return msg.Encrypted
}

// MsgObject transforms the PubKeyObject to a *MsgObject.
func (msg *Message) MsgObject() *wire.MsgObject {
	return wire.NewMsgObject(msg.ObjectHeader.Nonce,
		msg.ObjectHeader.ExpiresTime, msg.ObjectHeader.ObjectType,
		msg.ObjectHeader.Version, msg.ObjectHeader.StreamNumber, msg.Payload())
}

func (msg *Message) InventoryHash() *wire.ShaHash {
	return msg.MsgObject().InventoryHash()
}

// NewMessage returns a new object message that conforms to the Message interface
// using the passed parameters and defaults for the remaining fields.
func NewMessage(nonce uint64, expires time.Time, version, streamNumber uint64,
	encrypted []byte, addressVersion, fromStreamNumber uint64, behavior uint32,
	signingKey, encryptKey *wire.PubKey, nonceTrials, extraBytes uint64,
	destination *wire.RipeHash, encoding uint64, message, ack, signature []byte) *Message {
	return &Message{
		ObjectHeader: wire.ObjectHeader{
			Nonce:        nonce,
			ExpiresTime:  expires,
			ObjectType:   wire.ObjectTypeMsg,
			Version:      version,
			StreamNumber: streamNumber,
		},
		Encrypted:          encrypted,
		FromAddressVersion: addressVersion,
		FromStreamNumber:   fromStreamNumber,
		Behavior:           behavior,
		SigningKey:         signingKey,
		EncryptionKey:      encryptKey,
		NonceTrials:        nonceTrials,
		ExtraBytes:         extraBytes,
		Destination:        destination,
		Encoding:           encoding,
		Message:            message,
		Ack:                ack,
		Signature:          signature,
	}
}

// DecodeMessage takes a byte array and turns it into an object message.
func DecodeMessage(obj []byte) (*Message, error) {
	// Make sure that object type specific checks happen first.
	var msg *Message
	err := msg.Decode(bytes.NewReader(obj))
	if err != nil {
		return nil, err
	}

	return msg, nil
}
