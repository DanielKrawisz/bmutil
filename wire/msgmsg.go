// Copyright (c) 2015 Monetas
// Copyright 2016 Daniel Krawisz.
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package wire

import (
	"fmt"
	"io"
	"io/ioutil"
	"time"
	"bytes"

	"github.com/DanielKrawisz/bmutil"
)

// MsgMsg implements the Message interface and represents a message sent between
// two addresses. It can be decrypted only by those that have the private
// encryption key that corresponds to the destination address.
type MsgMsg struct {
	Nonce              uint64
	ExpiresTime        time.Time
	ObjectType         ObjectType
	Version            uint64
	StreamNumber       uint64
	Encrypted          []byte
	FromAddressVersion uint64
	FromStreamNumber   uint64
	Behavior           uint32
	SigningKey         *PubKey
	EncryptionKey      *PubKey
	NonceTrials        uint64
	ExtraBytes         uint64
	Destination        *RipeHash
	Encoding           uint64
	Message            []byte
	Ack                []byte
	Signature          []byte
}

// Decode decodes r using the bitmessage protocol encoding into the receiver.
// This is part of the Message interface implementation.
func (msg *MsgMsg) Decode(r io.Reader) error {
	var err error
	msg.Nonce, msg.ExpiresTime, msg.ObjectType, msg.Version,
		msg.StreamNumber, err = DecodeMsgObjectHeader(r)
	if err != nil {
		return err
	}

	if msg.ObjectType != ObjectTypeMsg {
		str := fmt.Sprintf("Object Type should be %d, but is %d",
			ObjectTypeMsg, msg.ObjectType)
		return messageError("Decode", str)
	}

	msg.Encrypted, err = ioutil.ReadAll(r)

	return err
}

// Encode encodes the receiver to w using the bitmessage protocol encoding.
// This is part of the Message interface implementation.
func (msg *MsgMsg) Encode(w io.Writer) error {
	err := EncodeMsgObjectHeader(w, msg.Nonce, msg.ExpiresTime, msg.ObjectType,
		msg.Version, msg.StreamNumber)
	if err != nil {
		return err
	}

	_, err = w.Write(msg.Encrypted)
	return err
}

// Command returns the protocol command string for the message. This is part
// of the Message interface implementation.
func (msg *MsgMsg) Command() string {
	return CmdObject
}

// MaxPayloadLength returns the maximum length the payload can be for the
// receiver. This is part of the Message interface implementation.
func (msg *MsgMsg) MaxPayloadLength() int {
	return MaxPayloadOfMsgObject
}

func (msg *MsgMsg) String() string {
	return fmt.Sprintf("msg: v%d %d %s %d %x", msg.Version, msg.Nonce, msg.ExpiresTime, msg.StreamNumber, msg.Encrypted)
}

// EncodeForSigning encodes MsgMsg so that it can be hashed and signed.
func (msg *MsgMsg) EncodeForSigning(w io.Writer) error {
	err := EncodeMsgObjectSignatureHeader(w, msg.ExpiresTime, msg.ObjectType,
		msg.Version, msg.StreamNumber)
	if err != nil {
		return err
	}
	if err = bmutil.WriteVarInt(w, msg.FromAddressVersion); err != nil {
		return err
	}
	if err = bmutil.WriteVarInt(w, msg.FromStreamNumber); err != nil {
		return err
	}
	err = writeElements(w, msg.Behavior, msg.SigningKey, msg.EncryptionKey)
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
	err = writeElement(w, msg.Destination)
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

// EncodeForEncryption encodes MsgMsg so that it can be encrypted.
func (msg *MsgMsg) EncodeForEncryption(w io.Writer) error {
	if err := bmutil.WriteVarInt(w, msg.FromAddressVersion); err != nil {
		return err
	}
	if err := bmutil.WriteVarInt(w, msg.FromStreamNumber); err != nil {
		return err
	}
	err := writeElements(w, msg.Behavior, msg.SigningKey, msg.EncryptionKey)
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
	if err = writeElement(w, msg.Destination); err != nil {
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

// DecodeFromDecrypted decodes MsgMsg from its decrypted form.
func (msg *MsgMsg) DecodeFromDecrypted(r io.Reader) error {
	var err error
	if msg.FromAddressVersion, err = bmutil.ReadVarInt(r); err != nil {
		return err
	}
	if msg.FromStreamNumber, err = bmutil.ReadVarInt(r); err != nil {
		return err
	}
	msg.SigningKey = &PubKey{}
	msg.EncryptionKey = &PubKey{}
	err = readElements(r, &msg.Behavior, msg.SigningKey, msg.EncryptionKey)
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
	msg.Destination = &RipeHash{}
	if err = readElement(r, msg.Destination); err != nil {
		return err
	}
	if msg.Encoding, err = bmutil.ReadVarInt(r); err != nil {
		return err
	}
	var msgLength uint64
	if msgLength, err = bmutil.ReadVarInt(r); err != nil {
		return err
	}
	if msgLength > MaxPayloadOfMsgObject {
		str := fmt.Sprintf("message length exceeds max length - "+
			"indicates %d, but max length is %d",
			msgLength, MaxPayloadOfMsgObject)
		return messageError("DecodeFromDecrypted", str)
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
	if ackLength > MaxPayloadOfMsgObject {
		str := fmt.Sprintf("ack length exceeds max length - "+
			"indicates %d, but max length is %d",
			msgLength, MaxPayloadOfMsgObject)
		return messageError("DecodeFromDecrypted", str)
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
		return messageError("DecodeFromDecrypted", str)
	}
	msg.Signature = make([]byte, sigLength)
	_, err = io.ReadFull(r, msg.Signature)
	return err
}

// NewMsgMsg returns a new object message that conforms to the Message interface
// using the passed parameters and defaults for the remaining fields.
func NewMsgMsg(nonce uint64, expires time.Time, version, streamNumber uint64, encrypted []byte, addressVersion, fromStreamNumber uint64, behavior uint32, signingKey, encryptKey *PubKey, nonceTrials, extraBytes uint64, destination *RipeHash, encoding uint64, message, ack, signature []byte) *MsgMsg {
	return &MsgMsg{
		Nonce:              nonce,
		ExpiresTime:        expires,
		ObjectType:         ObjectTypeMsg,
		Version:            version,
		StreamNumber:       streamNumber,
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

// DecodeMsgMsg takes a byte array and turns it into an object message.
func DecodeMsgMsg(obj []byte) (*MsgMsg, error) {
	// Make sure that object type specific checks happen first.
	var msg *MsgMsg
	err := msg.Decode(bytes.NewReader(obj))
	if err != nil {
		return nil, err
	}
	
	return msg, nil
}
