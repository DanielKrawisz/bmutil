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

	"github.com/DanielKrawisz/bmutil"
)

const (
	// TaglessBroadcastVersion is the broadcast version which does not contain
	// a tag.
	TaglessBroadcastVersion = 4

	// TagBroadcastVersion is the broadcast version from which tags for light
	// clients started being added at the beginning of the broadcast message.
	TagBroadcastVersion = 5
)

// MsgBroadcast implements the Message interface and represents a broadcast
// message that can be decrypted by all the clients that know the address of the
// sender.
type MsgBroadcast struct {
	Nonce              uint64
	ExpiresTime        time.Time
	ObjectType         ObjectType
	Version            uint64
	StreamNumber       uint64
	Tag                *ShaHash
	Encrypted          []byte
	FromAddressVersion uint64
	FromStreamNumber   uint64
	Behavior           uint32
	SigningKey         *PubKey
	EncryptionKey      *PubKey
	NonceTrials        uint64
	ExtraBytes         uint64
	Encoding           uint64
	Message            []byte
	Signature          []byte
}

// Decode decodes r using the bitmessage protocol encoding into the receiver.
// This is part of the Message interface implementation.
func (msg *MsgBroadcast) Decode(r io.Reader) error {
	var err error
	msg.Nonce, msg.ExpiresTime, msg.ObjectType, msg.Version,
		msg.StreamNumber, err = DecodeMsgObjectHeader(r)
	if err != nil {
		return err
	}

	if msg.ObjectType != ObjectTypeBroadcast {
		str := fmt.Sprintf("Object Type should be %d, but is %d",
			ObjectTypeBroadcast, msg.ObjectType)
		return messageError("Decode", str)
	}

	if msg.Version == TagBroadcastVersion {
		msg.Tag = &ShaHash{}
		if err = readElements(r, msg.Tag); err != nil {
			return err
		}
	}

	msg.Encrypted, err = ioutil.ReadAll(r)

	return err
}

// Encode encodes the receiver to w using the bitmessage protocol encoding.
// This is part of the Message interface implementation.
func (msg *MsgBroadcast) Encode(w io.Writer) error {
	err := EncodeMsgObjectHeader(w, msg.Nonce, msg.ExpiresTime, msg.ObjectType,
		msg.Version, msg.StreamNumber)
	if err != nil {
		return err
	}

	if msg.Version == TagBroadcastVersion {
		if err = writeElement(w, msg.Tag); err != nil {
			return err
		}
	}

	_, err = w.Write(msg.Encrypted)
	return err
}

// Command returns the protocol command string for the message. This is part
// of the Message interface implementation.
func (msg *MsgBroadcast) Command() string {
	return CmdObject
}

// MaxPayloadLength returns the maximum length the payload can be for the
// receiver. This is part of the Message interface implementation.
func (msg *MsgBroadcast) MaxPayloadLength() int {
	return MaxPayloadOfMsgObject
}

func (msg *MsgBroadcast) String() string {
	return fmt.Sprintf("broadcast: v%d %d %s %d %x %x", msg.Version, msg.Nonce, msg.ExpiresTime, msg.StreamNumber, msg.Tag, msg.Encrypted)
}

// EncodeForSigning encodes MsgBroadcast so that it can be hashed and signed.
func (msg *MsgBroadcast) EncodeForSigning(w io.Writer) error {
	err := EncodeMsgObjectSignatureHeader(w, msg.ExpiresTime, msg.ObjectType,
		msg.Version, msg.StreamNumber)
	if err != nil {
		return err
	}
	if msg.Version == TagBroadcastVersion {
		err = writeElement(w, msg.Tag)
		if err != nil {
			return err
		}
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
	return nil
}

// EncodeForEncryption encodes MsgBroadcast so that it can be encrypted.
func (msg *MsgBroadcast) EncodeForEncryption(w io.Writer) error {
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
	sigLength := uint64(len(msg.Signature))
	if err = bmutil.WriteVarInt(w, sigLength); err != nil {
		return err
	}
	if _, err = w.Write(msg.Signature); err != nil {
		return err
	}
	return nil
}

// DecodeFromDecrypted decodes MsgBroadcast from its decrypted form.
func (msg *MsgBroadcast) DecodeFromDecrypted(r io.Reader) error {
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

// NewMsgBroadcast returns a new object message that conforms to the
// Message interface using the passed parameters and defaults for the remaining
// fields.
func NewMsgBroadcast(nonce uint64, expires time.Time, version, streamNumber uint64, tag *ShaHash, encrypted []byte, fromAddressVersion, fromStreamNumber uint64, behavior uint32, signingKey, encryptKey *PubKey, nonceTrials, extraBytes, encoding uint64, message, signature []byte) *MsgBroadcast {
	return &MsgBroadcast{
		Nonce:              nonce,
		ExpiresTime:        expires,
		ObjectType:         ObjectTypeBroadcast,
		Version:            version,
		StreamNumber:       streamNumber,
		Tag:                tag,
		Encrypted:          encrypted,
		FromAddressVersion: fromAddressVersion,
		FromStreamNumber:   fromStreamNumber,
		Behavior:           behavior,
		SigningKey:         signingKey,
		EncryptionKey:      encryptKey,
		NonceTrials:        nonceTrials,
		ExtraBytes:         extraBytes,
		Encoding:           encoding,
		Message:            message,
		Signature:          signature,
	}
}
