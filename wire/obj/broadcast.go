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

const (
	// TaglessBroadcastVersion is the broadcast version which does not contain
	// a tag.
	TaglessBroadcastVersion = 4

	// TagBroadcastVersion is the broadcast version from which tags for light
	// clients started being added at the beginning of the broadcast message.
	TagBroadcastVersion = 5
)

// Broadcast implements the Object interface and represents a broadcast
// message that can be decrypted by all the clients that know the address of the
// sender.
type Broadcast struct {
	header             *wire.ObjectHeader
	Tag                *wire.ShaHash
	Encrypted          []byte
	FromAddressVersion uint64
	FromStreamNumber   uint64
	Behavior           uint32
	SigningKey         *wire.PubKey
	EncryptionKey      *wire.PubKey
	NonceTrials        uint64
	ExtraBytes         uint64
	Encoding           uint64
	Message            []byte
	Signature          []byte
}

// Decode decodes r using the bitmessage protocol encoding into the receiver.
// This is part of the Message interface implementation.
func (msg *Broadcast) Decode(r io.Reader) error {
	var err error
	msg.header, err = wire.DecodeMsgObjectHeader(r)
	if err != nil {
		return err
	}

	if msg.header.ObjectType != wire.ObjectTypeBroadcast {
		str := fmt.Sprintf("Object Type should be %d, but is %d",
			wire.ObjectTypeBroadcast, msg.header.ObjectType)
		return wire.NewMessageError("Decode", str)
	}

	if msg.header.Version == TagBroadcastVersion {
		msg.Tag = &wire.ShaHash{}
		if err = wire.ReadElements(r, msg.Tag); err != nil {
			return err
		}
	}

	msg.Encrypted, err = ioutil.ReadAll(r)

	return err
}

func (msg *Broadcast) encodePayload(w io.Writer) (err error) {
	if msg.header.Version == TagBroadcastVersion {
		if err = wire.WriteElement(w, msg.Tag); err != nil {
			return err
		}
	}

	_, err = w.Write(msg.Encrypted)
	return err
}

// Encode encodes the receiver to w using the bitmessage protocol encoding.
// This is part of the Message interface implementation.
func (msg *Broadcast) Encode(w io.Writer) error {
	err := msg.header.Encode(w)
	if err != nil {
		return err
	}

	return msg.encodePayload(w)
}

// MaxPayloadLength returns the maximum length the payload can be for the
// receiver. This is part of the Message interface implementation.
func (msg *Broadcast) MaxPayloadLength() int {
	return wire.MaxPayloadOfMsgObject
}

func (msg *Broadcast) String() string {
	return fmt.Sprintf("broadcast: v%d %d %s %d %x %x",
		msg.header.Version, msg.header.Nonce, msg.header.ExpiresTime,
		msg.header.StreamNumber, msg.Tag, msg.Encrypted)
}

// EncodeForSigning encodes Broadcast so that it can be hashed and signed.
func (msg *Broadcast) EncodeForSigning(w io.Writer) error {
	err := msg.header.EncodeForSigning(w)
	if err != nil {
		return err
	}
	if msg.header.Version == TagBroadcastVersion {
		err = wire.WriteElement(w, msg.Tag)
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

// EncodeForEncryption encodes Broadcast so that it can be encrypted.
func (msg *Broadcast) EncodeForEncryption(w io.Writer) error {
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

// DecodeFromDecrypted decodes Broadcast from its decrypted form.
func (msg *Broadcast) DecodeFromDecrypted(r io.Reader) error {
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
func (msg *Broadcast) Header() *wire.ObjectHeader {
	return msg.header
}

// Payload return the object payload of the message.
func (msg *Broadcast) Payload() []byte {
	w := &bytes.Buffer{}
	msg.encodePayload(w)
	return w.Bytes()
}

// MsgObject transforms the PubKeyObject to a *MsgObject.
func (msg *Broadcast) MsgObject() *wire.MsgObject {
	return wire.NewMsgObject(msg.header, msg.Payload())
}

// InventoryHash returns the inv hash of the message.
func (msg *Broadcast) InventoryHash() *wire.ShaHash {
	return msg.MsgObject().InventoryHash()
}

// NewBroadcast returns a new object message that conforms to the
// Object interface using the passed parameters and defaults for the remaining
// fields.
func NewBroadcast(nonce uint64, expires time.Time, version, streamNumber uint64,
	tag *wire.ShaHash, encrypted []byte, fromAddressVersion, fromStreamNumber uint64,
	behavior uint32, signingKey, encryptKey *wire.PubKey, nonceTrials, extraBytes,
	encoding uint64, message, signature []byte) *Broadcast {
	return &Broadcast{
		header: &wire.ObjectHeader{
			Nonce:        nonce,
			ExpiresTime:  expires,
			ObjectType:   wire.ObjectTypeBroadcast,
			Version:      version,
			StreamNumber: streamNumber,
		},
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
