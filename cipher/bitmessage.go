// Copyright 2016 Daniel Krawisz.
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package cipher

import (
	"fmt"
	"io"

	"github.com/DanielKrawisz/bmutil"
	"github.com/DanielKrawisz/bmutil/pow"
	"github.com/DanielKrawisz/bmutil/wire"
)

// Bitmessage is a representation of the data included in a bitmessage.
// It could be part of a message object or a broadcast object.
type Bitmessage struct {
	FromAddressVersion uint64
	FromStreamNumber   uint64
	Behavior           uint32
	SigningKey         *wire.PubKey
	EncryptionKey      *wire.PubKey
	Pow                *pow.Data
	Destination        *wire.RipeHash
	Encoding           uint64
	Message            []byte
}

// encodeMessage encodes a Bitmessage so that it can be encrypted.
func (msg *Bitmessage) encodeMessage(w io.Writer) error {
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
		if err = msg.Pow.Encode(w); err != nil {
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
	return nil
}

// encodeBroadcast encodes a Bitmessage so that it can be encrypted.
func (msg *Bitmessage) encodeBroadcast(w io.Writer) error {
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
		if err = msg.Pow.Encode(w); err != nil {
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

// decodeMessage decodes a Bitmessage from its decrypted form.
func (msg *Bitmessage) decodeMessage(r io.Reader) error {
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
		msg.Pow = &pow.Data{}
		if err = msg.Pow.Decode(r); err != nil {
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
	return nil
}

// decodeBroadcast decodes a Bitmessage from its decrypted form.
func (msg *Bitmessage) decodeBroadcast(r io.Reader) error {
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
		msg.Pow = &pow.Data{}
		if err = msg.Pow.Decode(r); err != nil {
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
	return nil
}
