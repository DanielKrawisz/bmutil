// Copyright 2016 Daniel Krawisz.
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package cipher

import (
	"io"

	"github.com/DanielKrawisz/bmutil"
	"github.com/DanielKrawisz/bmutil/format"
	"github.com/DanielKrawisz/bmutil/hash"
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
	Destination        *hash.Ripe
	Content            format.Encoding
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
	return format.Encode(w, msg.Content)
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
	return format.Encode(w, msg.Content)
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
	msg.Destination = &hash.Ripe{}
	if err = wire.ReadElement(r, msg.Destination); err != nil {
		return err
	}

	if msg.Content, err = format.Decode(r); err != nil {
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

	if msg.Content, err = format.Decode(r); err != nil {
		return err
	}
	return nil
}
