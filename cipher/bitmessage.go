// Copyright 2016 Daniel Krawisz.
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package cipher

import (
	"io"

	. "github.com/DanielKrawisz/bmutil"
	"github.com/DanielKrawisz/bmutil/format"
	"github.com/DanielKrawisz/bmutil/hash"
	"github.com/DanielKrawisz/bmutil/identity"
	"github.com/DanielKrawisz/bmutil/wire"
	"github.com/DanielKrawisz/bmutil/wire/obj"
)

// Bitmessage is a representation of the data included in a bitmessage.
// It could be part of a message object or a broadcast object.
type Bitmessage struct {
	Version     uint64
	Stream      uint64
	Data        *obj.PubKeyData
	Destination *hash.Ripe
	Content     format.Encoding
}

// ToPublicKey constructs the PublicKey object from this Bitmessage.
func (b *Bitmessage) ToPublicKey() (*identity.PublicKey, error) {
	// Check if embedded keys correspond to the address used to decrypt.
	vk, err := b.Data.Verification.ToBtcec()
	if err != nil {
		return nil, err
	}
	ek, err := b.Data.Encryption.ToBtcec()
	if err != nil {
		return nil, err
	}

	return &identity.PublicKey{
		Verification: vk,
		Encryption:   ek,
	}, nil
}

// ToPublicID constructs the PublicID of this Bitmessage.
func (b *Bitmessage) ToPublicID() (*identity.PublicID, error) {
	pub, err := b.ToPublicKey()
	if err != nil {
		return nil, err
	}
	return identity.NewPublicID(pub, b.Version, b.Stream, b.Data.Behavior, b.Data.Pow)
}

// From construct the from address of this bitmessage.
func (b *Bitmessage) From() (Address, error) {
	pub, err := b.ToPublicID()
	if err != nil {
		return nil, err
	}
	return pub.Address(), nil
}

// encodeMessage encodes a Bitmessage so that it can be encrypted.
func (b *Bitmessage) encodeMessage(w io.Writer) error {
	var err error
	if err = WriteVarInt(w, b.Version); err != nil {
		return err
	}
	if err = WriteVarInt(w, b.Stream); err != nil {
		return err
	}
	if b.Version >= 3 {
		err = b.Data.Encode(w)
	} else {
		err = b.Data.EncodeSimple(w)
	}
	if err != nil {
		return err
	}
	if err = wire.WriteElement(w, b.Destination); err != nil {
		return err
	}
	return format.Encode(w, b.Content)
}

// encodeBroadcast encodes a Bitmessage so that it can be encrypted.
func (b *Bitmessage) encodeBroadcast(w io.Writer) error {
	var err error
	if err := WriteVarInt(w, b.Version); err != nil {
		return err
	}
	if err := WriteVarInt(w, b.Stream); err != nil {
		return err
	}
	if b.Version >= 3 {
		err = b.Data.Encode(w)
	} else {
		err = b.Data.EncodeSimple(w)
	}
	if err != nil {
		return err
	}
	return format.Encode(w, b.Content)
}

// decodeMessage decodes a Bitmessage from its decrypted form.
func (b *Bitmessage) decodeMessage(r io.Reader) error {
	var err error
	if b.Version, err = ReadVarInt(r); err != nil {
		return err
	}
	if b.Stream, err = ReadVarInt(r); err != nil {
		return err
	}
	b.Data = &obj.PubKeyData{}
	if b.Version >= 3 {
		err = b.Data.Decode(r)
	} else {
		err = b.Data.DecodeSimple(r)
	}
	if err != nil {
		return err
	}
	b.Destination = &hash.Ripe{}
	if err = wire.ReadElement(r, b.Destination); err != nil {
		return err
	}

	if b.Content, err = format.Decode(r); err != nil {
		return err
	}

	return nil
}

// decodeBroadcast decodes a Bitmessage from its decrypted form.
func (b *Bitmessage) decodeBroadcast(r io.Reader) error {
	var err error
	if b.Version, err = ReadVarInt(r); err != nil {
		return err
	}
	if b.Stream, err = ReadVarInt(r); err != nil {
		return err
	}
	b.Data = &obj.PubKeyData{}
	if b.Version >= 3 {
		err = b.Data.Decode(r)
	} else {
		err = b.Data.DecodeSimple(r)
	}
	if err != nil {
		return err
	}

	if b.Content, err = format.Decode(r); err != nil {
		return err
	}
	return nil
}
