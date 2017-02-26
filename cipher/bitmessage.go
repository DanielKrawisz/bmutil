// Copyright 2016 Daniel Krawisz.
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package cipher

import (
	"fmt"
	"io"

	. "github.com/DanielKrawisz/bmutil"
	"github.com/DanielKrawisz/bmutil/format"
	"github.com/DanielKrawisz/bmutil/hash"
	"github.com/DanielKrawisz/bmutil/identity"
	"github.com/DanielKrawisz/bmutil/pow"
	"github.com/DanielKrawisz/bmutil/wire"
	"github.com/DanielKrawisz/bmutil/wire/obj"
)

// Bitmessage is a representation of the data included in a bitmessage.
// It could be part of a message object or a broadcast object.
type Bitmessage struct {
	Public      identity.Public
	Destination *hash.Ripe
	Content     format.Encoding
}

// encodeMessage encodes a Bitmessage so that it can be encrypted.
func (b *Bitmessage) encodeMessage(w io.Writer) error {
	var err error
	if err = identity.Encode(w, b.Public); err != nil {
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
	if err = identity.Encode(w, b.Public); err != nil {
		return err
	}
	return format.Encode(w, b.Content)
}

// decodeMessage decodes a Bitmessage from its decrypted form.
func (b *Bitmessage) decodeMessage(r io.Reader) error {
	var err error
	b.Public, err = identity.Decode(r)
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
	b.Public, err = identity.Decode(r)
	if err != nil {
		return err
	}

	if b.Content, err = format.Decode(r); err != nil {
		return err
	}
	return nil
}

func (b *Bitmessage) String() string {
	if b.Destination == nil {
		return fmt.Sprintf("Bitmessage{%s, %s}", b.Public.String(), string(b.Content.Message()))
	}

	return fmt.Sprintf("Bitmessage{destination:%s, %s, %s}", b.Destination.String(), b.Public.String(), string(b.Content.Message()))
}

type Data struct {
	Key      identity.PublicKey
	Version  uint64
	Stream   uint64
	Behavior uint32
	Pow      *pow.Data
}

func (d *Data) PubKeyData() *obj.PubKeyData {
	return &obj.PubKeyData{
		Behavior:     d.Behavior,
		Verification: d.Key.Verification.Wire(),
		Encryption:   d.Key.Encryption.Wire(),
		Pow:          d.Pow,
	}
}

// Encode serializes the public identity.
func (d *Data) Encode(w io.Writer) error {
	var err error
	if err = WriteVarInt(w, d.Version); err != nil {
		return err
	}
	if err = WriteVarInt(w, d.Stream); err != nil {
		return err
	}
	return d.PubKeyData().Encode(w)
}

// Decode reads a public identity as a publicID type, which implements Public.
func (d *Data) Decode(r io.Reader) error {
	var err error
	d.Version, err = ReadVarInt(r)
	if err != nil {
		return err
	}

	d.Stream, err = ReadVarInt(r)
	if err != nil {
		return err
	}

	data := &obj.PubKeyData{}
	if d.Version >= 3 {
		err = data.Decode(r)
	} else {
		err = data.DecodeSimple(r)
	}
	if err != nil {
		return err
	}

	return nil
}
