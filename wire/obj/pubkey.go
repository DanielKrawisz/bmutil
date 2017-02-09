// Copyright (c) 2015 Monetas
// Copyright 2016 Daniel Krawisz.
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package obj

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"io"
	"io/ioutil"
	"time"

	"github.com/DanielKrawisz/bmutil"
	"github.com/DanielKrawisz/bmutil/pow"
	"github.com/DanielKrawisz/bmutil/wire"
)

const (
	// SimplePubKeyVersion is the version in which pubkeys are sent unencrypted
	// without any details of PoW required by the sender.
	SimplePubKeyVersion = 2
	
	// ExtendedPubKeyVersion is the version in which pubkeys are sent
	// unencrypted with details of PoW required by the sender.
	ExtendedPubKeyVersion = 3
	
	// EncryptedPubKeyVersion is the version from which pubkeys started to be
	// sent as an encrypted ExtendedPubKey, decryptable by those who had the
	// addresses of the owners of those keys.
	EncryptedPubKeyVersion = 4
	
	// SignatureMaxLength consists of 2 256-bit integers encoding using ASN.1
	// 2*256/8 + 16 (safe encoding boundary). TODO find precise number. Probably
	// 72.
	SignatureMaxLength = 80
)

// PubKeyData contains the information that is transmitted in a PubKey object.
type PubKeyData struct {
	Behavior        uint32
	VerificationKey *wire.PubKey
	EncryptionKey   *wire.PubKey
	Pow             *pow.Data
}

// EncodeSimple encodes the PubKeyData to a writer according to the format
// for a SimplePubKey.
func (pk *PubKeyData) EncodeSimple(w io.Writer) error {
	return wire.WriteElements(w, pk.Behavior, pk.VerificationKey, pk.EncryptionKey)
}

// Encode encodes the PubKeyData to a writer.
func (pk *PubKeyData) Encode(w io.Writer) error {
	if err := pk.EncodeSimple(w); err != nil {
		return err
	}

	if pk.Pow != nil {
		err := pk.Pow.Encode(w)
		if err != nil {
			return err
		}
	}

	return nil
}

// DecodeSimple decodes a PubKeyData according to the simpler, original
// format for PubKey objects.
func (pk *PubKeyData) DecodeSimple(r io.Reader) error {
	pk.VerificationKey = &wire.PubKey{}
	pk.EncryptionKey = &wire.PubKey{}
	return wire.ReadElements(r, &pk.Behavior, pk.VerificationKey, pk.EncryptionKey)
}

// Decode decodes a PubKeyData from a reader.
func (pk *PubKeyData) Decode(r io.Reader) error {
	err := pk.DecodeSimple(r)
	if err != nil {
		return err
	}

	pk.Pow = &pow.Data{}
	return pk.Pow.Decode(r)
}

// String creates a human-readible string of a PubKeyData.
func (pk *PubKeyData) String() string {
	str := fmt.Sprintf("{Behavior: %d, VerificationKey: %s, EncryptionKey: %s",
		pk.Behavior, pk.VerificationKey.String(), pk.EncryptionKey.String())

	if pk.Pow != nil {
		str += ", " + pk.Pow.String()
	}

	return str + "}"
}

// EncodePubKeySignature encodes a PubKey signature.
func EncodePubKeySignature(w io.Writer, signature []byte) (err error) {
	sigLength := uint64(len(signature))
	err = bmutil.WriteVarInt(w, sigLength)
	if err != nil {
		return
	}
	_, err = w.Write(signature)
	return
}

// DecodePubKeySignature decodes a PubKey signature.
func DecodePubKeySignature(r io.Reader) (signature []byte, err error) {
	sigLength, err := bmutil.ReadVarInt(r)
	if err != nil {
		return
	}
	if sigLength > SignatureMaxLength {
		str := fmt.Sprintf("signature length exceeds max length - "+
			"indicates %d, but max length is %d",
			sigLength, SignatureMaxLength)
		err = wire.NewMessageError("Decode", str)
		return
	}
	signature = make([]byte, sigLength)
	_, err = io.ReadFull(r, signature)
	return
}

// SimplePubKey implements the Message and Object interfaces and represents a pubkey sent in
// response to MsgGetPubKey.
type SimplePubKey struct {
	header *wire.ObjectHeader
	Data   *PubKeyData
}

// NewSimplePubKey returns a new object message that conforms to the Message
// interface using the passed parameters and defaults for the remaining fields.
func NewSimplePubKey(nonce pow.Nonce, expiration time.Time,
	streamNumber uint64, behavior uint32,
	signingKey, encryptKey *wire.PubKey) *SimplePubKey {
	return &SimplePubKey{
		header: wire.NewObjectHeader(
			nonce,
			expiration,
			wire.ObjectTypePubKey,
			SimplePubKeyVersion,
			streamNumber,
		),
		Data: &PubKeyData{
			Behavior:        behavior,
			VerificationKey: signingKey,
			EncryptionKey:   encryptKey,
		},
	}
}

func (p *SimplePubKey) decodePayload(r io.Reader) error {
	p.Data = &PubKeyData{}
	return p.Data.DecodeSimple(r)
}

// Decode is part of the Message interface and it reads a new SimplePubKey
// in from r.
func (p *SimplePubKey) Decode(r io.Reader) error {
	var err error
	p.header, err = wire.DecodeObjectHeader(r)
	if err != nil {
		return err
	}

	if p.header.ObjectType != wire.ObjectTypePubKey {
		str := fmt.Sprintf("Object Type should be %d, but is %d",
			wire.ObjectTypePubKey, p.header.ObjectType)
		return wire.NewMessageError("Decode", str)
	}

	if p.header.Version != SimplePubKeyVersion {
		str := fmt.Sprintf("Object version should be %d, but is %d",
			SimplePubKeyVersion, p.header.Version)
		return wire.NewMessageError("Decode", str)
	}

	return p.decodePayload(r)
}

func (p *SimplePubKey) encodePayload(w io.Writer) error {
	return p.Data.EncodeSimple(w)
}

// Encode is part of the Message interface and it writes the SimplePubKey
// as a string of bits to the Writer.
func (p *SimplePubKey) Encode(w io.Writer) error {
	err := p.header.Encode(w)
	if err != nil {
		return err
	}

	return p.encodePayload(w)
}

// Command returns the protocol command string for the message. This is part
// of the Message interface implementation.
func (p *SimplePubKey) Command() string {
	return wire.CmdObject
}

// MaxPayloadLength returns the maximum length the payload can be for the
// receiver. This is part of the Message interface implementation.
func (p *SimplePubKey) MaxPayloadLength() int {
	return wire.MaxPayloadOfMsgObject
}

// Header is part of the Object interface and returns the object header.
func (p *SimplePubKey) Header() *wire.ObjectHeader {
	return p.header
}

// Payload is part of the Object interface and
// returns the object payload of the message.
func (p *SimplePubKey) Payload() []byte {
	w := &bytes.Buffer{}
	p.encodePayload(w)
	return w.Bytes()
}

// MsgObject is part of the Object interface and transforms
// the abstract Object to a *MsgObject.
func (p *SimplePubKey) MsgObject() *wire.MsgObject {
	return wire.NewMsgObject(p.header, p.Payload())
}

// Behavior returns the PubKey's behavior (currently unused).
func (p *SimplePubKey) Behavior() uint32 {
	return p.Data.Behavior
}

// VerificationKey return's the PubKey's VerificationKey
func (p *SimplePubKey) VerificationKey() *wire.PubKey {
	return p.Data.VerificationKey
}

// EncryptionKey return's the PubKey's EncryptionKey
func (p *SimplePubKey) EncryptionKey() *wire.PubKey {
	return p.Data.EncryptionKey
}

// Pow return's the key's pow data. For the SimplePubKey, this is nil.
func (p *SimplePubKey) Pow() *pow.Data {
	return nil
}

// Tag return's the key's pow data. For the SimplePubKey, this is nil.
func (p *SimplePubKey) Tag() *wire.ShaHash {
	return nil
}

// Object is part of the cipher.PubKey interface and returns the PubKey
// as an Object type.
func (p *SimplePubKey) Object() Object {
	return p
}

// String returns a representation of the SimplePubKey as a
// human-readable string.
func (p *SimplePubKey) String() string {
	return "SimplePubKey{" + p.header.String() + ", " + p.Data.String() + "}"
}

// ExtendedPubKey implements the Message and Object interfaces and represents an
// extended pubkey sent in response to MsgGetPubKey. The extended pub key includes
// information about the proof-of-work required to send a message.
type ExtendedPubKey struct {
	header    *wire.ObjectHeader
	Data      *PubKeyData
	Signature []byte
}

func (p *ExtendedPubKey) decodePayload(r io.Reader) error {
	p.Data = &PubKeyData{}
	err := p.Data.Decode(r)
	if err != nil {
		return nil
	}

	p.Signature, err = DecodePubKeySignature(r)
	return err
}

// Decode decodes an ExtendedPubKey from a reader.
func (p *ExtendedPubKey) Decode(r io.Reader) error {
	var err error
	p.header, err = wire.DecodeObjectHeader(r)
	if err != nil {
		return err
	}

	if p.header.ObjectType != wire.ObjectTypePubKey {
		str := fmt.Sprintf("Object Type should be %d, but is %d",
			wire.ObjectTypePubKey, p.header.ObjectType)
		return wire.NewMessageError("Decode", str)
	}

	if p.header.Version != ExtendedPubKeyVersion {
		str := fmt.Sprintf("Object version should be %d, but is %d",
			ExtendedPubKeyVersion, p.header.Version)
		return wire.NewMessageError("Decode", str)
	}

	return p.decodePayload(r)
}

func (p *ExtendedPubKey) encodePayload(w io.Writer) error {
	err := p.Data.Encode(w)
	if err != nil {
		return err
	}

	return EncodePubKeySignature(w, p.Signature)
}

// Encode encodes the receiver to w using the bitmessage protocol encoding.
// This is part of the Message interface implementation.
func (p *ExtendedPubKey) Encode(w io.Writer) error {
	err := p.header.Encode(w)
	if err != nil {
		return err
	}

	return p.encodePayload(w)
}

// EncodeForSigning encodes the data that is signed.
func (p *ExtendedPubKey) EncodeForSigning(w io.Writer) error {
	err := p.header.EncodeForSigning(w)
	if err != nil {
		return err
	}

	return p.Data.Encode(w)
}

// Command returns the protocol command string for the message. This is part
// of the Message interface implementation.
func (p *ExtendedPubKey) Command() string {
	return wire.CmdObject
}

// MaxPayloadLength returns the maximum length the payload can be for the
// receiver. This is part of the Message interface implementation.
func (p *ExtendedPubKey) MaxPayloadLength() int {
	return wire.MaxPayloadOfMsgObject
}

// Header is part of the Object interface and returns the object header.
func (p *ExtendedPubKey) Header() *wire.ObjectHeader {
	return p.header
}

// Payload is part of the Object interface and
// returns the object payload of the message.
func (p *ExtendedPubKey) Payload() []byte {
	w := &bytes.Buffer{}
	p.encodePayload(w)
	return w.Bytes()
}

// MsgObject is part of the Object interface and transforms
// the abstract Object to a *MsgObject.
func (p *ExtendedPubKey) MsgObject() *wire.MsgObject {
	return wire.NewMsgObject(p.header, p.Payload())
}

// Behavior returns the PubKey's behavior (currently unused).
func (p *ExtendedPubKey) Behavior() uint32 {
	return p.Data.Behavior
}

// VerificationKey return's the PubKey's VerificationKey
func (p *ExtendedPubKey) VerificationKey() *wire.PubKey {
	return p.Data.VerificationKey
}

// EncryptionKey return's the PubKey's EncryptionKey
func (p *ExtendedPubKey) EncryptionKey() *wire.PubKey {
	return p.Data.EncryptionKey
}

// Pow return's the key's pow data. For the SimplePubKey, this is nil.
func (p *ExtendedPubKey) Pow() *pow.Data {
	return p.Data.Pow
}

// Tag return's the key's pow data. For the SimplePubKey, this is nil.
func (p *ExtendedPubKey) Tag() *wire.ShaHash {
	return nil
}

// Object is part of the cipher.PubKey interface and returns the PubKey
// as an Object type.
func (p *ExtendedPubKey) Object() Object {
	return p
}

func (p *ExtendedPubKey) String() string {
	return "SimplePubKey{" + p.header.String() + ", " + p.Data.String() + ", " + hex.EncodeToString(p.Signature) + "}"
}

// NewExtendedPubKey returns a new object message that conforms to the Message
// interface using the passed parameters and defaults for the remaining fields.
func NewExtendedPubKey(nonce pow.Nonce, expiration time.Time, streamNumber uint64,
	behavior uint32, signingKey, encryptKey *wire.PubKey, powData *pow.Data,
	signature []byte) *ExtendedPubKey {
	return &ExtendedPubKey{
		header: wire.NewObjectHeader(
			nonce,
			expiration,
			wire.ObjectTypePubKey,
			ExtendedPubKeyVersion,
			streamNumber,
		),
		Data: &PubKeyData{
			Behavior:        behavior,
			VerificationKey: signingKey,
			EncryptionKey:   encryptKey,
			Pow:             powData,
		},
		Signature: signature,
	}
}

// EncryptedPubKey represents an encrypted pubkey.
type EncryptedPubKey struct {
	header    *wire.ObjectHeader
	Tag       *wire.ShaHash
	Encrypted []byte
}

func (p *EncryptedPubKey) decodePayload(r io.Reader) error {
	var err error
	p.Tag = &wire.ShaHash{}
	if err = wire.ReadElement(r, p.Tag); err != nil {
		return err
	}
	// The rest is the encrypted data, accessible only to those that know
	// the address that the pubkey belongs to.
	p.Encrypted, err = ioutil.ReadAll(r)
	return err
}

// Decode decodes an EncryptedPubKey from a reader.
func (p *EncryptedPubKey) Decode(r io.Reader) error {
	var err error
	p.header, err = wire.DecodeObjectHeader(r)
	if err != nil {
		return err
	}

	if p.header.ObjectType != wire.ObjectTypePubKey {
		str := fmt.Sprintf("Object Type should be %d, but is %d",
			wire.ObjectTypePubKey, p.header.ObjectType)
		return wire.NewMessageError("Decode", str)
	}

	if p.header.Version != EncryptedPubKeyVersion {
		str := fmt.Sprintf("Object version should be %d, but is %d",
			EncryptedPubKeyVersion, p.header.Version)
		return wire.NewMessageError("Decode", str)
	}

	return p.decodePayload(r)
}

func (p *EncryptedPubKey) encodePayload(w io.Writer) error {
	if err := wire.WriteElement(w, p.Tag); err != nil {
		return err
	}
	// The rest is the encrypted data, accessible only to the holder
	// of the private key to whom it's addressed.
	_, err := w.Write(p.Encrypted)
	return err
}

// Encode encodes the receiver to w using the bitmessage protocol encoding.
// This is part of the Message interface implementation.
func (p *EncryptedPubKey) Encode(w io.Writer) error {
	err := p.header.Encode(w)
	if err != nil {
		return err
	}

	return p.encodePayload(w)
}

// Command returns the protocol command string for the message. This is part
// of the Message interface implementation.
func (p *EncryptedPubKey) Command() string {
	return wire.CmdObject
}

// MaxPayloadLength returns the maximum length the payload can be for the
// receiver. This is part of the Message interface implementation.
func (p *EncryptedPubKey) MaxPayloadLength() int {
	return wire.MaxPayloadOfMsgObject
}

// Header is part of the Object interface and returns the object header.
func (p *EncryptedPubKey) Header() *wire.ObjectHeader {
	return p.header
}

// Payload is part of the Object interface and
// returns the object payload of the message.
func (p *EncryptedPubKey) Payload() []byte {
	w := &bytes.Buffer{}
	p.encodePayload(w)
	return w.Bytes()
}

// MsgObject is part of the Object interface and transforms
// the abstract Object to a *MsgObject.
func (p *EncryptedPubKey) MsgObject() *wire.MsgObject {
	return wire.NewMsgObject(p.header, p.Payload())
}

func (p *EncryptedPubKey) String() string {
	return "ExtendedPubKey{" + p.header.String() + ", " + p.Tag.String() + ", " + hex.EncodeToString(p.Encrypted) + "}"
}

// NewEncryptedPubKey returns a new object message that conforms to the Message
// interface using the passed parameters and defaults for the remaining fields.
func NewEncryptedPubKey(nonce pow.Nonce, expiration time.Time,
	streamNumber uint64, tag *wire.ShaHash, encrypted []byte) *EncryptedPubKey {
	return &EncryptedPubKey{
		header: wire.NewObjectHeader(
			nonce,
			expiration,
			wire.ObjectTypePubKey,
			EncryptedPubKeyVersion,
			streamNumber,
		),
		Tag:       tag,
		Encrypted: encrypted,
	}
}

// DecodePubKey takes a reader and decodes it as some kind of PubKey object.
func DecodePubKey(r io.Reader) (Object, error) {
	header, err := wire.DecodeObjectHeader(r)
	if err != nil {
		return nil, err
	}

	if header.ObjectType != wire.ObjectTypePubKey {
		str := fmt.Sprintf("Object Type should be %d, but is %d",
			wire.ObjectTypePubKey, header.ObjectType)
		return nil, wire.NewMessageError("Decode", str)
	}

	switch header.Version {
	default:
		return nil, ErrInvalidVersion
	case SimplePubKeyVersion:
		k := &SimplePubKey{header: header}
		return k, k.decodePayload(r)
	case ExtendedPubKeyVersion:
		k := &ExtendedPubKey{header: header}
		return k, k.decodePayload(r)
	case EncryptedPubKeyVersion:
		k := &EncryptedPubKey{header: header}
		return k, k.decodePayload(r)
	}
}

// ReadPubKey takes a byte array and and tries to read it as some kind of pubkey.
func ReadPubKey(obj []byte) (Object, error) {
	r := bytes.NewReader(obj)
	return DecodePubKey(r)
}
