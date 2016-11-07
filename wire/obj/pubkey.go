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
	// Signature consists of 2 256-bit integers encoding using ASN.1
	// 2*256/8 + 16 (safe encoding boundary). TODO find precise number. Probably
	// 72.
	signatureMaxLength = 80
)

// PubKey implements the Message interface and represents a pubkey sent in
// response to MsgGetPubKey.
type PubKey struct {
	wire.ObjectHeader
	Behavior      uint32
	SigningKey    *wire.PubKey
	EncryptionKey *wire.PubKey
	NonceTrials   uint64
	ExtraBytes    uint64
	Signature     []byte
	Tag           *wire.ShaHash
	Encrypted     []byte
}

// Decode decodes r using the bitmessage protocol encoding into the receiver.
// This is part of the Message interface implementation.
func (msg *PubKey) Decode(r io.Reader) error {
	var err error
	msg.ObjectHeader, err = wire.DecodeMsgObjectHeader(r)
	if err != nil {
		return err
	}

	if msg.ObjectType != wire.ObjectTypePubKey {
		str := fmt.Sprintf("Object Type should be %d, but is %d",
			wire.ObjectTypePubKey, msg.ObjectType)
		return wire.NewMessageError("Decode", str)
	}

	switch msg.Version {
	case SimplePubKeyVersion:
		msg.SigningKey = &wire.PubKey{}
		msg.EncryptionKey = &wire.PubKey{}
		return wire.ReadElements(r, &msg.Behavior, msg.SigningKey, msg.EncryptionKey)
	case ExtendedPubKeyVersion:
		msg.SigningKey = &wire.PubKey{}
		msg.EncryptionKey = &wire.PubKey{}
		var sigLength uint64
		err = wire.ReadElements(r, &msg.Behavior, msg.SigningKey, msg.EncryptionKey)
		if err != nil {
			return err
		}
		if msg.NonceTrials, err = bmutil.ReadVarInt(r); err != nil {
			return err
		}
		if msg.ExtraBytes, err = bmutil.ReadVarInt(r); err != nil {
			return err
		}
		if sigLength, err = bmutil.ReadVarInt(r); err != nil {
			return err
		}
		if sigLength > signatureMaxLength {
			str := fmt.Sprintf("signature length exceeds max length - "+
				"indicates %d, but max length is %d",
				sigLength, signatureMaxLength)
			return wire.NewMessageError("Decode", str)
		}
		msg.Signature = make([]byte, sigLength)
		_, err = io.ReadFull(r, msg.Signature)
		return err
	case EncryptedPubKeyVersion:
		msg.Tag = &wire.ShaHash{}
		if err = wire.ReadElement(r, msg.Tag); err != nil {
			return err
		}
		// The rest is the encrypted data, accessible only to those that know
		// the address that the pubkey belongs to.
		msg.Encrypted, err = ioutil.ReadAll(r)
		return err
	default:
		return wire.NewMessageError("PubKey.Decode", "unsupported PubKey version")
	}
}

func (msg *PubKey) encodePayload(w io.Writer) error {
	switch msg.Version {
	case SimplePubKeyVersion:
		return wire.WriteElements(w, msg.Behavior, msg.SigningKey, msg.EncryptionKey)
	case ExtendedPubKeyVersion:
		err := wire.WriteElements(w, msg.Behavior, msg.SigningKey, msg.EncryptionKey)
		if err != nil {
			return err
		}
		if err = bmutil.WriteVarInt(w, msg.NonceTrials); err != nil {
			return err
		}
		if err = bmutil.WriteVarInt(w, msg.ExtraBytes); err != nil {
			return err
		}
		sigLength := uint64(len(msg.Signature))
		if err = bmutil.WriteVarInt(w, sigLength); err != nil {
			return err
		}
		_, err = w.Write(msg.Signature)
		return err
	case EncryptedPubKeyVersion:
		if err := wire.WriteElement(w, msg.Tag); err != nil {
			return err
		}
		// The rest is the encrypted data, accessible only to the holder
		// of the private key to whom it's addressed.
		_, err := w.Write(msg.Encrypted)
		return err
	default:
		return wire.NewMessageError("PubKey.Encode", "unsupported PubKey version")
	}
}

// Encode encodes the receiver to w using the bitmessage protocol encoding.
// This is part of the Message interface implementation.
func (msg *PubKey) Encode(w io.Writer) error {
	err := msg.ObjectHeader.Encode(w)
	if err != nil {
		return err
	}

	return msg.encodePayload(w)
}

// MaxPayloadLength returns the maximum length the payload can be for the
// receiver. This is part of the Message interface implementation.
func (msg *PubKey) MaxPayloadLength() int {
	// TODO find a sensible value based on pubkey version
	return wire.MaxPayloadOfMsgObject
}

func (msg *PubKey) String() string {
	return fmt.Sprintf("pubkey: v%d %d %s %d %x", msg.Version, msg.Nonce, msg.ExpiresTime, msg.StreamNumber, msg.Tag)
}

// EncodeForSigning encodes PubKey so that it can be hashed and signed.
func (msg *PubKey) EncodeForSigning(w io.Writer) error {
	err := msg.ObjectHeader.EncodeForSigning(w)
	if err != nil {
		return err
	}
	if msg.Version == EncryptedPubKeyVersion {
		err = wire.WriteElement(w, msg.Tag)
		if err != nil {
			return err
		}
	}
	err = wire.WriteElements(w, msg.Behavior, msg.SigningKey, msg.EncryptionKey)
	if err != nil {
		return err
	}
	if err = bmutil.WriteVarInt(w, msg.NonceTrials); err != nil {
		return err
	}
	if err = bmutil.WriteVarInt(w, msg.ExtraBytes); err != nil {
		return err
	}

	return nil
}

// EncodeForEncryption encodes PubKey so that it can be encrypted.
func (msg *PubKey) EncodeForEncryption(w io.Writer) error {
	err := wire.WriteElements(w, msg.Behavior, msg.SigningKey, msg.EncryptionKey)
	if err != nil {
		return err
	}
	if err = bmutil.WriteVarInt(w, msg.NonceTrials); err != nil {
		return err
	}
	if err = bmutil.WriteVarInt(w, msg.ExtraBytes); err != nil {
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

// DecodeFromDecrypted decodes PubKey from its decrypted form.
func (msg *PubKey) DecodeFromDecrypted(r io.Reader) error {
	msg.SigningKey = &wire.PubKey{}
	msg.EncryptionKey = &wire.PubKey{}
	err := wire.ReadElements(r, &msg.Behavior, msg.SigningKey, msg.EncryptionKey)
	if err != nil {
		return err
	}
	if msg.NonceTrials, err = bmutil.ReadVarInt(r); err != nil {
		return err
	}
	if msg.ExtraBytes, err = bmutil.ReadVarInt(r); err != nil {
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
func (msg *PubKey) Header() *wire.ObjectHeader {
	return &msg.ObjectHeader
}

// ObjectPayload return the object payload of the message.
func (msg *PubKey) Payload() []byte {
	w := &bytes.Buffer{}
	msg.encodePayload(w)
	return w.Bytes()
}

// MsgObject transforms the PubKey to a *MsgObject.
func (msg *PubKey) MsgObject() *wire.MsgObject {
	return wire.NewMsgObject(msg.ObjectHeader.Nonce,
		msg.ObjectHeader.ExpiresTime, msg.ObjectHeader.ObjectType,
		msg.ObjectHeader.Version, msg.ObjectHeader.StreamNumber, msg.Payload())
}

func (msg *PubKey) InventoryHash() *wire.ShaHash {
	return msg.MsgObject().InventoryHash()
}

// NewPubKey returns a new object message that conforms to the Message
// interface using the passed parameters and defaults for the remaining fields.
func NewPubKey(nonce uint64, expires time.Time,
	version, streamNumber uint64, behavior uint32,
	signingKey, encryptKey *wire.PubKey, nonceTrials, extraBytes uint64,
	signature []byte, tag *wire.ShaHash, encrypted []byte) *PubKey {
	return &PubKey{
		ObjectHeader: wire.ObjectHeader{
			Nonce:        nonce,
			ExpiresTime:  expires,
			ObjectType:   wire.ObjectTypePubKey,
			Version:      version,
			StreamNumber: streamNumber,
		},
		Behavior:      behavior,
		SigningKey:    signingKey,
		EncryptionKey: encryptKey,
		NonceTrials:   nonceTrials,
		ExtraBytes:    extraBytes,
		Signature:     signature,
		Tag:           tag,
		Encrypted:     encrypted,
	}
}
