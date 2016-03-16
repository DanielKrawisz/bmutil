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

// MsgPubKey implements the Message interface and represents a pubkey sent in
// response to MsgGetPubKey.
type MsgPubKey struct {
	Nonce         uint64
	ExpiresTime   time.Time
	ObjectType    ObjectType
	Version       uint64
	StreamNumber  uint64
	Behavior      uint32
	SigningKey    *PubKey
	EncryptionKey *PubKey
	NonceTrials   uint64
	ExtraBytes    uint64
	Signature     []byte
	Tag           *ShaHash
	Encrypted     []byte
}

// Decode decodes r using the bitmessage protocol encoding into the receiver.
// This is part of the Message interface implementation.
func (msg *MsgPubKey) Decode(r io.Reader) error {
	var err error
	msg.Nonce, msg.ExpiresTime, msg.ObjectType, msg.Version,
		msg.StreamNumber, err = DecodeMsgObjectHeader(r)
	if err != nil {
		return err
	}

	if msg.ObjectType != ObjectTypePubKey {
		str := fmt.Sprintf("Object Type should be %d, but is %d",
			ObjectTypePubKey, msg.ObjectType)
		return messageError("Decode", str)
	}

	switch msg.Version {
	case SimplePubKeyVersion:
		msg.SigningKey = &PubKey{}
		msg.EncryptionKey = &PubKey{}
		return readElements(r, &msg.Behavior, msg.SigningKey, msg.EncryptionKey)
	case ExtendedPubKeyVersion:
		msg.SigningKey = &PubKey{}
		msg.EncryptionKey = &PubKey{}
		var sigLength uint64
		err = readElements(r, &msg.Behavior, msg.SigningKey, msg.EncryptionKey)
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
			return messageError("Decode", str)
		}
		msg.Signature = make([]byte, sigLength)
		_, err = io.ReadFull(r, msg.Signature)
		return err
	case EncryptedPubKeyVersion:
		msg.Tag = &ShaHash{}
		if err = readElement(r, msg.Tag); err != nil {
			return err
		}
		// The rest is the encrypted data, accessible only to those that know
		// the address that the pubkey belongs to.
		msg.Encrypted, err = ioutil.ReadAll(r)
		return err
	default:
		return messageError("MsgPubKey.Decode", "unsupported PubKey version")
	}
}

// Encode encodes the receiver to w using the bitmessage protocol encoding.
// This is part of the Message interface implementation.
func (msg *MsgPubKey) Encode(w io.Writer) error {
	err := EncodeMsgObjectHeader(w, msg.Nonce, msg.ExpiresTime, msg.ObjectType,
		msg.Version, msg.StreamNumber)
	if err != nil {
		return err
	}

	switch msg.Version {
	case SimplePubKeyVersion:
		return writeElements(w, msg.Behavior, msg.SigningKey, msg.EncryptionKey)
	case ExtendedPubKeyVersion:
		err = writeElements(w, msg.Behavior, msg.SigningKey, msg.EncryptionKey)
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
		if err = writeElement(w, msg.Tag); err != nil {
			return err
		}
		// The rest is the encrypted data, accessible only to the holder
		// of the private key to whom it's addressed.
		_, err = w.Write(msg.Encrypted)
		return err
	default:
		return messageError("MsgPubKey.Encode", "unsupported PubKey version")
	}
}

// Command returns the protocol command string for the message. This is part
// of the Message interface implementation.
func (msg *MsgPubKey) Command() string {
	return CmdObject
}

// MaxPayloadLength returns the maximum length the payload can be for the
// receiver. This is part of the Message interface implementation.
func (msg *MsgPubKey) MaxPayloadLength() int {
	// TODO find a sensible value based on pubkey version
	return MaxPayloadOfMsgObject
}

func (msg *MsgPubKey) String() string {
	return fmt.Sprintf("pubkey: v%d %d %s %d %x", msg.Version, msg.Nonce, msg.ExpiresTime, msg.StreamNumber, msg.Tag)
}

// EncodeForSigning encodes MsgPubKey so that it can be hashed and signed.
func (msg *MsgPubKey) EncodeForSigning(w io.Writer) error {
	err := EncodeMsgObjectSignatureHeader(w, msg.ExpiresTime, msg.ObjectType,
		msg.Version, msg.StreamNumber)
	if err != nil {
		return err
	}
	if msg.Version == EncryptedPubKeyVersion {
		err = writeElement(w, msg.Tag)
		if err != nil {
			return err
		}
	}
	err = writeElements(w, msg.Behavior, msg.SigningKey, msg.EncryptionKey)
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

// EncodeForEncryption encodes MsgPubKey so that it can be encrypted.
func (msg *MsgPubKey) EncodeForEncryption(w io.Writer) error {
	err := writeElements(w, msg.Behavior, msg.SigningKey, msg.EncryptionKey)
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

// DecodeFromDecrypted decodes MsgPubKey from its decrypted form.
func (msg *MsgPubKey) DecodeFromDecrypted(r io.Reader) error {
	msg.SigningKey = &PubKey{}
	msg.EncryptionKey = &PubKey{}
	err := readElements(r, &msg.Behavior, msg.SigningKey, msg.EncryptionKey)
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
		return messageError("DecodeFromDecrypted", str)
	}
	msg.Signature = make([]byte, sigLength)
	_, err = io.ReadFull(r, msg.Signature)
	return err
}

// NewMsgPubKey returns a new object message that conforms to the Message
// interface using the passed parameters and defaults for the remaining fields.
func NewMsgPubKey(nonce uint64, expires time.Time,
	version, streamNumber uint64, behavior uint32,
	signingKey, encryptKey *PubKey, nonceTrials, extraBytes uint64,
	signature []byte, tag *ShaHash, encrypted []byte) *MsgPubKey {
	return &MsgPubKey{
		Nonce:         nonce,
		ExpiresTime:   expires,
		ObjectType:    ObjectTypePubKey,
		Version:       version,
		StreamNumber:  streamNumber,
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
