// Copyright 2016 Daniel Krawisz.
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package cipher

import (
	"bytes"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"io"

	"github.com/DanielKrawisz/bmutil"
	"github.com/DanielKrawisz/bmutil/identity"
	"github.com/DanielKrawisz/bmutil/wire"
	"github.com/DanielKrawisz/bmutil/wire/obj"
	"github.com/btcsuite/btcd/btcec"
)

// Message is a representation of a message object that includes
// data which would normally be encrypted.
type Message struct {
	msg       *obj.Message
	data      *Bitmessage
	ack       []byte
	signature []byte
}

// Object returns the object form of the message that can be sent over
// the network.
func (msg *Message) Object() *obj.Message {
	return msg.msg
}

// Bitmessage returns the message data.
func (msg *Message) Bitmessage() *Bitmessage {
	return msg.data
}

// Ack returns the acknowledgement message.
func (msg *Message) Ack() []byte {
	return msg.ack
}

// encodeForSigning encodes MessageData so that it can be hashed and signed.
func (msg *Message) encodeForSigning(w io.Writer) error {
	err := msg.msg.Header().EncodeForSigning(w)
	if err != nil {
		return err
	}

	if err = msg.data.encodeMessage(w); err != nil {
		return err
	}

	ackLength := uint64(len(msg.ack))
	if err = bmutil.WriteVarInt(w, ackLength); err != nil {
		return err
	}
	if _, err := w.Write(msg.ack); err != nil {
		return err
	}
	return nil
}

// encodeForEncryption encodes Message so that it can be encrypted.
func (msg *Message) encodeForEncryption(w io.Writer) error {
	err := msg.data.encodeMessage(w)
	if err != nil {
		return err
	}

	ackLength := uint64(len(msg.ack))
	if err = bmutil.WriteVarInt(w, ackLength); err != nil {
		return err
	}
	if _, err := w.Write(msg.ack); err != nil {
		return err
	}

	sigLength := uint64(len(msg.signature))
	if err = bmutil.WriteVarInt(w, sigLength); err != nil {
		return err
	}
	if _, err = w.Write(msg.signature); err != nil {
		return err
	}
	return nil
}

// decodeFromDecrypted decodes Message from its decrypted form.
func (msg *Message) decodeFromDecrypted(r io.Reader) error {
	msg.data = &Bitmessage{}
	err := msg.data.decodeMessage(r)
	if err != nil {
		return err
	}

	var ackLength uint64
	if ackLength, err = bmutil.ReadVarInt(r); err != nil {
		return err
	}
	if ackLength > wire.MaxPayloadOfMsgObject {
		str := fmt.Sprintf("ack length exceeds max length - "+
			"indicates %d, but max length is %d",
			ackLength, wire.MaxPayloadOfMsgObject)
		return wire.NewMessageError("decodeFromDecrypted", str)
	}
	msg.ack = make([]byte, ackLength)
	_, err = io.ReadFull(r, msg.ack)
	if err != nil {
		return err
	}

	var sigLength uint64
	if sigLength, err = bmutil.ReadVarInt(r); err != nil {
		return err
	}
	if sigLength > obj.SignatureMaxLength {
		str := fmt.Sprintf("signature length exceeds max length - "+
			"indicates %d, but max length is %d",
			sigLength, obj.SignatureMaxLength)
		return wire.NewMessageError("decodeFromDecrypted", str)
	}
	msg.signature = make([]byte, sigLength)
	_, err = io.ReadFull(r, msg.signature)
	return err
}

func (msg Message) verify(private *identity.Private) error {
	// Check if embedded destination ripe corresponds to private identity.
	if subtle.ConstantTimeCompare(private.Address.Ripe[:],
		msg.data.Destination.Bytes()) != 1 {
		return fmt.Errorf("Decryption succeeded but ripes don't match. Got %s"+
			" expected %s", msg.data.Destination,
			hex.EncodeToString(private.Address.Ripe[:]))
	}

	// Start signature verification
	var b bytes.Buffer
	err := msg.encodeForSigning(&b)
	if err != nil {
		return err
	}

	// Hash
	hash := sha256.Sum256(b.Bytes())
	sha1hash := sha1.Sum(b.Bytes())

	// Verify
	pubSigningKey, err := msg.data.SigningKey.ToBtcec()
	if err != nil {
		return err
	}

	sig, err := btcec.ParseSignature(msg.signature, btcec.S256())
	if err != nil {
		return ErrInvalidSignature
	}

	if !sig.Verify(hash[:], pubSigningKey) { // Try SHA256 first
		if !sig.Verify(sha1hash[:], pubSigningKey) { // then SHA1
			return ErrInvalidSignature
		}
	}

	return nil
}

// NewMessage attempts to decrypt the data in a message object and turn it
// into a Message.
func NewMessage(msg *obj.Message, private *identity.Private) (*Message, error) {
	dec, err := btcec.Decrypt(private.EncryptionKey, msg.Encrypted)

	if err == btcec.ErrInvalidMAC { // decryption failed due to invalid key
		return nil, ErrInvalidIdentity
	} else if err != nil { // other reasons
		return nil, err
	}

	message := Message{
		msg: msg,
	}
	err = message.decodeFromDecrypted(bytes.NewReader(dec))
	if err != nil {
		return nil, err
	}

	err = message.verify(private)
	if err != nil {
		return nil, err
	}

	return &message, nil
}
