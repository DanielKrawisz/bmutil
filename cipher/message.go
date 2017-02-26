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

const (
	// AckLength is the length of an ack message.
	AckLength = 26
)

// Message is a representation of a message object that includes
// data which would normally be encrypted.
type Message struct {
	msg *obj.Message
	bm  *Bitmessage
	ack []byte
	sig []byte
}

// Object returns the object form of the message that can be sent over
// the network.
func (msg *Message) Object() *obj.Message {
	return msg.msg
}

// Bitmessage returns the message data.
func (msg *Message) Bitmessage() *Bitmessage {
	return msg.bm
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

	if err = msg.bm.encodeMessage(w); err != nil {
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
	err := msg.bm.encodeMessage(w)
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

	sigLength := uint64(len(msg.sig))
	if err = bmutil.WriteVarInt(w, sigLength); err != nil {
		return err
	}
	if _, err = w.Write(msg.sig); err != nil {
		return err
	}
	return nil
}

// decodeFromDecrypted decodes Message from its decrypted form.
func (msg *Message) decodeFromDecrypted(r io.Reader) error {
	msg.bm = &Bitmessage{}
	err := msg.bm.decodeMessage(r)
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
	msg.sig = make([]byte, sigLength)
	_, err = io.ReadFull(r, msg.sig)
	return err
}

func (msg Message) verify(private *identity.PrivateID) error {
	// Check if embedded destination ripe corresponds to private identity.
	if subtle.ConstantTimeCompare(private.Address().RipeHash()[:],
		msg.bm.Destination.Bytes()) != 1 {
		return fmt.Errorf("Decryption succeeded but ripes don't match. Got %s"+
			" expected %s", msg.bm.Destination,
			hex.EncodeToString(private.Address().RipeHash()[:]))
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
	pvk := msg.bm.Public.Key().Verification.Btcec()

	sig, err := btcec.ParseSignature(msg.sig, btcec.S256())
	if err != nil {
		return ErrInvalidSignature
	}

	if !sig.Verify(hash[:], pvk) { // Try SHA256 first
		if !sig.Verify(sha1hash[:], pvk) { // then SHA1
			return ErrInvalidSignature
		}
	}

	return nil
}

// NewMessage attempts to decrypt the data in a message object and turn it
// into a Message.
func NewMessage(msg *obj.Message, private *identity.PrivateID) (*Message, error) {
	dec, err := btcec.Decrypt(private.PrivateKey().Decryption, msg.Encrypted)

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
