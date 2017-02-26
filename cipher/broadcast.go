// Copyright 2016 Daniel Krawisz.
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package cipher

import (
	"bytes"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/DanielKrawisz/bmutil"
	"github.com/DanielKrawisz/bmutil/hash"
	"github.com/DanielKrawisz/bmutil/identity"
	"github.com/DanielKrawisz/bmutil/wire"
	"github.com/DanielKrawisz/bmutil/wire/obj"
	"github.com/btcsuite/btcd/btcec"
)

type incompleteBroadcast interface {
	Encode(io.Writer) error
	Encrypt(address bmutil.Address, data []byte) (obj.Broadcast, error)
}

type incompleteTaglessBroadcast struct {
	expiration   time.Time
	streamNumber uint64
}

func (i *incompleteTaglessBroadcast) Encode(w io.Writer) error {
	err := wire.NewObjectHeader(
		0, i.expiration,
		wire.ObjectTypeBroadcast,
		obj.TaglessBroadcastVersion,
		i.streamNumber).EncodeForSigning(w)
	if err != nil {
		return err
	}

	return nil
}

func (i *incompleteTaglessBroadcast) Encrypt(address bmutil.Address, data []byte) (obj.Broadcast, error) {
	encrypted, err := btcec.Encrypt(bmutil.V4BroadcastDecryptionKey(address).PubKey(), data)

	if err != nil {
		return nil, err
	}

	return obj.NewTaglessBroadcast(0, i.expiration, i.streamNumber, encrypted), nil
}

type incompleteTaggedBroadcast struct {
	expiration   time.Time
	streamNumber uint64
	tag          *hash.Sha
}

func (i *incompleteTaggedBroadcast) Encode(w io.Writer) error {
	err := wire.NewObjectHeader(
		0, i.expiration,
		wire.ObjectTypeBroadcast,
		obj.TaggedBroadcastVersion,
		i.streamNumber).EncodeForSigning(w)
	if err != nil {
		return err
	}

	err = wire.WriteElement(w, i.tag)
	if err != nil {
		return err
	}

	return nil
}

func (i *incompleteTaggedBroadcast) Encrypt(address bmutil.Address, data []byte) (obj.Broadcast, error) {
	encrypted, err := btcec.Encrypt(bmutil.V5BroadcastDecryptionKey(address).PubKey(), data)

	if err != nil {
		return nil, err
	}

	return obj.NewTaggedBroadcast(0, i.expiration, i.streamNumber, i.tag, encrypted), nil
}

// broadcastEncodeForSigning encodes Broadcast so that it can be hashed and signed.
func broadcastEncodeForSigning(w io.Writer, i incompleteBroadcast, data *Bitmessage) error {
	err := i.Encode(w)
	if err != nil {
		return err
	}

	if err = data.encodeBroadcast(w); err != nil {
		return err
	}

	return nil
}

// Broadcast represents a broadcast that has either been decrypted from the
// network or which we have created.
type Broadcast struct {
	msg obj.Broadcast
	bm  *Bitmessage
	sig []byte
}

// Object returns the object form of the message.
func (broadcast *Broadcast) Object() obj.Broadcast {
	return broadcast.msg
}

// Bitmessage returns the message data.
func (broadcast *Broadcast) Bitmessage() *Bitmessage {
	return broadcast.bm
}

func (broadcast *Broadcast) String() string {
	return fmt.Sprintf("Broadcast{%s, %s, %v}", broadcast.msg.String(), broadcast.bm.String(), broadcast.sig)
}

// encodeForSigning encodes Broadcast so that it can be hashed and signed.
func (broadcast *Broadcast) encodeForSigning(w io.Writer) error {
	if broadcast.msg == nil {
		panic("msg is nil")
	}
	err := broadcast.msg.EncodeForSigning(w)
	if err != nil {
		return err
	}

	if err = broadcast.bm.encodeBroadcast(w); err != nil {
		return err
	}

	return nil
}

// encodeForEncryption encodes Broadcast so that it can be encrypted.
func (broadcast *Broadcast) encodeForEncryption(w io.Writer) error {
	err := broadcast.bm.encodeBroadcast(w)
	if err != nil {
		return err
	}

	sigLength := uint64(len(broadcast.sig))
	if err = bmutil.WriteVarInt(w, sigLength); err != nil {
		return err
	}
	if _, err = w.Write(broadcast.sig); err != nil {
		return err
	}
	return nil
}

// decodeFromDecrypted decodes Broadcast from its decrypted form.
func (broadcast *Broadcast) decodeFromDecrypted(r io.Reader) error {
	broadcast.bm = &Bitmessage{}
	err := broadcast.bm.decodeBroadcast(r)
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
		return wire.NewMessageError("DecodeFromDecrypted", str)
	}
	broadcast.sig = make([]byte, sigLength)
	_, err = io.ReadFull(r, broadcast.sig)
	return err
}

func (broadcast *Broadcast) signAndEncrypt(
	i incompleteBroadcast,
	address bmutil.Address,
	private *identity.PrivateKey) error {

	// Start signing
	var b bytes.Buffer
	err := broadcastEncodeForSigning(&b, i, broadcast.bm)
	if err != nil {
		return err
	}

	// Hash
	hash := sha256.Sum256(b.Bytes())
	b.Reset()

	// Sign
	sig, err := private.Signing.Sign(hash[:])
	if err != nil {
		return fmt.Errorf("signing failed: %v", err)
	}
	broadcast.sig = sig.Serialize()

	// Start encryption
	err = broadcast.encodeForEncryption(&b)
	if err != nil {
		return err
	}

	// Encrypt
	broadcast.msg, err = i.Encrypt(address, b.Bytes())

	if err != nil {
		return fmt.Errorf("encryption failed: %v", err)
	}

	return nil
}

func (broadcast Broadcast) verify(address bmutil.Address) error {

	if broadcast.msg == nil {
		panic("msg is nil")
	}

	id := broadcast.bm.Public

	addr := id.Address()

	genAddr := addr.String()
	dencAddr := address.String()
	if dencAddr != genAddr {
		return fmt.Errorf("Address used for decryption (%s) doesn't match "+
			"that generated from public key (%s). Possible surreptitious "+
			"forwarding attack.", dencAddr, genAddr)
	}

	// Start signature verification
	var b bytes.Buffer
	err := broadcast.encodeForSigning(&b)
	if err != nil {
		return err
	}

	// Hash
	hash := sha256.Sum256(b.Bytes())
	sha1hash := sha1.Sum(b.Bytes()) // backwards compatibility

	// Verify
	sig, err := btcec.ParseSignature(broadcast.sig, btcec.S256())
	if err != nil {
		return ErrInvalidSignature
	}

	pk := id.Key().Verification
	if !sig.Verify(hash[:], pk.Btcec()) { // Try SHA256 first
		if !sig.Verify(sha1hash[:], pk.Btcec()) { // then SHA1
			return ErrInvalidSignature
		}
	}
	return nil
}

// CreateTaglessBroadcast creates a Broadcast that we send over the network,
// as opposed to one that we receive and decrypt.
func CreateTaglessBroadcast(expiration time.Time, bm *Bitmessage,
	private *identity.PrivateID) (*Broadcast, error) {

	address := private.Address()

	if bm.Destination != nil {
		return nil, errors.New("Broadcasts do not have a destination.")
	}

	broadcast := Broadcast{
		bm: bm,
	}

	err := broadcast.signAndEncrypt(
		&incompleteTaglessBroadcast{expiration, address.Stream()},
		address, private.PrivateKey())
	if err != nil {
		return nil, err
	}

	return &broadcast, err
}

// CreateTaggedBroadcast creates a Broadcast that we send over the network,
// as opposed to one that we receive and decrypt.
func CreateTaggedBroadcast(expires time.Time, bm *Bitmessage, tag *hash.Sha,
	private *identity.PrivateID) (*Broadcast, error) {

	address := private.Address()

	if bm.Destination != nil {
		return nil, errors.New("Broadcasts do not have a destination.")
	}

	broadcast := Broadcast{
		bm: bm,
	}

	err := broadcast.signAndEncrypt(
		&incompleteTaggedBroadcast{expires, address.Stream(), tag},
		address, private.PrivateKey())
	if err != nil {
		return nil, err
	}

	return &broadcast, nil
}

func newBroadcast(msg obj.Broadcast, key *btcec.PrivateKey, address bmutil.Address) (*Broadcast, error) {
	encrypted := msg.Encrypted()
	dec, err := btcec.Decrypt(key, encrypted)
	if err != nil {
		if err == btcec.ErrInvalidMAC { // decryption failed due to invalid key
			return nil, ErrInvalidIdentity
		}
		return nil, err
	}
	broadcast := Broadcast{}

	var b bytes.Buffer
	b.Write(dec)
	err = broadcast.decodeFromDecrypted(&b)
	if err != nil {
		return nil, err
	}

	broadcast.msg = msg

	err = broadcast.verify(address)
	if err != nil {
		return nil, err
	}

	return &broadcast, nil
}

// NewTaglessBroadcast takes a broadcast we have received over the network
// and attempts to decrypt it.
func NewTaglessBroadcast(msg *obj.TaglessBroadcast, address bmutil.Address) (*Broadcast, error) {
	broadcast, err := newBroadcast(msg, bmutil.V4BroadcastDecryptionKey(address), address)
	if err != nil {
		return nil, err
	}

	return broadcast, nil
}

// NewTaggedBroadcast takes a broadcast we have received over the network
// and attempts to decrypt it.
func NewTaggedBroadcast(msg *obj.TaggedBroadcast, address bmutil.Address) (*Broadcast, error) {
	if subtle.ConstantTimeCompare(msg.Tag[:], bmutil.Tag(address)) != 1 {
		return nil, ErrInvalidIdentity
	}

	broadcast, err := newBroadcast(msg, bmutil.V5BroadcastDecryptionKey(address), address)
	if err != nil {
		return nil, err
	}

	return broadcast, nil
}
