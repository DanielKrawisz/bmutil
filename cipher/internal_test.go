// Copyright 2016 Daniel Krawisz.
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package cipher

import (
	"bytes"
	"io"
	"time"

	"github.com/DanielKrawisz/bmutil/format"
	"github.com/DanielKrawisz/bmutil/identity"
	"github.com/DanielKrawisz/bmutil/pow"
	"github.com/DanielKrawisz/bmutil/wire"
	"github.com/DanielKrawisz/bmutil/wire/obj"
	"github.com/btcsuite/btcd/btcec"
)

var PrivID1, PrivID2 *identity.Private
var EncKey1, SignKey1, EncKey2, SignKey2 *wire.PubKey
var Tag1, Tag2 *wire.ShaHash

// Setup everything
func init() {
	PrivID1, _ = identity.ImportWIF("BM-2cXm1jokUVp9Nn1kBtkeMjpxaLJuP3FwET",
		"5K3oNuMzVEWdrtyBAZXrPQwQTSmCGrAZS1groRDQVGDeccLim15",
		"5HzhkuimkuizxJyw9b7qnFEMtUrAXD25Y5AV1sZ964dSSXReKnb",
		pow.DefaultNonceTrialsPerByte, pow.DefaultExtraBytes)
	EncKey1, _ = wire.NewPubKey(PrivID1.EncryptionKey.PubKey().SerializeUncompressed()[1:])
	SignKey1, _ = wire.NewPubKey(PrivID1.SigningKey.PubKey().SerializeUncompressed()[1:])

	PrivID2, _ = identity.ImportWIF("BM-2cTLMh1CufXWQ9co4CWzD9muDZP4a7N4MA",
		"5Jw6Gtjy8RCZ5BmTtyx3VykzdXvX4WyWsGu2wLrhfTv8zgKfo7C",
		"5JY8Lsf5cmNTrXXj1e7FkvCZVYgsK7tAiiocTDtVKLBvQm1EsFw",
		pow.DefaultNonceTrialsPerByte, pow.DefaultExtraBytes)
	EncKey2, _ = wire.NewPubKey(PrivID2.EncryptionKey.PubKey().SerializeUncompressed()[1:])
	SignKey2, _ = wire.NewPubKey(PrivID2.SigningKey.PubKey().SerializeUncompressed()[1:])

	Tag1, _ = wire.NewShaHash(PrivID1.Address.Tag())
	Tag2, _ = wire.NewShaHash(PrivID2.Address.Tag())
}

func TstGenerateForwardingData(key *wire.PubKey) []byte {
	var b bytes.Buffer
	attackPub := new(decryptedPubKey)
	attackPub.data = &obj.PubKeyData{
		EncryptionKey:   key,
		VerificationKey: key,
	}
	attackPub.EncodeForEncryption(&b)

	fd, err := btcec.Encrypt(PrivID1.Address.PrivateKey().PubKey(),
		b.Bytes())
	if err != nil {
		panic("could not generate forwardingData")
	}

	return fd
}

func TstGenerateInvalidSig() []byte {
	var b bytes.Buffer
	attackPub := new(decryptedPubKey)
	attackPub.data = &obj.PubKeyData{}
	attackPub.data.EncryptionKey, _ = wire.NewPubKey(PrivID1.EncryptionKey.PubKey().SerializeUncompressed()[1:])
	attackPub.data.VerificationKey, _ = wire.NewPubKey(PrivID1.SigningKey.PubKey().SerializeUncompressed()[1:])
	attackPub.signature = []byte{0x00}
	attackPub.EncodeForEncryption(&b)

	invalidSig, err := btcec.Encrypt(PrivID1.Address.PrivateKey().PubKey(),
		b.Bytes())
	if err != nil {
		panic("could not generate invalidSig")
	}

	return invalidSig
}

func TstGenerateMismatchSig() []byte {
	var b bytes.Buffer
	attackPub := new(decryptedPubKey)
	attackPub.object = obj.NewEncryptedPubKey(0, time.Time{}, 0, Tag1, nil)
	attackPub.data = &obj.PubKeyData{}
	attackPub.data.EncryptionKey, _ = wire.NewPubKey(PrivID1.EncryptionKey.PubKey().SerializeUncompressed()[1:])
	attackPub.data.VerificationKey, _ = wire.NewPubKey(PrivID1.SigningKey.PubKey().SerializeUncompressed()[1:])
	attackPub.EncodeForSigning(&b)
	// should actually be hash
	sig, _ := PrivID1.EncryptionKey.Sign(b.Bytes())
	attackPub.signature = sig.Serialize()

	b.Reset()
	attackPub.EncodeForEncryption(&b)

	mismatchSig, err := btcec.Encrypt(PrivID1.Address.PrivateKey().PubKey(),
		b.Bytes())
	if err != nil {
		panic("could not generate mismatchedSig")
	}

	return mismatchSig
}

func (b *Broadcast) SetMessage(n *Broadcast) {
	b.msg = n.msg
}

func (b *Message) SetMessage(n *Message) {
	b.msg = n.msg
}

func tstNewExtendedPubKey(nonce pow.Nonce, expires time.Time, streamNumber uint64,
	behavior uint32, signingKey, encKey *wire.PubKey, nonceTrials,
	extraBytes uint64, signature []byte) *obj.ExtendedPubKey {

	return obj.NewExtendedPubKey(0, expires, streamNumber, behavior,
		signingKey, encKey, &pow.Data{
			NonceTrialsPerByte: nonceTrials,
			ExtraBytes:         extraBytes,
		}, signature)
}

func tstNewDecryptedPubKey(nonce pow.Nonce, expires time.Time, streamNumber uint64,
	behavior uint32, signingKey, encryptKey *wire.PubKey, nonceTrials,
	extraBytes uint64, signature []byte, tag *wire.ShaHash, encrypted []byte) *decryptedPubKey {
	return &decryptedPubKey{
		object: obj.NewEncryptedPubKey(nonce, expires, streamNumber, tag, encrypted),
		data: &obj.PubKeyData{
			Behavior:        behavior,
			VerificationKey: signingKey,
			EncryptionKey:   encryptKey,
			Pow: &pow.Data{
				NonceTrialsPerByte: nonceTrials,
				ExtraBytes:         extraBytes,
			},
		},
		signature: signature,
	}
}

func TstNewExtendedPubKey(nonce pow.Nonce, expires time.Time, streamNumber uint64,
	behavior uint32, signingKey, encKey *wire.PubKey, nonceTrials,
	extraBytes uint64, private *identity.Private) *obj.ExtendedPubKey {

	ep := tstNewExtendedPubKey(nonce, expires, streamNumber,
		behavior, signingKey, encKey, nonceTrials, extraBytes, nil)

	if private != nil {
		signExtendedPubKey(ep, private)
	}

	return ep
}

func TstNewDecryptedPubKey(nonce pow.Nonce, expires time.Time, streamNumber uint64,
	behavior uint32, signingKey, encKey *wire.PubKey, nonceTrials, extraBytes uint64,
	signature []byte, tag *wire.ShaHash, encrypted []byte, private *identity.Private) PubKey {

	dk := tstNewDecryptedPubKey(nonce, expires, streamNumber,
		behavior, signingKey, encKey, nonceTrials, extraBytes, signature, tag, encrypted)

	if encrypted == nil && private != nil {
		dk.signAndEncrypt(private)
	}

	return dk
}

type TstBroadcast struct {
	i         incompleteBroadcast
	Data      *Bitmessage
	Signature []byte
	Private   *identity.Private
}

func (tb *TstBroadcast) EncodeForSigning(w io.Writer) error {
	return broadcastEncodeForSigning(w, tb.i, tb.Data)
}

func TstNewBroadcast(nonce pow.Nonce, expires time.Time, streamNumber uint64,
	tag *wire.ShaHash, encrypted []byte, fromAddressVersion, fromStreamNumber uint64,
	behavior uint32, signingKey, encryptKey *wire.PubKey, nonceTrials, extraBytes,
	encoding uint64, message, signature []byte, private *identity.Private) (*Broadcast, *TstBroadcast) {

	var stream uint64
	if private != nil {
		stream = private.Address.Stream
	}

	var msg obj.Broadcast
	var i incompleteBroadcast
	if tag != nil {
		msg = obj.NewTaggedBroadcast(nonce, expires, streamNumber, tag, encrypted)
		i = &incompleteTaggedBroadcast{expires, stream, tag}
	} else {
		msg = obj.NewTaglessBroadcast(nonce, expires, streamNumber, encrypted)
		i = &incompleteTaglessBroadcast{expires, stream}
	}

	content, err := format.Read(encoding, message)
	if err != nil {
		panic(err.Error())
	}

	data := &Bitmessage{
		FromAddressVersion: fromAddressVersion,
		FromStreamNumber:   fromStreamNumber,
		Behavior:           behavior,
		SigningKey:         signingKey,
		EncryptionKey:      encryptKey,
		Pow: &pow.Data{
			NonceTrialsPerByte: nonceTrials,
			ExtraBytes:         extraBytes,
		},
		Content: content,
	}

	return &Broadcast{
			msg:       msg,
			signature: signature,
			data:      data,
		}, &TstBroadcast{
			i:         i,
			Data:      data,
			Signature: signature,
			Private:   private,
		}
}

func TstBroadcastEncryptParams(expires time.Time, streamNumber uint64,
	tag *wire.ShaHash, fromAddressVersion, fromStreamNumber uint64,
	behavior uint32, signingKey, encryptKey *wire.PubKey, nonceTrials, extraBytes,
	encoding uint64, message []byte, private *identity.Private) (time.Time, *Bitmessage, *wire.ShaHash, *identity.Private) {

	content, err := format.Read(encoding, message)
	if err != nil {
		panic(err.Error())
	}

	return expires, &Bitmessage{
		FromAddressVersion: fromAddressVersion,
		FromStreamNumber:   fromStreamNumber,
		Behavior:           behavior,
		SigningKey:         signingKey,
		EncryptionKey:      encryptKey,
		Pow: &pow.Data{
			NonceTrialsPerByte: nonceTrials,
			ExtraBytes:         extraBytes,
		},
		Content: content,
	}, tag, private
}

func TstGenerateBroadcastErrorData(validPubkey *wire.PubKey) (invSigningKey,
	invEncKey, forwardingData, invalidSig, mismatchSig []byte) {

	var b bytes.Buffer
	attackB, _ := TstNewBroadcast(0, time.Now().Add(time.Minute*5).Truncate(time.Second),
		1, Tag1, nil, 0, 0, 0, &wire.PubKey{}, validPubkey, 0, 0, 1, []byte{0x00}, nil, nil)
	attackB.encodeForEncryption(&b)
	invSigningKey, _ = btcec.Encrypt(PrivID1.Address.PrivateKey().PubKey(),
		b.Bytes())

	b.Reset()
	attackB, _ = TstNewBroadcast(0, time.Now().Add(time.Minute*5).Truncate(time.Second),
		1, Tag1, nil, 0, 0, 0, validPubkey, &wire.PubKey{}, 0, 0, 1, []byte{0x00}, nil, nil)
	attackB.encodeForEncryption(&b)
	invEncKey, _ = btcec.Encrypt(PrivID1.Address.PrivateKey().PubKey(),
		b.Bytes())

	b.Reset()
	attackB, _ = TstNewBroadcast(0, time.Now().Add(time.Minute*5).Truncate(time.Second),
		1, Tag1, nil, 4, 1, 0, validPubkey, validPubkey, 0, 0, 1, []byte{0x00}, nil, nil)
	attackB.encodeForEncryption(&b)
	forwardingData, _ = btcec.Encrypt(PrivID1.Address.PrivateKey().PubKey(),
		b.Bytes())

	b.Reset()
	sk, _ := wire.NewPubKey(PrivID1.SigningKey.PubKey().SerializeUncompressed()[1:])
	ek, _ := wire.NewPubKey(PrivID1.EncryptionKey.PubKey().SerializeUncompressed()[1:])
	attackB, _ = TstNewBroadcast(0, time.Now().Add(time.Minute*5).Truncate(time.Second),
		1, Tag1, nil, 4, 1, 0, sk, ek, 0, 0, 1, []byte{0x00}, nil, nil)
	attackB.encodeForEncryption(&b)
	invalidSig, _ = btcec.Encrypt(PrivID1.Address.PrivateKey().PubKey(),
		b.Bytes())

	b.Reset()
	attackB.encodeForSigning(&b)
	// should actually be hash
	sig, _ := PrivID1.EncryptionKey.Sign(b.Bytes())
	attackB.signature = sig.Serialize()
	b.Reset()
	attackB.encodeForEncryption(&b)
	mismatchSig, _ = btcec.Encrypt(PrivID1.Address.PrivateKey().PubKey(),
		b.Bytes())

	return
}

func TstNewMessage(nonce pow.Nonce, expires time.Time, streamNumber uint64,
	encrypted []byte, addressVersion, fromStreamNumber uint64, behavior uint32,
	signingKey, encryptKey *wire.PubKey, nonceTrials, extraBytes uint64,
	destination *wire.RipeHash, encoding uint64,
	message, ack, signature []byte) *Message {

	msg := obj.NewMessage(nonce, expires, streamNumber, encrypted)

	content, err := format.Read(encoding, message)
	if err != nil {
		panic(err.Error())
	}

	return &Message{
		msg: msg,
		data: &Bitmessage{
			FromAddressVersion: addressVersion,
			FromStreamNumber:   fromStreamNumber,
			Behavior:           behavior,
			SigningKey:         signingKey,
			EncryptionKey:      encryptKey,
			Pow: &pow.Data{
				NonceTrialsPerByte: nonceTrials,
				ExtraBytes:         extraBytes,
			},
			Destination: destination,
			Content:     content,
		},
		ack:       ack,
		signature: signature,
	}
}

func TstSignAndEncryptMessage(nonce uint64, expires time.Time, streamNumber uint64,
	encrypted []byte, addressVersion, fromStreamNumber uint64, behavior uint32,
	signingKey, encryptKey *wire.PubKey, nonceTrials, extraBytes uint64,
	destination *wire.RipeHash, encoding uint64,
	message, ack, signature []byte, privID *identity.Private, pubID *identity.Public) (*Message, error) {

	if encrypted == nil && signature != nil {
		panic("Test setup err A")
	}

	if encrypted != nil && nonce != 0 {
		panic("Test setup err B")
	}

	if encrypted == nil && privID == nil {
		panic("Test setup err C")
	}

	if encrypted != nil {
		panic("Test setup err D")
	}

	content, err := format.Read(encoding, message)
	if err != nil {
		panic(err.Error())
	}

	data := &Bitmessage{
		FromAddressVersion: addressVersion,
		FromStreamNumber:   fromStreamNumber,
		Behavior:           behavior,
		SigningKey:         signingKey,
		EncryptionKey:      encryptKey,
		Pow: &pow.Data{
			NonceTrialsPerByte: nonceTrials,
			ExtraBytes:         extraBytes,
		},
		Destination: destination,
		Content:     content,
	}

	return SignAndEncryptMessage(expires, streamNumber, data, ack, privID, pubID)
}

func TstGenerateMessageErrorData(validPubkey *wire.PubKey) (invDest,
	invSigningKey, invalidSig, mismatchSig []byte) {
	var b bytes.Buffer
	attackB := TstNewMessage(0, time.Now().Add(time.Minute*5).Truncate(time.Second),
		1, nil, 0, 0, 0, &wire.PubKey{}, &wire.PubKey{}, 0, 0, &wire.RipeHash{}, 1, []byte{0x00}, []byte{}, nil)
	attackB.encodeForEncryption(&b)
	invDest, _ = btcec.Encrypt(PrivID1.EncryptionKey.PubKey(), b.Bytes())

	b.Reset()
	attackB.data.SigningKey = &wire.PubKey{}
	attackB.data.EncryptionKey = validPubkey
	attackB.data.Destination, _ = wire.NewRipeHash(PrivID1.Address.Ripe[:])
	attackB.encodeForEncryption(&b)
	invSigningKey, _ = btcec.Encrypt(PrivID1.EncryptionKey.PubKey(), b.Bytes())

	b.Reset()
	attackB.data.EncryptionKey, _ = wire.NewPubKey(PrivID2.EncryptionKey.PubKey().SerializeUncompressed()[1:])
	attackB.data.SigningKey, _ = wire.NewPubKey(PrivID2.SigningKey.PubKey().SerializeUncompressed()[1:])
	attackB.signature = []byte{0x00}
	attackB.encodeForEncryption(&b)
	invalidSig, _ = btcec.Encrypt(PrivID1.EncryptionKey.PubKey(), b.Bytes())

	b.Reset()
	attackB.encodeForSigning(&b)
	// should actually be hash
	sig, _ := PrivID1.EncryptionKey.Sign(b.Bytes())
	attackB.signature = sig.Serialize()
	b.Reset()
	attackB.encodeForEncryption(&b)
	mismatchSig, _ = btcec.Encrypt(PrivID1.EncryptionKey.PubKey(), b.Bytes())

	return
}
