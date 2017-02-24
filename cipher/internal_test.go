// Copyright 2016 Daniel Krawisz.
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package cipher

import (
	"bytes"
	"io"
	"time"

	. "github.com/DanielKrawisz/bmutil"
	"github.com/DanielKrawisz/bmutil/format"
	"github.com/DanielKrawisz/bmutil/hash"
	"github.com/DanielKrawisz/bmutil/identity"
	"github.com/DanielKrawisz/bmutil/pow"
	"github.com/DanielKrawisz/bmutil/wire"
	"github.com/DanielKrawisz/bmutil/wire/obj"
	"github.com/btcsuite/btcd/btcec"
)

func PrivAddr1() *identity.PrivateAddress {
	p, _ := identity.ImportWIF("BM-2cXm1jokUVp9Nn1kBtkeMjpxaLJuP3FwET",
		"5K3oNuMzVEWdrtyBAZXrPQwQTSmCGrAZS1groRDQVGDeccLim15",
		"5HzhkuimkuizxJyw9b7qnFEMtUrAXD25Y5AV1sZ964dSSXReKnb")
	return p
}

func PrivAddr2() *identity.PrivateAddress {
	p, _ := identity.ImportWIF("BM-2cTLMh1CufXWQ9co4CWzD9muDZP4a7N4MA",
		"5Jw6Gtjy8RCZ5BmTtyx3VykzdXvX4WyWsGu2wLrhfTv8zgKfo7C",
		"5JY8Lsf5cmNTrXXj1e7FkvCZVYgsK7tAiiocTDtVKLBvQm1EsFw")
	return p
}

func PrivID1() *identity.PrivateID {
	return identity.NewPrivateID(PrivAddr1(), identity.BehaviorAck,
		&pow.Default)
}

func PrivID2() *identity.PrivateID {
	return identity.NewPrivateID(PrivAddr2(), identity.BehaviorAck,
		&pow.Default)
}

func PrivKey1() *identity.PrivateKey {
	return PrivID1().PrivateKey()
}

func PrivKey2() *identity.PrivateKey {
	return PrivID2().PrivateKey()
}

var EncKey1, SignKey1, EncKey2, SignKey2 *wire.PubKey
var Tag1, Tag2 *hash.Sha

// Setup everything
func init() {
	EncKey1, _ = wire.NewPubKey(PrivKey1().Decryption.PubKey().SerializeUncompressed()[1:])
	SignKey1, _ = wire.NewPubKey(PrivKey1().Signing.PubKey().SerializeUncompressed()[1:])

	EncKey2, _ = wire.NewPubKey(PrivKey2().Decryption.PubKey().SerializeUncompressed()[1:])
	SignKey2, _ = wire.NewPubKey(PrivKey2().Signing.PubKey().SerializeUncompressed()[1:])

	Tag1, _ = hash.NewSha(Tag(PrivID1().Address()))
	Tag2, _ = hash.NewSha(Tag(PrivID2().Address()))
}

func TstGenerateForwardingData(key *wire.PubKey) []byte {
	var b bytes.Buffer
	attackPub := new(decryptedPubKey)
	attackPub.data = &obj.PubKeyData{
		Encryption:   key,
		Verification: key,
	}
	attackPub.EncodeForEncryption(&b)

	fd, err := btcec.Encrypt(V5BroadcastDecryptionKey(PrivID1().Address()).PubKey(),
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
	attackPub.data.Encryption, _ = wire.NewPubKey(PrivKey1().Decryption.PubKey().SerializeUncompressed()[1:])
	attackPub.data.Verification, _ = wire.NewPubKey(PrivKey1().Signing.PubKey().SerializeUncompressed()[1:])
	attackPub.signature = []byte{0x00}
	attackPub.EncodeForEncryption(&b)

	invalidSig, err := btcec.Encrypt(V5BroadcastDecryptionKey(PrivID1().Address()).PubKey(),
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
	attackPub.data.Encryption, _ = wire.NewPubKey(PrivKey1().Decryption.PubKey().SerializeUncompressed()[1:])
	attackPub.data.Verification, _ = wire.NewPubKey(PrivKey1().Signing.PubKey().SerializeUncompressed()[1:])
	attackPub.EncodeForSigning(&b)
	// should actually be hash
	sig, _ := PrivKey1().Decryption.Sign(b.Bytes())
	attackPub.signature = sig.Serialize()

	b.Reset()
	attackPub.EncodeForEncryption(&b)

	mismatchSig, err := btcec.Encrypt(V5BroadcastDecryptionKey(PrivID1().Address()).PubKey(),
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

	return obj.NewExtendedPubKey(0, expires, streamNumber,
		&obj.PubKeyData{
			Behavior:     behavior,
			Verification: signingKey,
			Encryption:   encKey,
			Pow: &pow.Data{
				NonceTrialsPerByte: nonceTrials,
				ExtraBytes:         extraBytes,
			},
		}, signature)
}

func tstNewDecryptedPubKey(nonce pow.Nonce, expires time.Time, streamNumber uint64,
	behavior uint32, signingKey, encryptKey *wire.PubKey, nonceTrials,
	extraBytes uint64, signature []byte, tag *hash.Sha, encrypted []byte) *decryptedPubKey {
	return &decryptedPubKey{
		object: obj.NewEncryptedPubKey(nonce, expires, streamNumber, tag, encrypted),
		data: &obj.PubKeyData{
			Behavior:     behavior,
			Verification: signingKey,
			Encryption:   encryptKey,
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
	extraBytes uint64, private *identity.PrivateKey) *obj.ExtendedPubKey {

	ep := tstNewExtendedPubKey(nonce, expires, streamNumber,
		behavior, signingKey, encKey, nonceTrials, extraBytes, nil)

	if private != nil {
		signExtendedPubKey(ep, private)
	}

	return ep
}

func TstNewDecryptedPubKey(nonce pow.Nonce, expires time.Time, streamNumber uint64,
	behavior uint32, signingKey, encKey *wire.PubKey, nonceTrials, extraBytes uint64,
	signature []byte, tag *hash.Sha, encrypted []byte, private *identity.PrivateID) PubKey {

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
	Private   *identity.PrivateID
}

func (tb *TstBroadcast) EncodeForSigning(w io.Writer) error {
	return broadcastEncodeForSigning(w, tb.i, tb.Data)
}

func TstNewBroadcast(nonce pow.Nonce, expires time.Time, streamNumber uint64,
	tag *hash.Sha, encrypted []byte, fromAddressVersion, fromStreamNumber uint64,
	behavior uint32, signingKey, encryptKey *wire.PubKey, nonceTrials, extraBytes,
	encoding uint64, message, signature []byte, private *identity.PrivateID) (*Broadcast, *TstBroadcast) {

	var stream uint64
	if private != nil {
		stream = private.Address().Stream()
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
		Version: fromAddressVersion,
		Stream:  fromStreamNumber,
		Data: &obj.PubKeyData{
			Behavior:     behavior,
			Verification: signingKey,
			Encryption:   encryptKey,
			Pow: &pow.Data{
				NonceTrialsPerByte: nonceTrials,
				ExtraBytes:         extraBytes,
			},
		},
		Content: content,
	}

	return &Broadcast{
			msg: msg,
			sig: signature,
			bm:  data,
		}, &TstBroadcast{
			i:         i,
			Data:      data,
			Signature: signature,
			Private:   private,
		}
}

func TstBroadcastEncryptParams(expires time.Time, streamNumber uint64,
	tag *hash.Sha, fromAddressVersion, fromStreamNumber uint64,
	behavior uint32, signingKey, encryptKey *wire.PubKey, nonceTrials, extraBytes,
	encoding uint64, message []byte, private *identity.PrivateID) (time.Time, *Bitmessage, *hash.Sha, *identity.PrivateID) {

	content, err := format.Read(encoding, message)
	if err != nil {
		panic(err.Error())
	}

	return expires, &Bitmessage{
		Version: fromAddressVersion,
		Stream:  fromStreamNumber,
		Data: &obj.PubKeyData{
			Behavior:     behavior,
			Verification: signingKey,
			Encryption:   encryptKey,
			Pow: &pow.Data{
				NonceTrialsPerByte: nonceTrials,
				ExtraBytes:         extraBytes,
			},
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
	invSigningKey, _ = btcec.Encrypt(V5BroadcastDecryptionKey(PrivID1().Address()).PubKey(),
		b.Bytes())

	b.Reset()
	attackB, _ = TstNewBroadcast(0, time.Now().Add(time.Minute*5).Truncate(time.Second),
		1, Tag1, nil, 0, 0, 0, validPubkey, &wire.PubKey{}, 0, 0, 1, []byte{0x00}, nil, nil)
	attackB.encodeForEncryption(&b)
	invEncKey, _ = btcec.Encrypt(V5BroadcastDecryptionKey(PrivID1().Address()).PubKey(),
		b.Bytes())

	b.Reset()
	attackB, _ = TstNewBroadcast(0, time.Now().Add(time.Minute*5).Truncate(time.Second),
		1, Tag1, nil, 4, 1, 0, validPubkey, validPubkey, 0, 0, 1, []byte{0x00}, nil, nil)
	attackB.encodeForEncryption(&b)
	forwardingData, _ = btcec.Encrypt(V5BroadcastDecryptionKey(PrivID1().Address()).PubKey(),
		b.Bytes())

	b.Reset()
	sk, _ := wire.NewPubKey(PrivKey1().Signing.PubKey().SerializeUncompressed()[1:])
	ek, _ := wire.NewPubKey(PrivKey1().Decryption.PubKey().SerializeUncompressed()[1:])
	attackB, _ = TstNewBroadcast(0, time.Now().Add(time.Minute*5).Truncate(time.Second),
		1, Tag1, nil, 4, 1, 0, sk, ek, 0, 0, 1, []byte{0x00}, nil, nil)
	attackB.encodeForEncryption(&b)
	invalidSig, _ = btcec.Encrypt(V5BroadcastDecryptionKey(PrivID1().Address()).PubKey(),
		b.Bytes())

	b.Reset()
	attackB.encodeForSigning(&b)
	// should actually be hash
	sig, _ := PrivKey1().Decryption.Sign(b.Bytes())
	attackB.sig = sig.Serialize()
	b.Reset()
	attackB.encodeForEncryption(&b)
	mismatchSig, _ = btcec.Encrypt(V5BroadcastDecryptionKey(PrivID1().Address()).PubKey(),
		b.Bytes())

	return
}

func TstNewMessage(nonce pow.Nonce, expires time.Time, streamNumber uint64,
	encrypted []byte, addressVersion, fromStreamNumber uint64, behavior uint32,
	signingKey, encryptKey *wire.PubKey, nonceTrials, extraBytes uint64,
	destination *hash.Ripe, encoding uint64,
	message, ack, signature []byte) *Message {

	msg := obj.NewMessage(nonce, expires, streamNumber, encrypted)

	content, err := format.Read(encoding, message)
	if err != nil {
		panic(err.Error())
	}

	return &Message{
		msg: msg,
		bm: &Bitmessage{
			Version: addressVersion,
			Stream:  fromStreamNumber,
			Data: &obj.PubKeyData{
				Behavior:     behavior,
				Verification: signingKey,
				Encryption:   encryptKey,
				Pow: &pow.Data{
					NonceTrialsPerByte: nonceTrials,
					ExtraBytes:         extraBytes,
				},
			},
			Destination: destination,
			Content:     content,
		},
		ack: ack,
		sig: signature,
	}
}

func TstSignAndEncryptMessage(nonce uint64, expires time.Time, streamNumber uint64,
	encrypted []byte, addressVersion, fromStreamNumber uint64, behavior uint32,
	signingKey, encryptKey *wire.PubKey, nonceTrials, extraBytes uint64,
	destination *hash.Ripe, encoding uint64, message, ack, signature []byte,
	privID *identity.PrivateKey, pubID *identity.PublicKey) (*Message, error) {

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
		Version: addressVersion,
		Stream:  fromStreamNumber,
		Data: &obj.PubKeyData{
			Behavior:     behavior,
			Verification: signingKey,
			Encryption:   encryptKey,
			Pow: &pow.Data{
				NonceTrialsPerByte: nonceTrials,
				ExtraBytes:         extraBytes,
			},
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
		1, nil, 0, 0, 0, &wire.PubKey{}, &wire.PubKey{}, 0, 0, &hash.Ripe{}, 1, []byte{0x00}, []byte{}, nil)
	attackB.encodeForEncryption(&b)
	invDest, _ = btcec.Encrypt(PrivKey1().Decryption.PubKey(), b.Bytes())

	b.Reset()
	attackB.bm.Data.Verification = &wire.PubKey{}
	attackB.bm.Data.Encryption = validPubkey
	attackB.bm.Destination, _ = hash.NewRipe(PrivID1().Address().RipeHash()[:])
	attackB.encodeForEncryption(&b)
	invSigningKey, _ = btcec.Encrypt(PrivKey1().Decryption.PubKey(), b.Bytes())

	b.Reset()
	attackB.bm.Data.Encryption, _ = wire.NewPubKey(PrivKey2().Decryption.PubKey().SerializeUncompressed()[1:])
	attackB.bm.Data.Verification, _ = wire.NewPubKey(PrivKey2().Signing.PubKey().SerializeUncompressed()[1:])
	attackB.sig = []byte{0x00}
	attackB.encodeForEncryption(&b)
	invalidSig, _ = btcec.Encrypt(PrivKey1().Decryption.PubKey(), b.Bytes())

	b.Reset()
	attackB.encodeForSigning(&b)
	// should actually be hash
	sig, _ := PrivKey1().Decryption.Sign(b.Bytes())
	attackB.sig = sig.Serialize()
	b.Reset()
	attackB.encodeForEncryption(&b)
	mismatchSig, _ = btcec.Encrypt(PrivKey1().Decryption.PubKey(), b.Bytes())

	return
}
