// Copyright 2016 Daniel Krawisz.
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package cipher

import (
	"bytes"
	"time"

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

func tstNewExtendedPubKey(nonce uint64, expires time.Time, streamNumber uint64,
	behavior uint32, signingKey, encKey *wire.PubKey, nonceTrials,
	extraBytes uint64, signature []byte) *obj.ExtendedPubKey {

	return obj.NewExtendedPubKey(0, expires, streamNumber, behavior,
		signingKey, encKey, &pow.Data{
			NonceTrialsPerByte: nonceTrials,
			ExtraBytes:         extraBytes,
		}, signature)
}

func tstNewDecryptedPubKey(nonce uint64, expires time.Time, streamNumber uint64,
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

func TstNewExtendedPubKey(nonce uint64, expires time.Time, streamNumber uint64,
	behavior uint32, signingKey, encKey *wire.PubKey, nonceTrials,
	extraBytes uint64, private *identity.Private) *obj.ExtendedPubKey {

	ep := tstNewExtendedPubKey(nonce, expires, streamNumber,
		behavior, signingKey, encKey, nonceTrials, extraBytes, nil)

	if private != nil {
		signExtendedPubKey(ep, private)
	}

	return ep
}

func TstNewDecryptedPubKey(nonce uint64, expires time.Time, streamNumber uint64,
	behavior uint32, signingKey, encKey *wire.PubKey, nonceTrials, extraBytes uint64,
	signature []byte, tag *wire.ShaHash, encrypted []byte, private *identity.Private) PubKey {

	dk := tstNewDecryptedPubKey(nonce, expires, streamNumber,
		behavior, signingKey, encKey, nonceTrials, extraBytes, signature, tag, encrypted)

	if encrypted == nil && private != nil {
		dk.signAndEncrypt(private)
	}

	return dk
}
