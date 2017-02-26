// Copyright (c) 2015 Monetas.
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
	"errors"
	"fmt"
	"io"
	"time"

	. "github.com/DanielKrawisz/bmutil"
	"github.com/DanielKrawisz/bmutil/hash"
	"github.com/DanielKrawisz/bmutil/identity"
	"github.com/DanielKrawisz/bmutil/pow"
	"github.com/DanielKrawisz/bmutil/wire"
	"github.com/DanielKrawisz/bmutil/wire/obj"
	"github.com/btcsuite/btcd/btcec"
)

// PubKeyObject is an interface representing a PubKeyMessage. It represents
// a pubkey object that we either created or were able to decrypt. It
// encapsulates the cryptographic operations required to work with pubkey objects.
type PubKeyObject interface {
	Object() obj.Object
	Data() *obj.PubKeyData
	Behavior() uint32
	Pow() *pow.Data
	Tag() *hash.Sha
	String() string
}

// ToIdentity transforms a PubKeyObject to an identity.Public
func ToIdentity(pubkey PubKeyObject) (identity.Public, error) {
	data := pubkey.Data()
	k, err := identity.NewPublicKey(data.Verification, data.Encryption)
	if err != nil {
		return nil, err
	}

	header := pubkey.Object().Header()

	id, err := identity.NewPublic(k, header.Version, header.StreamNumber,
		pubkey.Behavior(), pubkey.Pow())
	if err != nil {
		return nil, err
	}

	return id, nil
}

func createSimplePubKey(expires time.Time, privID *identity.PrivateID) *obj.SimplePubKey {

	data := privID.Data()

	return obj.NewSimplePubKey(0, expires, privID.Address().Stream(), data.Behavior,
		data.Verification, data.Encryption)
}

// sign signs an extendedPubKey, populating the
// signature fields using the provided private identity.
func signExtendedPubKey(ep *obj.ExtendedPubKey, private *identity.PrivateKey) error {
	if ep == nil {
		return errors.New("ExtendedPubKey is nil.")
	}

	if private == nil {
		return errors.New("PrivateKey is nil.")
	}

	// Start signing
	var b bytes.Buffer
	err := ep.EncodeForSigning(&b)
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
	ep.Signature = sig.Serialize()
	return nil
}

// verify checks the validity of the signature. It returns an error
// if the signature could not be verified or is invalid.
func verifyExtendedPubKey(ep *obj.ExtendedPubKey) error {

	// Verify validity of secp256k1 public keys.
	signKey, err := ep.Data().Verification.ToBtcec()
	if err != nil {
		return err
	}

	// Start signature verification
	var b bytes.Buffer
	err = ep.EncodeForSigning(&b)
	if err != nil {
		return err
	}

	// Hash
	hash := sha256.Sum256(b.Bytes())
	sha1hash := sha1.Sum(b.Bytes()) // backwards compatibility

	// Verify
	sig, err := btcec.ParseSignature(ep.Signature, btcec.S256())
	if err != nil {
		return ErrInvalidSignature
	}

	if !sig.Verify(hash[:], signKey) { // Try SHA256 first
		if !sig.Verify(sha1hash[:], signKey) { // then SHA1
			return ErrInvalidSignature
		}
	}

	return nil
}

func createExtendedPubKey(expires time.Time, privID *identity.PrivateID) (*obj.ExtendedPubKey, error) {

	pk := obj.NewExtendedPubKey(0, expires, privID.Address().Stream(), privID.Data(), nil)

	err := signExtendedPubKey(pk, privID.PrivateKey())
	if err != nil {
		return nil, err
	}

	return pk, nil
}

func newExtendedPubKey(pk *obj.ExtendedPubKey) (*obj.ExtendedPubKey, error) {
	return pk, verifyExtendedPubKey(pk)
}

type decryptedPubKey struct {
	object    *obj.EncryptedPubKey
	data      *obj.PubKeyData
	signature []byte
}

func (dp *decryptedPubKey) Object() obj.Object {
	return dp.object
}

func (dp *decryptedPubKey) Behavior() uint32 {
	return dp.data.Behavior
}

func (dp *decryptedPubKey) VerificationKey() *wire.PubKey {
	return dp.data.Verification
}

func (dp *decryptedPubKey) EncryptionKey() *wire.PubKey {
	return dp.data.Encryption
}

func (dp *decryptedPubKey) Pow() *pow.Data {
	return dp.data.Pow
}

func (dp *decryptedPubKey) Data() *obj.PubKeyData {
	return dp.data
}

func (dp *decryptedPubKey) Tag() *hash.Sha {
	return dp.object.Tag
}

func (dp *decryptedPubKey) String() string {
	return fmt.Sprintf("decryptedPubKey{data: %s, signature: %s}",
		dp.data.String(),
		hex.EncodeToString(dp.signature))
}

func (dp *decryptedPubKey) EncodeForEncryption(w io.Writer) error {
	err := dp.data.Encode(w)
	if err != nil {
		return err
	}

	return obj.EncodePubKeySignature(w, dp.signature)
}

func (dp *decryptedPubKey) decodeFromDecrypted(r io.Reader) error {
	dp.data = &obj.PubKeyData{}
	err := dp.data.Decode(r)
	if err != nil {
		return err
	}

	dp.signature, err = obj.DecodePubKeySignature(r)
	if err != nil {
		return err
	}

	return nil
}

func (dp *decryptedPubKey) EncodeForSigning(w io.Writer) error {
	err := dp.object.Header().EncodeForSigning(w)
	if err != nil {
		return err
	}

	err = wire.WriteElement(w, dp.object.Tag)
	if err != nil {
		return err
	}

	return dp.data.Encode(w)
}

func (dp *decryptedPubKey) signAndEncrypt(private *identity.PrivateID) error {
	// Start signing
	var b bytes.Buffer
	err := dp.EncodeForSigning(&b)
	if err != nil {
		return err
	}

	// Hash
	hash := sha256.Sum256(b.Bytes())
	b.Reset()

	// Sign
	sig, err := private.PrivateKey().Signing.Sign(hash[:])
	if err != nil {
		return fmt.Errorf("signing failed: %v", err)
	}
	dp.signature = sig.Serialize()

	err = dp.EncodeForEncryption(&b)
	if err != nil {
		return err
	}

	// Encrypt
	dp.object.Encrypted, err = btcec.Encrypt(
		V5BroadcastDecryptionKey(private.Address()).PubKey(), b.Bytes())
	if err != nil {
		return fmt.Errorf("encryption failed: %v", err)
	}

	return nil
}

func (dp *decryptedPubKey) decryptAndVerify(address Address) error {
	// Try decryption.
	// Check tag, save decryption cost.
	if subtle.ConstantTimeCompare(dp.object.Tag[:], Tag(address)) != 1 {
		return ErrInvalidIdentity
	}

	dec, err := btcec.Decrypt(V5BroadcastDecryptionKey(address), dp.object.Encrypted)
	if err == btcec.ErrInvalidMAC { // decryption failed due to invalid key
		return ErrInvalidIdentity
	} else if err != nil { // other reasons
		return err
	}

	err = dp.decodeFromDecrypted(bytes.NewReader(dec))
	if err != nil {
		return err
	}

	// Verify validity of secp256k1 public keys.
	public, err := identity.NewPublicKey(dp.data.Verification, dp.data.Encryption)
	if err != nil {
		return err
	}

	header := dp.object.Header()

	// Check if embedded keys correspond to the address used for decryption.
	id, err := identity.NewPublic(public, header.Version,
		header.StreamNumber, dp.data.Behavior, dp.data.Pow)
	if err != nil {
		return err
	}

	genAddr := id.Address().String()
	dencAddr := address.String()
	if dencAddr != genAddr {
		return fmt.Errorf("Address used for decryption (%s) doesn't match "+
			"that generated from public key (%s). Possible surreptitious "+
			"forwarding attack.", dencAddr, genAddr)
	}

	// Start signature verification
	var b bytes.Buffer
	err = dp.EncodeForSigning(&b)
	if err != nil {
		return err
	}

	// Hash
	hash := sha256.Sum256(b.Bytes())
	sha1hash := sha1.Sum(b.Bytes()) // backwards compatibility

	// Verify
	sig, err := btcec.ParseSignature(dp.signature, btcec.S256())
	if err != nil {
		return ErrInvalidSignature
	}

	k := public.Verification.Btcec()
	if !sig.Verify(hash[:], k) { // Try SHA256 first
		if !sig.Verify(sha1hash[:], k) { // then SHA1
			return ErrInvalidSignature
		}
	}

	return nil
}

func createDecryptedPubKey(expires time.Time, privID *identity.PrivateID) (*decryptedPubKey, error) {
	addr := privID.Address()

	var tag hash.Sha
	copy(tag[:], Tag(addr))

	dp := &decryptedPubKey{
		object: obj.NewEncryptedPubKey(0, expires, privID.Address().Stream(), &tag, nil),
		data:   privID.Data(),
	}

	err := dp.signAndEncrypt(privID)
	if err != nil {
		return nil, err
	}

	return dp, nil
}

func newDecryptedPubKey(msg *obj.EncryptedPubKey, address Address) (*decryptedPubKey, error) {
	pk := &decryptedPubKey{
		object: msg,
	}

	return pk, pk.decryptAndVerify(address)
}
