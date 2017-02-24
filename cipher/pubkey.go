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
	"fmt"
	"io"
	"time"

	"github.com/DanielKrawisz/bmutil"
	"github.com/DanielKrawisz/bmutil/hash"
	"github.com/DanielKrawisz/bmutil/identity"
	"github.com/DanielKrawisz/bmutil/pow"
	"github.com/DanielKrawisz/bmutil/wire"
	"github.com/DanielKrawisz/bmutil/wire/obj"
	"github.com/btcsuite/btcd/btcec"
)

// PubKey is an interface that makes certain guarantees about the information
// it contains. It represents a pubkey object that we either created or were
// able to decrypt. It encapsulates the cryptographic operations required
// to work with pubkey objects.
type PubKey interface {
	Object() obj.Object
	Behavior() uint32
	VerificationKey() *wire.PubKey
	EncryptionKey() *wire.PubKey
	Pow() *pow.Data
	Tag() *hash.Sha
	String() string
}

func createSimplePubKey(expires time.Time, streamNumber uint64,
	behavior uint32, privID *identity.Private) *obj.SimplePubKey {

	return obj.NewSimplePubKey(0, expires, streamNumber, privID.ToPubKeyData())
}

// sign signs an extendedPubKey, populating the
// signature fields using the provided private identity.
func signExtendedPubKey(ep *obj.ExtendedPubKey, private *identity.Private) error {
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
	sig, err := private.SigningKey.Sign(hash[:])
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
	signKey, err := ep.Data.VerificationKey.ToBtcec()
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

func createExtendedPubKey(expires time.Time, streamNumber uint64,
	behavior uint32, privID *identity.Private) (*obj.ExtendedPubKey, error) {

	pk := obj.NewExtendedPubKey(0, expires, streamNumber, privID.ToPubKeyData(), nil)

	err := signExtendedPubKey(pk, privID)
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
	return dp.data.VerificationKey
}

func (dp *decryptedPubKey) EncryptionKey() *wire.PubKey {
	return dp.data.EncryptionKey
}

func (dp *decryptedPubKey) Pow() *pow.Data {
	return dp.data.Pow
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

func (dp *decryptedPubKey) signAndEncrypt(private *identity.Private) error {
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
	sig, err := private.SigningKey.Sign(hash[:])
	if err != nil {
		return fmt.Errorf("signing failed: %v", err)
	}
	dp.signature = sig.Serialize()

	err = dp.EncodeForEncryption(&b)
	if err != nil {
		return err
	}

	// Encrypt
	dp.object.Encrypted, err = btcec.Encrypt(private.Address.PrivateKey().PubKey(),
		b.Bytes())
	if err != nil {
		return fmt.Errorf("encryption failed: %v", err)
	}

	return nil
}

func (dp *decryptedPubKey) decryptAndVerify(address *bmutil.Address) error {
	// Try decryption.
	// Check tag, save decryption cost.
	if subtle.ConstantTimeCompare(dp.object.Tag[:], address.Tag()) != 1 {
		return ErrInvalidIdentity
	}

	dec, err := btcec.Decrypt(address.PrivateKey(), dp.object.Encrypted)
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
	signKey, err := dp.data.VerificationKey.ToBtcec()
	if err != nil {
		return err
	}
	encKey, err := dp.data.EncryptionKey.ToBtcec()
	if err != nil {
		return err
	}

	header := dp.object.Header()

	// Check if embedded keys correspond to the address used for decryption.
	id := identity.NewPublic(signKey, encKey, dp.data.Pow, header.Version, header.StreamNumber)

	genAddr, _ := id.Address.Encode()
	dencAddr, _ := address.Encode()
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

	if !sig.Verify(hash[:], signKey) { // Try SHA256 first
		if !sig.Verify(sha1hash[:], signKey) { // then SHA1
			return ErrInvalidSignature
		}
	}

	return nil
}

func createDecryptedPubKey(expires time.Time, streamNumber uint64,
	behavior uint32, privID *identity.Private) (*decryptedPubKey, error) {
	addr := &privID.Address

	var tag hash.Sha
	copy(tag[:], addr.Tag())

	dp := &decryptedPubKey{
		object: obj.NewEncryptedPubKey(0, expires, streamNumber, &tag, nil),
		data:   privID.ToPubKeyData(),
	}

	err := dp.signAndEncrypt(privID)
	if err != nil {
		return nil, err
	}

	return dp, nil
}

func newDecryptedPubKey(msg *obj.EncryptedPubKey, address *bmutil.Address) (*decryptedPubKey, error) {
	pk := &decryptedPubKey{
		object: msg,
	}

	return pk, pk.decryptAndVerify(address)
}
