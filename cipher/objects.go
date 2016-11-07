package cipher

import (
	"bytes"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/DanielKrawisz/bmutil"
	"github.com/DanielKrawisz/bmutil/identity"
	"github.com/DanielKrawisz/bmutil/wire"
	"github.com/DanielKrawisz/bmutil/wire/obj"
	"github.com/btcsuite/btcd/btcec"
)

var (
	// ErrUnsupportedOp is returned when the attempted operation is unsupported.
	ErrUnsupportedOp = errors.New("operation unsupported")

	// ErrInvalidSignature is returned when the signature embedded in the
	// message is malformed or fails to verify (because of invalid checksum).
	ErrInvalidSignature = errors.New("invalid signature/verification failed")

	// ErrInvalidIdentity is returned when the provided address/identity is
	// unable to decrypt the given message.
	ErrInvalidIdentity = errors.New("invalid supplied identity/decryption failed")
)

// GeneratePubKey generates a obj.PubKey from the specified private
// identity. It also signs and encrypts it (if necessary) yielding an object
// that only needs proof-of-work to be done on it.
func GeneratePubKey(privID *identity.Private, expiry time.Duration) (*obj.PubKey, error) {
	addr := &privID.Address
	if addr.Version < obj.SimplePubKeyVersion ||
		addr.Version > obj.EncryptedPubKeyVersion {
		return nil, ErrUnsupportedOp
	}
	var signingKey, encKey wire.PubKey
	sk := privID.SigningKey.PubKey().SerializeUncompressed()[1:]
	ek := privID.EncryptionKey.PubKey().SerializeUncompressed()[1:]
	copy(signingKey[:], sk)
	copy(encKey[:], ek)

	var tag wire.ShaHash
	copy(tag[:], addr.Tag())

	msg := obj.NewPubKey(0, time.Now().Add(expiry), addr.Version,
		addr.Stream, privID.Behavior, &signingKey, &encKey,
		privID.NonceTrialsPerByte, privID.ExtraBytes, nil, &tag, nil)
	if addr.Version == obj.SimplePubKeyVersion { // We're done.
		return msg, nil
	}

	// We still need to sign (and encrypt).
	return msg, SignAndEncryptPubKey(msg, privID)
}

// SignAndEncryptPubKey signs and encrypts a PubKey message, populating the
// Signature and Encrypted fields using the provided private identity.
//
// The private identity supplied should be of the sender. There are no checks
// against supplying invalid private identity.
func SignAndEncryptPubKey(msg *obj.PubKey, privID *identity.Private) error {
	if msg.Version < obj.ExtendedPubKeyVersion ||
		msg.Version > obj.EncryptedPubKeyVersion {
		return ErrUnsupportedOp
	}
	// Start signing
	var b bytes.Buffer
	err := msg.EncodeForSigning(&b)
	if err != nil {
		return err
	}

	// Hash
	hash := sha256.Sum256(b.Bytes())
	b.Reset()

	// Sign
	sig, err := privID.SigningKey.Sign(hash[:])
	if err != nil {
		return fmt.Errorf("signing failed: %v", err)
	}
	msg.Signature = sig.Serialize()

	// Start encryption
	if msg.Version != obj.EncryptedPubKeyVersion {
		return nil // Current version doesn't support encryption. We're done!
	}

	err = msg.EncodeForEncryption(&b)
	if err != nil {
		return err
	}

	// Encrypt
	msg.Encrypted, err = btcec.Encrypt(privID.Address.PrivateKey().PubKey(),
		b.Bytes())
	if err != nil {
		return fmt.Errorf("encryption failed: %v", err)
	}

	return nil
}

// SignAndEncryptBroadcast signs and encrypts a Broadcast, populating
// the Signature and Encrypted fields using the provided private identity.
//
// The private identity supplied should be of the sender. There are no checks
// against supplying invalid private identity.
func SignAndEncryptBroadcast(msg *obj.Broadcast, privID *identity.Private) error {
	switch msg.Version {
	case obj.TaglessBroadcastVersion:
		if msg.FromAddressVersion != 2 && msg.FromAddressVersion != 3 {
			// only v2/v3 addresses allowed for tagless broadcast
			return ErrUnsupportedOp
		}
	case obj.TagBroadcastVersion:
		if msg.FromAddressVersion != 4 {
			// only v4 addresses support tags
			return ErrUnsupportedOp
		}
	default:
		return ErrUnsupportedOp
	}

	// Start signing
	var b bytes.Buffer
	err := msg.EncodeForSigning(&b)
	if err != nil {
		return err
	}

	// Hash
	hash := sha256.Sum256(b.Bytes())
	b.Reset()

	// Sign
	sig, err := privID.SigningKey.Sign(hash[:])
	if err != nil {
		return fmt.Errorf("signing failed: %v", err)
	}
	msg.Signature = sig.Serialize()

	// Start encryption
	err = msg.EncodeForEncryption(&b)
	if err != nil {
		return err
	}

	// Encrypt
	switch msg.Version {
	case obj.TaglessBroadcastVersion:
		msg.Encrypted, err = btcec.Encrypt(privID.Address.PrivateKeySingleHash().PubKey(),
			b.Bytes())

	case obj.TagBroadcastVersion:
		msg.Encrypted, err = btcec.Encrypt(privID.Address.PrivateKey().PubKey(),
			b.Bytes())
	}

	if err != nil {
		return fmt.Errorf("encryption failed: %v", err)
	}

	return nil
}

// SignAndEncryptMsg signs and encrypts a obj.Message, populating the
// Signature and Encrypted fields using the provided private identity.
//
// The private identity supplied should be of the sender. The public identity
// should be that of the recipient. There are no checks against supplying
// invalid private or public identities.
func SignAndEncryptMsg(msg *obj.Message, privID *identity.Private,
	pubID *identity.Public) error {
	if msg.Version != 1 {
		return ErrUnsupportedOp
	}

	// Start signing
	var b bytes.Buffer
	err := msg.EncodeForSigning(&b)
	if err != nil {
		return err
	}

	// Hash
	hash := sha256.Sum256(b.Bytes())
	b.Reset()

	// Sign
	sig, err := privID.SigningKey.Sign(hash[:])
	if err != nil {
		return fmt.Errorf("signing failed: %v", err)
	}
	msg.Signature = sig.Serialize()

	// Start encryption
	err = msg.EncodeForEncryption(&b)
	if err != nil {
		return err
	}

	// Encrypt
	msg.Encrypted, err = btcec.Encrypt(pubID.EncryptionKey, b.Bytes())
	if err != nil {
		return fmt.Errorf("encryption failed: %v", err)
	}

	return nil
}

// TryDecryptAndVerifyPubKey tries to decrypt a obj.PubKey of the address.
// If it fails, it returns ErrInvalidIdentity. If decryption succeeds, it
// verifies the embedded signature. If signature verification fails, it returns
// ErrInvalidSignature. Else, it returns nil.
//
// All necessary fields of the provided obj.PubKeyObject are populated.
func TryDecryptAndVerifyPubKey(msg *obj.PubKey, address *bmutil.Address) error {
	version := msg.ObjectHeader.Version
	if version < obj.ExtendedPubKeyVersion ||
		version > obj.EncryptedPubKeyVersion {
		return ErrUnsupportedOp
	}

	// Try decryption if msg.Version == wire.EncryptedPubKeyVersion
	if version == obj.EncryptedPubKeyVersion {
		// Check tag, save decryption cost.
		if subtle.ConstantTimeCompare(msg.Tag[:], address.Tag()) != 1 {
			return ErrInvalidIdentity
		}

		dec, err := btcec.Decrypt(address.PrivateKey(), msg.Encrypted)
		if err == btcec.ErrInvalidMAC { // decryption failed due to invalid key
			return ErrInvalidIdentity
		} else if err != nil { // other reasons
			return err
		}

		err = msg.DecodeFromDecrypted(bytes.NewReader(dec))
		if err != nil {
			return err
		}
	}

	// Verify validity of secp256k1 public keys.
	signKey, err := msg.SigningKey.ToBtcec()
	if err != nil {
		return err
	}
	encKey, err := msg.EncryptionKey.ToBtcec()
	if err != nil {
		return err
	}

	// Check if embedded keys correspond to the address used for decryption.
	if msg.Version == obj.EncryptedPubKeyVersion {
		id := identity.NewPublic(signKey, encKey, msg.NonceTrials,
			msg.ExtraBytes, msg.Version, msg.StreamNumber)

		genAddr, _ := id.Address.Encode()
		dencAddr, _ := address.Encode()
		if dencAddr != genAddr {
			return fmt.Errorf("Address used for decryption (%s) doesn't match "+
				"that generated from public key (%s). Possible surreptitious "+
				"forwarding attack.", dencAddr, genAddr)
		}
	}

	// Start signature verification
	var b bytes.Buffer
	err = msg.EncodeForSigning(&b)
	if err != nil {
		return err
	}

	// Hash
	hash := sha256.Sum256(b.Bytes())
	sha1hash := sha1.Sum(b.Bytes()) // backwards compatibility

	// Verify
	sig, err := btcec.ParseSignature(msg.Signature, btcec.S256())
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

// TryDecryptAndVerifyBroadcast tries to decrypt a wire.BroadcastObject of the
// public identity. If it fails, it returns ErrInvalidIdentity. If decryption
// succeeds, it verifies the embedded signature. If signature verification
// fails, it returns ErrInvalidSignature. Else, it returns nil.
//
// All necessary fields of the provided obj.Broadcast are populated.
func TryDecryptAndVerifyBroadcast(msg *obj.Broadcast, address *bmutil.Address) error {
	var dec []byte
	var err error

	switch msg.Version {
	case obj.TaglessBroadcastVersion:
		dec, err = btcec.Decrypt(address.PrivateKeySingleHash(), msg.Encrypted)
	case obj.TagBroadcastVersion:
		if subtle.ConstantTimeCompare(msg.Tag[:], address.Tag()) != 1 {
			return ErrInvalidIdentity
		}
		dec, err = btcec.Decrypt(address.PrivateKey(), msg.Encrypted)
	default:
		return ErrUnsupportedOp
	}

	if err == btcec.ErrInvalidMAC { // decryption failed due to invalid key
		return ErrInvalidIdentity
	} else if err != nil { // other reasons
		return err
	}

	err = msg.DecodeFromDecrypted(bytes.NewReader(dec))
	if err != nil {
		return err
	}

	// Check if embedded keys correspond to the address used to decrypt.
	signKey, err := msg.SigningKey.ToBtcec()
	if err != nil {
		return err
	}
	encKey, err := msg.EncryptionKey.ToBtcec()
	if err != nil {
		return err
	}
	id := identity.NewPublic(signKey, encKey, msg.NonceTrials,
		msg.ExtraBytes, msg.FromAddressVersion, msg.FromStreamNumber)

	genAddr, _ := id.Address.Encode()
	dencAddr, _ := address.Encode()
	if dencAddr != genAddr {
		return fmt.Errorf("Address used for decryption (%s) doesn't match "+
			"that generated from public key (%s). Possible surreptitious "+
			"forwarding attack.", dencAddr, genAddr)
	}

	// Start signature verification
	var b bytes.Buffer
	err = msg.EncodeForSigning(&b)
	if err != nil {
		return err
	}

	// Hash
	hash := sha256.Sum256(b.Bytes())
	sha1hash := sha1.Sum(b.Bytes()) // backwards compatibility

	// Verify
	sig, err := btcec.ParseSignature(msg.Signature, btcec.S256())
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

// TryDecryptAndVerifyMsg tries to decrypt an obj.Message using the private
// identity. If it fails, it returns ErrInvalidIdentity. If decryption succeeds,
// it verifies the embedded signature. If signature verification fails, it
// returns ErrInvalidSignature. Else, it returns nil.
//
// All necessary fields of the provided wire.Message are populated.
func TryDecryptAndVerifyMsg(msg *obj.Message, privID *identity.Private) error {
	if msg.Version != 1 {
		return ErrUnsupportedOp
	}

	dec, err := btcec.Decrypt(privID.EncryptionKey, msg.Encrypted)

	if err == btcec.ErrInvalidMAC { // decryption failed due to invalid key
		return ErrInvalidIdentity
	} else if err != nil { // other reasons
		return err
	}

	err = msg.DecodeFromDecrypted(bytes.NewReader(dec))
	if err != nil {
		return err
	}

	// Check if embedded destination ripe corresponds to private identity.
	if subtle.ConstantTimeCompare(privID.Address.Ripe[:],
		msg.Destination.Bytes()) != 1 {
		return fmt.Errorf("Decryption succeeded but ripes don't match. Got %s"+
			" expected %s", msg.Destination,
			hex.EncodeToString(privID.Address.Ripe[:]))
	}

	// Start signature verification
	var b bytes.Buffer
	err = msg.EncodeForSigning(&b)
	if err != nil {
		return err
	}

	// Hash
	hash := sha256.Sum256(b.Bytes())
	sha1hash := sha1.Sum(b.Bytes())

	// Verify
	pubSigningKey, err := msg.SigningKey.ToBtcec()
	if err != nil {
		return err
	}

	sig, err := btcec.ParseSignature(msg.Signature, btcec.S256())
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
