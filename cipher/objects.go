package cipher

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"time"

	"github.com/DanielKrawisz/bmutil"
	"github.com/DanielKrawisz/bmutil/hash"
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

	// ErrInvalidObjectType is returned when the given object is not of
	// the expected type.
	ErrInvalidObjectType = errors.New("invalid object type")
)

// GeneratePubKey generates a PubKey from the specified private
// identity. It also signs and encrypts it (if necessary) yielding an object
// that only needs proof-of-work to be done on it.
func GeneratePubKey(privID *identity.PrivateID, expiry time.Duration) (PubKeyObject, error) {

	switch privID.Address().Version() {
	case obj.SimplePubKeyVersion:
		return createSimplePubKey(time.Now().Add(expiry), privID), nil
	case obj.ExtendedPubKeyVersion:
		return createExtendedPubKey(time.Now().Add(expiry), privID)
	case obj.EncryptedPubKeyVersion:
		return createDecryptedPubKey(time.Now().Add(expiry), privID)
	default:
		return nil, ErrUnsupportedOp
	}
}

// TryDecryptAndVerifyPubKey tries to decrypt a wire.PubKeyObject of the address.
// If it fails, it returns ErrInvalidIdentity. If decryption succeeds, it
// verifies the embedded signature. If signature verification fails, it returns
// ErrInvalidSignature. Else, it returns nil.
//
// All necessary fields of the provided wire.PubKeyObject are populated.
func TryDecryptAndVerifyPubKey(msg obj.Object, address bmutil.Address) (PubKeyObject, error) {
	header := msg.Header()

	if header.ObjectType != wire.ObjectTypePubKey {
		return nil, ErrInvalidObjectType
	}

	switch pk := msg.(type) {
	default:
		return nil, obj.ErrInvalidVersion
	case *wire.MsgObject:
		// Re-encode object.
		var buf bytes.Buffer
		pk.Encode(&buf)

		switch header.Version {
		default:
			return nil, obj.ErrInvalidVersion
		case obj.SimplePubKeyVersion:
			spk := &obj.SimplePubKey{}
			spk.Decode(&buf)

			return spk, nil
		case obj.ExtendedPubKeyVersion:
			epk := &obj.ExtendedPubKey{}
			epk.Decode(&buf)

			return newExtendedPubKey(epk)
		case obj.EncryptedPubKeyVersion:
			dpk := &obj.EncryptedPubKey{}
			dpk.Decode(&buf)

			return newDecryptedPubKey(dpk, address)
		}
	case *obj.SimplePubKey:
		return pk, nil
	case *obj.ExtendedPubKey:
		return newExtendedPubKey(pk)
	case *obj.EncryptedPubKey:
		return newDecryptedPubKey(pk, address)
	}
}

// SignAndEncryptBroadcast signs and encrypts a Broadcast, populating
// the Signature and Encrypted fields using the provided private identity.
//
// The private identity supplied should be of the sender. There are no checks
// against supplying invalid private identity.
func SignAndEncryptBroadcast(expiration time.Time,
	msg *Bitmessage, tag *hash.Sha, privID *identity.PrivateID) (*Broadcast, error) {

	version := msg.Public.Address().Version()
	if tag == nil {
		if version != 2 && version != 3 {
			// only v2/v3 addresses allowed for tagless broadcast
			return nil, ErrUnsupportedOp
		}

		return CreateTaglessBroadcast(expiration, msg, privID)
	}

	if version != 4 {
		// only v4 addresses support tags
		return nil, ErrUnsupportedOp
	}

	return CreateTaggedBroadcast(expiration, msg, tag, privID)
}

// TryDecryptAndVerifyBroadcast tries to decrypt a wire.BroadcastObject of the
// public identity. If it fails, it returns ErrInvalidIdentity. If decryption
// succeeds, it verifies the embedded signature. If signature verification
// fails, it returns ErrInvalidSignature. Else, it returns nil.
//
// All necessary fields of the provided wire.BroadcastObject are populated.
func TryDecryptAndVerifyBroadcast(msg obj.Broadcast, address bmutil.Address) (*Broadcast, error) {
	var b bytes.Buffer
	msg.Encode(&b)

	switch b := msg.(type) {
	case *obj.TaglessBroadcast:
		return NewTaglessBroadcast(b, address)
	case *obj.TaggedBroadcast:
		return NewTaggedBroadcast(b, address)
	default:
		return nil, obj.ErrInvalidVersion
	}
}

// SignAndEncryptMessage signs and encrypts a Message, populating the
// Signature and Encrypted fields using the provided private identity.
//
// The private identity supplied should be of the sender. The public identity
// should be that of the recipient. There are no checks against supplying
// invalid private or public identities.
func SignAndEncryptMessage(expiration time.Time, streamNumber uint64,
	bm *Bitmessage, ack []byte, privID *identity.PrivateKey,
	pubID *identity.PublicKey) (*Message, error) {

	if bm.Destination == nil {
		return nil, errors.New("No destination given.")
	}

	tmpMsg := obj.NewMessage(0, expiration, streamNumber, nil)
	message := Message{
		msg: tmpMsg,
		bm:  bm,
		ack: ack,
	}

	// Start signing
	var b bytes.Buffer
	err := message.encodeForSigning(&b)
	if err != nil {
		return nil, err
	}

	// Hash
	hash := sha256.Sum256(b.Bytes())
	b.Reset()

	// Sign
	sig, err := privID.Signing.Sign(hash[:])
	if err != nil {
		return nil, fmt.Errorf("signing failed: %v", err)
	}
	message.sig = sig.Serialize()

	// Start encryption
	err = message.encodeForEncryption(&b)
	if err != nil {
		return nil, err
	}

	// Encrypt
	encrypted, err := btcec.Encrypt(pubID.Encryption.Btcec(), b.Bytes())
	if err != nil {
		return nil, fmt.Errorf("encryption failed: %v", err)
	}

	message.msg = obj.NewMessage(0, expiration, streamNumber, encrypted)

	return &message, nil
}

// TryDecryptAndVerifyMessage tries to decrypt an obj.Message using the private
// identity. If it fails, it returns ErrInvalidIdentity. If decryption succeeds,
// it verifies the embedded signature. If signature verification fails, it
// returns ErrInvalidSignature. Else, it returns nil.
//
// All necessary fields of the provided obj.Message are populated.
func TryDecryptAndVerifyMessage(msg *obj.Message, privID *identity.PrivateID) (*Message, error) {
	if msg.Header().Version != obj.MessageVersion {
		println("Wrong message version: ", msg.Header().Version)
		return nil, ErrUnsupportedOp
	}

	var b bytes.Buffer
	msg.Encode(&b)

	var message obj.Message
	err := message.Decode(&b)
	if err != nil {
		return nil, err
	}

	return NewMessage(&message, privID)
}
