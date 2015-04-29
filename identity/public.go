// Copyright (c) 2015 Monetas
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package identity

import (
	"errors"
	"math"

	"github.com/btcsuite/btcd/btcec"

	"github.com/monetas/bmutil"
	"github.com/monetas/bmutil/pow"
	"github.com/monetas/bmutil/wire"
)

// Public contains the identity of the remote user, which includes public
// encryption and signing keys, POW parameters and the address that contains
// information about stream number and address version.
type Public struct {
	bmutil.Address
	NonceTrialsPerByte uint64
	ExtraBytes         uint64
	SigningKey         *btcec.PublicKey
	EncryptionKey      *btcec.PublicKey
}

// CreateAddress populates the Address object within the identity based on the
// provided version and stream values and also generates the ripe.
func (id *Public) CreateAddress(version, stream uint64) {
	id.Address.Version = version
	id.Address.Stream = stream
	copy(id.Address.Ripe[:], id.hash())
}

func (id *Public) setDefaultPOWParams() {
	id.NonceTrialsPerByte = pow.DefaultNonceTrialsPerByte
	id.ExtraBytes = pow.DefaultExtraBytes
}

// hash returns the ripemd160 hash used in the address
func (id *Public) hash() []byte {
	return hash_helper(id.SigningKey.SerializeUncompressed(),
		id.EncryptionKey.SerializeUncompressed())
}

// IdentityFromPubKeyMsg generates an *identity.Public object based on a
// wire.MsgPubKey object.
func IdentityFromPubKeyMsg(msg *wire.MsgPubKey) (*Public, error) {
	if msg == nil {
		return nil, errors.New("MsgPubKey is null")
	}
	switch msg.Version {
	case wire.SimplePubKeyVersion, wire.ExtendedPubKeyVersion:
		signingKey, err := msg.SigningKey.ToBtcec()
		if err != nil {
			return nil, err
		}
		encryptionKey, err := msg.EncryptionKey.ToBtcec()
		if err != nil {
			return nil, err
		}

		id := &Public{
			EncryptionKey: encryptionKey,
			SigningKey:    signingKey,
		}
		// set values appropriately; note that Go zero-initializes everything
		// so if version is 2, we should have 0 in msg.ExtraBytes and
		// msg.NonceTrials
		id.ExtraBytes = uint64(math.Max(float64(pow.DefaultExtraBytes),
			float64(msg.ExtraBytes)))
		id.NonceTrialsPerByte = uint64(math.Max(float64(pow.DefaultNonceTrialsPerByte),
			float64(msg.NonceTrials)))
		id.CreateAddress(msg.Version, msg.StreamNumber)

		return id, nil
	}

	// not defined for encrypted pubkey
	return nil, errors.New("unsupported pubkey version")
}
