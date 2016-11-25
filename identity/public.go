// Copyright (c) 2015 Monetas
// Copyright 2016 Daniel Krawisz.
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package identity

import (
	"math"

	"github.com/DanielKrawisz/bmutil"
	"github.com/DanielKrawisz/bmutil/pow"
	"github.com/btcsuite/btcd/btcec"
)

// Public contains the identity of the remote user, which includes public
// encryption and signing keys, POW parameters and the address that contains
// information about stream number and address version.
type Public struct {
	bmutil.Address
	pow.Data
	SigningKey    *btcec.PublicKey
	EncryptionKey *btcec.PublicKey
	Behavior      uint32
}

// CreateAddress populates the Address object within the identity based on the
// provided version and stream values and also generates the ripe.
func (id *Public) CreateAddress(version, stream uint64) {
	id.Address.Version = version
	id.Address.Stream = stream
	copy(id.Address.Ripe[:], id.hash())
}

// hash returns the ripemd160 hash used in the address
func (id *Public) hash() []byte {
	return hashHelper(id.SigningKey.SerializeUncompressed(),
		id.EncryptionKey.SerializeUncompressed())
}

// NewPublic creates and initializes an *identity.Public object.
func NewPublic(signingKey, encryptionKey *btcec.PublicKey, nonceTrials,
	extraBytes, addrVersion, addrStream uint64) *Public {

	id := &Public{
		EncryptionKey: encryptionKey,
		SigningKey:    signingKey,
	}
	// set values appropriately; note that Go zero-initializes everything
	// so if version is 2, we should have 0 in msg.ExtraBytes and
	// msg.NonceTrials
	id.NonceTrialsPerByte = uint64(math.Max(float64(pow.DefaultNonceTrialsPerByte),
		float64(nonceTrials)))
	id.ExtraBytes = uint64(math.Max(float64(pow.DefaultExtraBytes),
		float64(extraBytes)))
	id.CreateAddress(addrVersion, addrStream)

	return id
}
