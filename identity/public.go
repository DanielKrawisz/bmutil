// Copyright (c) 2015 Monetas
// Copyright 2016 Daniel Krawisz.
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package identity

import (
	"math"

	"github.com/DanielKrawisz/bmutil"
	"github.com/DanielKrawisz/bmutil/hash"
	"github.com/DanielKrawisz/bmutil/pow"
	"github.com/btcsuite/btcd/btcec"
)

// Public contains the identity of the remote user, which includes public
// encryption and signing keys, POW parameters and the address that contains
// information about stream number and address version.
type Public struct {
	address bmutil.Address
	pow.Data
	VerificationKey *btcec.PublicKey
	EncryptionKey   *btcec.PublicKey
	Behavior        uint32
}

// createAddress populates the Address object within the identity based on the
// provided version and stream values and also generates the ripe.
func createAddress(version, stream uint64, ripe []byte) (bmutil.Address, error) {
	r, err := hash.NewRipe(ripe)
	if err != nil {
		return nil, err
	}

	if version < 4 {
		return bmutil.NewDepricatedAddress(version, stream, r)
	}

	return bmutil.NewAddress(version, stream, r)
}

// hash returns the ripemd160 hash used in the address
func (id *Public) hash() []byte {
	return hashHelper(id.VerificationKey.SerializeUncompressed(),
		id.EncryptionKey.SerializeUncompressed())
}

// Address returns the address of the id.
func (id *Public) Address() bmutil.Address {
	return id.address
}

// NewPublic creates and initializes an *identity.Public object.
func NewPublic(verificationKey, encryptionKey *btcec.PublicKey, behavior uint32,
	data *pow.Data, addrVersion, addrStream uint64) (*Public, error) {

	id := &Public{
		EncryptionKey:   encryptionKey,
		VerificationKey: verificationKey,
	}
	// set values appropriately; note that Go zero-initializes everything
	// so if version is 2, we should have 0 in msg.ExtraBytes and
	// msg.NonceTrials
	if data == nil {
		id.NonceTrialsPerByte = pow.DefaultNonceTrialsPerByte
		id.ExtraBytes = pow.DefaultExtraBytes
	} else {
		id.NonceTrialsPerByte = uint64(math.Max(float64(pow.DefaultNonceTrialsPerByte),
			float64(data.NonceTrialsPerByte)))
		id.ExtraBytes = uint64(math.Max(float64(pow.DefaultExtraBytes),
			float64(data.ExtraBytes)))
	}

	var err error
	id.address, err = createAddress(addrVersion, addrStream, id.hash())
	if err != nil {
		return nil, err
	}

	return id, nil
}
