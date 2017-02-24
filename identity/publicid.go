package identity

import (
	"math"

	. "github.com/DanielKrawisz/bmutil"
	"github.com/DanielKrawisz/bmutil/pow"
	"github.com/DanielKrawisz/bmutil/wire"
	"github.com/DanielKrawisz/bmutil/wire/obj"
)

// BehaviorAck says whether a message to this pubkey should include
// an ack.
const BehaviorAck = 1

// PublicID contains the identity of the remote user, which includes public
// encryption and signing keys, and POW parameters.
type PublicID struct {
	address  *publicAddress
	behavior uint32
	pow      *pow.Data
}

// PublicKey returns the keys in this PublicID
func (id *PublicID) PublicKey() *PublicKey {
	return &id.address.PublicKey
}

// Address returns Address that is derived from this ID
func (id *PublicID) Address() Address {
	return id.address.Address()
}

// PubKeyData turns a PublicID type into PubKeyData type.
func (id *PublicID) PubKeyData() *obj.PubKeyData {
	var verKey, encKey wire.PubKey
	key := id.PublicKey()
	vk := key.Verification.SerializeUncompressed()[1:]
	ek := key.Encryption.SerializeUncompressed()[1:]
	copy(verKey[:], vk)
	copy(encKey[:], ek)

	return &obj.PubKeyData{
		Pow:          id.pow,
		Verification: &verKey,
		Encryption:   &encKey,
		Behavior:     id.behavior,
	}
}

// newPublicID creates and initializes an *identity.Public object.
func newPublicID(address *publicAddress, behavior uint32, data *pow.Data) *PublicID {
	id := PublicID{
		address:  address,
		behavior: behavior,
	}

	// set values appropriately; note that Go zero-initializes everything
	// so if version is 2, we should have 0 in msg.ExtraBytes and
	// msg.NonceTrials
	if data == nil {
		id.pow = &pow.Default
	} else {
		id.pow = &pow.Data{
			NonceTrialsPerByte: uint64(math.Max(float64(pow.DefaultNonceTrialsPerByte),
				float64(data.NonceTrialsPerByte))),
			ExtraBytes: uint64(math.Max(float64(pow.DefaultExtraBytes),
				float64(data.ExtraBytes))),
		}
	}

	return &id
}

// NewPublicID creates and initializes an *identity.PublicID object.
func NewPublicID(public *PublicKey, version, stream uint64, behavior uint32,
	data *pow.Data) (*PublicID, error) {
	address, err := newPublicAddress(public, version, stream)
	if err != nil {
		return nil, err
	}

	return newPublicID(address, behavior, data), nil
}

// NewPublicIDFromWIF creates an *identity.Public object from a PrivateAddress
func NewPublicIDFromWIF(address *PrivateAddress, behavior uint32,
	data *pow.Data) *PublicID {

	return newPublicID(address.public(), behavior, data)
}
