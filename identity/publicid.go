package identity

import (
	"fmt"
	"math"

	. "github.com/DanielKrawisz/bmutil"
	"github.com/DanielKrawisz/bmutil/pow"
	"github.com/DanielKrawisz/bmutil/wire/obj"
)

// publicID implements the Public interface and contains the identity of
// the remote user, which includes public encryption and signing keys,
// and POW parameters.
type publicID struct {
	address  *publicAddress
	behavior uint32
	pow      *pow.Data
}

func (id *publicID) String() string {
	return fmt.Sprintf("publicid{%s, behavior:%d, %s}", id.address.String(), id.behavior, id.pow.String())
}

// PublicKey returns the keys in this PublicID
func (id *publicID) Key() *PublicKey {
	return &id.address.PublicKey
}

// Address returns Address that is derived from this ID
func (id *publicID) Address() Address {
	return id.address.Address()
}

// Data returns a PubKeyData type.
func (id *publicID) Data() *obj.PubKeyData {
	key := id.Key()

	return &obj.PubKeyData{
		Pow:          id.pow,
		Verification: key.Verification.Wire(),
		Encryption:   key.Encryption.Wire(),
		Behavior:     id.behavior,
	}
}

// Pow returns the pow.Data for this identity.
func (id *publicID) Pow() *pow.Data {
	if id.pow == nil {
		return &pow.Default
	}

	return id.pow
}

// Behavior returns the Behavior value for this id.
func (id *publicID) Behavior() uint32 {
	return id.behavior
}

// newPublicID creates and initializes an *identity.Public object.
func newPublicID(address *publicAddress, behavior uint32, data *pow.Data) *publicID {
	id := publicID{
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
