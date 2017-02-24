package identity

import (
	"github.com/DanielKrawisz/bmutil/pow"
	"github.com/DanielKrawisz/bmutil/wire/obj"
)

// PrivateID contains the identity of the user, which includes private encryption
// and signing keys, and POW parameters.
type PrivateID struct {
	PrivateAddress
	behavior uint32
	pow      *pow.Data
}

// Public turns a Private identity object into Public identity object.
func (id *PrivateID) Public() *PublicID {
	return &PublicID{
		address:  id.PrivateAddress.public(),
		pow:      id.pow,
		behavior: id.behavior,
	}
}

// PubKeyData turns a PrivateID type into PubKeyData type.
func (id *PrivateID) PubKeyData() *obj.PubKeyData {
	return id.Public().PubKeyData()
}

// Pow returns the pow.Data for this identity.
func (id *PrivateID) Pow() *pow.Data {
	if id.pow == nil {
		return &pow.Default
	}

	return id.pow
}

// Behavior returns the Behavior value for this id.
func (id *PrivateID) Behavior() uint32 {
	return id.behavior
}

// NewPrivateID constructs a PrivateID.
func NewPrivateID(id *PrivateAddress, behavior uint32, data *pow.Data) *PrivateID {
	return &PrivateID{
		PrivateAddress: *id,
		behavior:       behavior,
		pow:            data,
	}
}
