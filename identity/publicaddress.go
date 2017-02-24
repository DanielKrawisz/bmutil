package identity

import (
	. "github.com/DanielKrawisz/bmutil"
)

// publicAddress is a bitmessage address that includes the public keys
// used to derive it.
type publicAddress struct {
	PublicKey
	version uint64
	stream  uint64
}

// address generates an address from the public id.
func (id *publicAddress) address() (Address, error) {
	if id.version < 4 {
		return NewDepricatedAddress(id.version, id.stream, id.Hash())
	}

	return NewAddress(id.version, id.stream, id.Hash())
}

// Address generates an address from the public id. We don't have to
// check for errors because when the publicAddress object is created,
// we checked whether the address was valid.
func (id *publicAddress) Address() Address {
	var a Address
	a, _ = id.address()
	return a
}

// newPublicAddress creates and initializes an *identity.Public object.
func newPublicAddress(public *PublicKey, version, stream uint64) (*publicAddress, error) {

	id := &publicAddress{
		PublicKey: *public,
		version:   version,
		stream:    stream,
	}

	// Check whether the address can be generated without an error.
	_, err := id.address()
	if err != nil {
		return nil, err
	}

	return id, nil
}
