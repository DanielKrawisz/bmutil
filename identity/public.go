package identity

import (
	"io"

	. "github.com/DanielKrawisz/bmutil"
	"github.com/DanielKrawisz/bmutil/pow"
	"github.com/DanielKrawisz/bmutil/wire/obj"
)

// BehaviorAck says whether a message to this pubkey should include
// an ack.
const BehaviorAck = 1

// Public refers to a public identity.
type Public interface {
	Address() Address
	Key() *PublicKey
	Data() *obj.PubKeyData
	Behavior() uint32
	Pow() *pow.Data
	String() string
}

// Encode serializes the public identity.
func Encode(w io.Writer, pub Public) error {
	var err error
	address := pub.Address()
	if err = WriteVarInt(w, address.Version()); err != nil {
		return err
	}
	if err = WriteVarInt(w, address.Stream()); err != nil {
		return err
	}

	data := pub.Data()
	if address.Version() >= 3 {
		return data.Encode(w)
	}

	return data.EncodeSimple(w)
}

// Decode reads a public identity as a publicID type, which implements Public.
func Decode(r io.Reader) (Public, error) {
	version, err := ReadVarInt(r)
	if err != nil {
		return nil, err
	}

	stream, err := ReadVarInt(r)
	if err != nil {
		return nil, err
	}

	data := &obj.PubKeyData{}
	if version >= 3 {
		err = data.Decode(r)
	} else {
		err = data.DecodeSimple(r)
	}
	if err != nil {
		return nil, err
	}

	pk, err := NewPublicKey(data.Verification, data.Encryption)
	if err != nil {
		return nil, err
	}

	pa, err := newPublicAddress(pk, version, stream)
	if err != nil {
		return nil, err
	}

	return newPublicID(pa, data.Behavior, data.Pow), nil
}

// NewPublic creates and initializes an *identity.PublicID object.
func NewPublic(public *PublicKey, version, stream uint64, behavior uint32,
	data *pow.Data) (Public, error) {
	address, err := newPublicAddress(public, version, stream)
	if err != nil {
		return nil, err
	}

	return newPublicID(address, behavior, data), nil
}

// NewPublicFromWIF creates an *identity.Public object from a PrivateAddress
func NewPublicFromWIF(address *PrivateAddress, behavior uint32,
	data *pow.Data) Public {

	return newPublicID(address.public(), behavior, data)
}
