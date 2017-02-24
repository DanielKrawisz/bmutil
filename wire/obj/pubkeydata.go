package obj

import (
	"fmt"
	"io"

	"github.com/DanielKrawisz/bmutil/pow"
	"github.com/DanielKrawisz/bmutil/wire"
)

// PubKeyData contains the information that is transmitted in a PubKey object.
type PubKeyData struct {
	Behavior     uint32
	Verification *wire.PubKey
	Encryption   *wire.PubKey
	Pow          *pow.Data
}

// EncodeSimple encodes the PubKeyData to a writer according to the format
// for a SimplePubKey.
func (pk *PubKeyData) EncodeSimple(w io.Writer) error {
	return wire.WriteElements(w, pk.Behavior, pk.Verification, pk.Encryption)
}

// Encode encodes the PubKeyData to a writer.
func (pk *PubKeyData) Encode(w io.Writer) error {
	if err := pk.EncodeSimple(w); err != nil {
		return err
	}

	if pk.Pow != nil {
		err := pk.Pow.Encode(w)
		if err != nil {
			return err
		}
	}

	return nil
}

// DecodeSimple decodes a PubKeyData according to the simpler, original
// format for PubKey objects.
func (pk *PubKeyData) DecodeSimple(r io.Reader) error {
	pk.Verification = &wire.PubKey{}
	pk.Encryption = &wire.PubKey{}
	return wire.ReadElements(r, &pk.Behavior, pk.Verification, pk.Encryption)
}

// Decode decodes a PubKeyData from a reader.
func (pk *PubKeyData) Decode(r io.Reader) error {
	err := pk.DecodeSimple(r)
	if err != nil {
		return err
	}

	pk.Pow = &pow.Data{}
	return pk.Pow.Decode(r)
}

// String creates a human-readible string of a PubKeyData.
func (pk *PubKeyData) String() string {
	str := fmt.Sprintf("{Behavior: %d, VerificationKey: %s, EncryptionKey: %s",
		pk.Behavior, pk.Verification.String(), pk.Encryption.String())

	if pk.Pow != nil {
		str += ", " + pk.Pow.String()
	}

	return str + "}"
}
