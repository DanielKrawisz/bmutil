// Copyright 2016 Daniel Krawisz.
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package wire

import (
	"fmt"
	"io"
	"time"

	"github.com/DanielKrawisz/bmutil"
	"github.com/DanielKrawisz/bmutil/pow"
)

// ObjectType represents the type of object than an object message contains.
// Objects in bitmessage are things on the network that get propagated. This can
// include requests/responses for pubkeys, messages and broadcasts.
type ObjectType uint32

// There are five types of objects in bitmessage.
//  - GetPubKey: requests for public keys.
//  - PubKey: public keys sent in response.
//  - Msg: bitmessage messages.
//  - Broadcast: broadcast messages.
// An ObjectType can also take on other values representing unknown message types.
const (
	ObjectTypeGetPubKey ObjectType = 0
	ObjectTypePubKey    ObjectType = 1
	ObjectTypeMsg       ObjectType = 2
	ObjectTypeBroadcast ObjectType = 3
)

// ObjectHeader is a representation of the header of the object message as
// defined in the Bitmessage protocol.
type ObjectHeader struct {
	Nonce        pow.Nonce
	expiration   uint64
	ObjectType   ObjectType
	Version      uint64
	StreamNumber uint64
}

// Expiration provides the expration time.
func (h *ObjectHeader) Expiration() time.Time {
	return time.Unix(int64(h.expiration), 0)
}

// String returns the header in a human-readible string form.
func (h *ObjectHeader) String() string {
	return fmt.Sprintf("header{Nonce: %d, Expiration: %s, Type: %d, Version:%d, Stream: %d}",
		h.Nonce, h.Expiration(), h.ObjectType, h.Version, h.StreamNumber)
}

// EncodeForSigning encodes the object header used for signing.
// It consists of everything in the normal object header except for nonce.
func (h *ObjectHeader) EncodeForSigning(w io.Writer) error {
	err := WriteElements(w, h.expiration, h.ObjectType)
	if err != nil {
		return err
	}
	if err = bmutil.WriteVarInt(w, h.Version); err != nil {
		return err
	}
	if err = bmutil.WriteVarInt(w, h.StreamNumber); err != nil {
		return err
	}
	return nil
}

// Encode encodes the object header to the given writer. Object
// header consists of Nonce, ExpiresTime, ObjectType, Version and Stream, in
// that order. Read Protocol Specifications for more information.
func (h *ObjectHeader) Encode(w io.Writer) error {
	err := h.Nonce.Encode(w)
	if err != nil {
		return err
	}

	return h.EncodeForSigning(w)
}

// DecodeObjectHeader decodes the object header from given reader. Object
// header consists of Nonce, ExpiresTime, ObjectType, Version and Stream, in
// that order. Read Protocol Specifications for more information.
func DecodeObjectHeader(r io.Reader) (*ObjectHeader, error) {
	var header ObjectHeader
	var err error
	header.Nonce, err = pow.DecodeNonce(r)
	if err != nil {
		return nil, err
	}

	err = ReadElements(r, &header.expiration, &header.ObjectType)
	if err != nil {
		return nil, err
	}

	version, err := bmutil.ReadVarInt(r)
	if err != nil {
		return nil, err
	}
	header.Version = version

	streamNumber, err := bmutil.ReadVarInt(r)
	if err != nil {
		return nil, err
	}
	header.StreamNumber = streamNumber

	return &header, nil
}

// NewObjectHeader creates an ObjectHeader from the given parameters.
func NewObjectHeader(
	Nonce pow.Nonce,
	Expiration time.Time,
	ObjectType ObjectType,
	Version uint64,
	StreamNumber uint64) *ObjectHeader {

	return &ObjectHeader{
		Nonce:        Nonce,
		expiration:   uint64(Expiration.Unix()),
		ObjectType:   ObjectType,
		Version:      Version,
		StreamNumber: StreamNumber,
	}
}
