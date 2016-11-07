// Copyright 2016 Daniel Krawisz.
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package wire

import (
	"io"
	"time"

	"github.com/DanielKrawisz/bmutil"
)

type ObjectHeader struct {
	Nonce        uint64
	ExpiresTime  time.Time
	ObjectType   ObjectType
	Version      uint64
	StreamNumber uint64
}

// Encode encodes the object header to the given writer. Object
// header consists of Nonce, ExpiresTime, ObjectType, Version and Stream, in
// that order. Read Protocol Specifications for more information.
func (h ObjectHeader) Encode(w io.Writer) error {
	err := WriteElements(w, h.Nonce)
	if err != nil {
		return err
	}

	return h.EncodeForSigning(w)
}

// EncodeForSigning encodes the object header used for signing.
// It consists of everything in the normal object header except for nonce.
func (h ObjectHeader) EncodeForSigning(w io.Writer) error {
	err := WriteElements(w, h.ExpiresTime, h.ObjectType)
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

// DecodeMsgObjectHeader decodes the object header from given reader. Object
// header consists of Nonce, ExpiresTime, ObjectType, Version and Stream, in
// that order. Read Protocol Specifications for more information.
func DecodeMsgObjectHeader(r io.Reader) (ObjectHeader, error) {
	var header ObjectHeader
	err := ReadElements(r, &header.Nonce, &header.ExpiresTime, &header.ObjectType)
	if err != nil {
		return header, err
	}

	version, err := bmutil.ReadVarInt(r)
	if err != nil {
		return header, err
	}
	header.Version = version

	streamNumber, err := bmutil.ReadVarInt(r)
	if err != nil {
		return header, err
	}
	header.StreamNumber = streamNumber

	return header, nil
}
