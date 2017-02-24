// Originally derived from: btcsuite/btcd/wire/invvect.go
// Copyright (c) 2013-2015 Conformal Systems LLC.

// Copyright (c) 2015 Monetas
// Copyright 2016 Daniel Krawisz.
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package wire

import (
	"io"

	"github.com/DanielKrawisz/bmutil/hash"
)

const (
	// MaxInvPerMsg is the maximum number of inventory vectors that can be in a
	// single bitmessage inv message.
	MaxInvPerMsg = 50000

	// Maximum payload size for an inventory vector.
	maxInvVectPayload = hash.ShaSize
)

// InvVect defines a bitmessage inventory vector which is used to describe data,
// as specified by the Type field, that a peer wants, has, or does not have to
// another peer.
type InvVect hash.Sha // Hash of the data

// readInvVect reads an encoded InvVect from r depending on the protocol
// version.
func readInvVect(r io.Reader, iv *InvVect) error {
	err := ReadElements(r, (*hash.Sha)(iv))
	if err != nil {
		return err
	}
	return nil
}

// writeInvVect serializes an InvVect to w depending on the protocol version.
func writeInvVect(w io.Writer, iv *InvVect) error {
	err := WriteElements(w, (*hash.Sha)(iv))
	if err != nil {
		return err
	}
	return nil
}
