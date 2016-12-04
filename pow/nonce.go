// Copyright (c) 2016 Daniel Krawisz.
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package pow

import (
	"encoding/binary"
	"io"
)

// Nonce represents a number at the head of an object message which
// is used for the proof of work.
type Nonce uint64

// Bytes returns the nonce as a bite array, as specified by the Bitmessage
// protocol.
func (n Nonce) Bytes() []byte {
	nonceBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(nonceBytes, uint64(n))
	return nonceBytes
}

// Encode encodes a nonce to a writer.
func (n Nonce) Encode(w io.Writer) error {
	_, err := w.Write(n.Bytes())
	if err != nil {
		return err
	}
	return nil
}

// Decode decodes a nonce from a reader.
func DecodeNonce(r io.Reader) (Nonce, error) {
	var b [8]byte
	_, err := io.ReadFull(r, b[:])
	if err != nil {
		return 0, err
	}
	return Nonce(binary.BigEndian.Uint64(b[:])), nil
}
