// Originally derived from: btcsuite/btcd/wire/invvect_test.go
// Copyright (c) 2013-2015 Conformal Systems LLC.

// Copyright (c) 2015 Monetas
// Copyright 2016 Daniel Krawisz.
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package wire_test

import (
	"bytes"
	"reflect"
	"testing"

	"github.com/DanielKrawisz/bmutil/hash"
	"github.com/DanielKrawisz/bmutil/wire"
	"github.com/davecgh/go-spew/spew"
)

// NewInvVect returns a new InvVect using the provided hash.
func NewInvVect(hash *hash.Sha) *wire.InvVect {
	return (*wire.InvVect)(hash)
}

// TestInvVectWire tests the InvVect wire.encode and decode for various
// protocol versions and supported inventory vector types.
func TestInvVectWire(t *testing.T) {
	// errInvVect is an inventory vector with an error.
	errInvVect := wire.InvVect(hash.Sha{})

	// errInvVectEncoded is the wire.encoded bytes of errInvVect.
	errInvVectEncoded := []byte{
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // No hash
	}

	tests := []struct {
		in  wire.InvVect // NetAddress to encode
		out wire.InvVect // Expected decoded NetAddress
		buf []byte       // Wire encoding
	}{
		// Latest protocol version error inventory vector.
		{
			errInvVect,
			errInvVect,
			errInvVectEncoded,
		},
	}

	t.Logf("Running %d tests", len(tests))
	for i, test := range tests {
		// Encode to wire.format.
		var buf bytes.Buffer
		err := wire.TstWriteInvVect(&buf, &test.in)
		if err != nil {
			t.Errorf("writeInvVect #%d error %v", i, err)
			continue
		}
		if !bytes.Equal(buf.Bytes(), test.buf) {
			t.Errorf("writeInvVect #%d\n got: %s want: %s", i,
				spew.Sdump(buf.Bytes()), spew.Sdump(test.buf))
			continue
		}

		// Decode the message from wire.format.
		var iv wire.InvVect
		rbuf := bytes.NewReader(test.buf)
		err = wire.TstReadInvVect(rbuf, &iv)
		if err != nil {
			t.Errorf("readInvVect #%d error %v", i, err)
			continue
		}
		if !reflect.DeepEqual(iv, test.out) {
			t.Errorf("readInvVect #%d\n got: %s want: %s", i,
				spew.Sdump(iv), spew.Sdump(test.out))
			continue
		}
	}
}
