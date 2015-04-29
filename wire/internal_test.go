// Originally derived from: btcsuite/btcd/wire/internal_test.go
// Copyright (c) 2013-2015 Conformal Systems LLC.

// Copyright (c) 2015 Monetas
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

/*
This test file is part of the wire.package rather than than the wire.test
package so it can bridge access to the internals to properly test cases which
are either not possible or can't reliably be tested via the public interface.
The functions are only exported while the tests are being run.
*/

package wire

import (
	"io"
)

// TstRandomUint64 makes the internal randomUint64 function available to the
// test package.
func TstRandomUint64(r io.Reader) (uint64, error) {
	return randomUint64(r)
}

// TstReadElement makes the internal readElement function available to the
// test package.
func TstReadElement(r io.Reader, element interface{}) error {
	return readElement(r, element)
}

// TstWriteElement makes the internal writeElement function available to the
// test package.
func TstWriteElement(w io.Writer, element interface{}) error {
	return writeElement(w, element)
}

// TstReadNetAddress makes the internal readNetAddress function available to
// the test package.
func TstReadNetAddress(r io.Reader, na *NetAddress, ts bool) error {
	return readNetAddress(r, na, ts)
}

// TstWriteNetAddress makes the internal writeNetAddress function available to
// the test package.
func TstWriteNetAddress(w io.Writer, na *NetAddress, ts bool) error {
	return writeNetAddress(w, na, ts)
}

// TstMaxNetAddressPayload makes the internal maxNetAddressPayload function
// available to the test package.
func TstMaxNetAddressPayload() int {
	return maxNetAddressPayload()
}

// TstReadInvVect makes the internal readInvVect function available to the test
// package.
func TstReadInvVect(r io.Reader, iv *InvVect) error {
	return readInvVect(r, iv)
}

// TstWriteInvVect makes the internal writeInvVect function available to the
// test package.
func TstWriteInvVect(w io.Writer, iv *InvVect) error {
	return writeInvVect(w, iv)
}

// TstDiscardInput makes the internal discardInput function available
// to the test package.
func TstDiscardInput(r io.Reader, n uint32) {
	discardInput(r, n)
}
