// Originally derived from: btcsuite/btcd/wire/common_test.go
// Copyright (c) 2013-2015 Conformal Systems LLC.

// Copyright (c) 2015 Monetas
// Copyright 2016 Daniel Krawisz.
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package bmutil_test

import (
	"bytes"
	"io"
	"strings"
	"testing"

	"github.com/davecgh/go-spew/spew"
	"github.com/DanielKrawisz/bmutil"
)

// MaxMessagePayload is used for testing ReadVarString and ReadVarBytes, to
// ensure that not more than this many bytes are read.
const maxMessagePayload = 1600100

// TestVarIntWire tests encode and decode for variable length integers.
func TestVarIntWire(t *testing.T) {
	tests := []struct {
		in  uint64 // Value to encode
		out uint64 // Expected decoded value
		buf []byte // Wire encoding
	}{
		// Latest protocol version.
		// Single byte
		{0, 0, []byte{0x00}},
		// Max single byte
		{0xfc, 0xfc, []byte{0xfc}},
		// Min 2-byte
		{0xfd, 0xfd, []byte{0xfd, 0x00, 0xfd}},
		// Max 2-byte
		{0xffff, 0xffff, []byte{0xfd, 0xff, 0xff}},
		// Min 4-byte
		{0x10000, 0x10000, []byte{0xfe, 0x00, 0x01, 0x00, 0x00}},
		// Max 4-byte
		{0xffffffff, 0xffffffff, []byte{0xfe, 0xff, 0xff, 0xff, 0xff}},
		// Min 8-byte
		{
			0x100000000, 0x100000000,
			[]byte{0xff, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00},
		},
		// Max 8-byte
		{
			0xffffffffffffffff, 0xffffffffffffffff,
			[]byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
		},
	}

	t.Logf("Running %d tests", len(tests))
	for i, test := range tests {
		// Encode
		var buf bytes.Buffer
		err := bmutil.WriteVarInt(&buf, test.in)
		if err != nil {
			t.Errorf("WriteVarInt #%d error %v", i, err)
			continue
		}
		if !bytes.Equal(buf.Bytes(), test.buf) {
			t.Errorf("WriteVarInt #%d\n got: %s want: %s", i,
				spew.Sdump(buf.Bytes()), spew.Sdump(test.buf))
			continue
		}

		// Decode
		rbuf := bytes.NewReader(test.buf)
		val, err := bmutil.ReadVarInt(rbuf)
		if err != nil {
			t.Errorf("ReadVarInt #%d error %v", i, err)
			continue
		}
		if val != test.out {
			t.Errorf("ReadVarInt #%d\n got: %d want: %d", i,
				val, test.out)
			continue
		}
	}
}

// TestVarIntWireErrors performs negative tests against encode and decode
// of variable length integers to confirm error paths work correctly.
func TestVarIntWireErrors(t *testing.T) {
	tests := []struct {
		in       uint64 // Value to encode
		buf      []byte // Wire encoding
		max      int    // Max size of fixed buffer to induce errors
		writeErr error  // Expected write error
		readErr  error  // Expected read error
	}{
		// Force errors on discriminant.
		{0, []byte{0x00}, 0, io.ErrShortWrite, io.EOF},
		// Force errors on 2-byte read/write.
		{0xfd, []byte{0xfd}, 2, io.ErrShortWrite, io.ErrUnexpectedEOF},
		// Force errors on 4-byte read/write.
		{0x10000, []byte{0xfe}, 2, io.ErrShortWrite, io.ErrUnexpectedEOF},
		// Force errors on 8-byte read/write.
		{0x100000000, []byte{0xff}, 2, io.ErrShortWrite, io.ErrUnexpectedEOF},
	}

	t.Logf("Running %d tests", len(tests))
	for i, test := range tests {
		// Encode
		w := newFixedWriter(test.max)
		err := bmutil.WriteVarInt(w, test.in)
		if err != test.writeErr {
			t.Errorf("WriteVarInt #%d wrong error got: %v, want: %v",
				i, err, test.writeErr)
			continue
		}

		// Decode from wire.format.
		r := newFixedReader(test.max, test.buf)
		_, err = bmutil.ReadVarInt(r)
		if err != test.readErr {
			t.Errorf("ReadVarInt #%d wrong error got: %v, want: %v",
				i, err, test.readErr)
			continue
		}
	}
}

// TestVarIntWire tests the serialize size for variable length integers.
func TestVarIntSerializeSize(t *testing.T) {
	tests := []struct {
		val  uint64 // Value to get the serialized size for
		size int    // Expected serialized size
	}{
		// Single byte
		{0, 1},
		// Max single byte
		{0xfc, 1},
		// Min 2-byte
		{0xfd, 3},
		// Max 2-byte
		{0xffff, 3},
		// Min 4-byte
		{0x10000, 5},
		// Max 4-byte
		{0xffffffff, 5},
		// Min 8-byte
		{0x100000000, 9},
		// Max 8-byte
		{0xffffffffffffffff, 9},
	}

	t.Logf("Running %d tests", len(tests))
	for i, test := range tests {
		serializedSize := bmutil.VarIntSerializeSize(test.val)
		if serializedSize != test.size {
			t.Errorf("VarIntSerializeSize #%d got: %d, want: %d", i,
				serializedSize, test.size)
			continue
		}
	}
}

// TestVarStringWire tests encode and decode for variable length strings.
func TestVarStringWire(t *testing.T) {
	// str256 is a string that takes a 2-byte varint to encode.
	str256 := strings.Repeat("test", 64)

	tests := []struct {
		in  string // String to encode
		out string // String to decoded value
		buf []byte // Wire encoding
	}{
		// Latest protocol version.
		// Empty string
		{"", "", []byte{0x00}},
		// Single byte varint + string
		{"Test", "Test", append([]byte{0x04}, []byte("Test")...)},
		// 2-byte varint + string
		{str256, str256, append([]byte{0xfd, 0x01, 0x00}, []byte(str256)...)},
	}

	t.Logf("Running %d tests", len(tests))
	for i, test := range tests {
		// Encode
		var buf bytes.Buffer
		err := bmutil.WriteVarString(&buf, test.in)
		if err != nil {
			t.Errorf("WriteVarString #%d error %v", i, err)
			continue
		}
		if !bytes.Equal(buf.Bytes(), test.buf) {
			t.Errorf("WriteVarString #%d\n got: %s want: %s", i,
				spew.Sdump(buf.Bytes()), spew.Sdump(test.buf))
			continue
		}

		// Decode
		rbuf := bytes.NewReader(test.buf)
		val, err := bmutil.ReadVarString(rbuf, maxMessagePayload)
		if err != nil {
			t.Errorf("ReadVarString #%d error %v", i, err)
			continue
		}
		if val != test.out {
			t.Errorf("ReadVarString #%d\n got: %s want: %s", i,
				val, test.out)
			continue
		}
	}
}

// TestVarStringWireErrors performs negative tests against encode and
// decode of variable length strings to confirm error paths work correctly.
func TestVarStringWireErrors(t *testing.T) {
	// str256 is a string that takes a 2-byte varint to encode.
	str256 := strings.Repeat("test", 64)

	tests := []struct {
		in       string // Value to encode
		buf      []byte // Wire encoding
		max      int    // Max size of fixed buffer to induce errors
		writeErr error  // Expected write error
		readErr  error  // Expected read error
	}{
		// Latest protocol version with intentional read/write errors.
		// Force errors on empty string.
		{"", []byte{0x00}, 0, io.ErrShortWrite, io.EOF},
		// Force error on single byte varint + string.
		{"Test", []byte{0x04}, 2, io.ErrShortWrite, io.ErrUnexpectedEOF},
		// Force errors on 2-byte varint + string.
		{str256, []byte{0xfd}, 2, io.ErrShortWrite, io.ErrUnexpectedEOF},
	}

	t.Logf("Running %d tests", len(tests))
	for i, test := range tests {
		// Encode
		w := newFixedWriter(test.max)
		err := bmutil.WriteVarString(w, test.in)
		if err != test.writeErr {
			t.Errorf("WriteVarString #%d wrong error got: %v, want: %v",
				i, err, test.writeErr)
			continue
		}

		// Decode
		r := newFixedReader(test.max, test.buf)
		_, err = bmutil.ReadVarString(r, maxMessagePayload)
		if err != test.readErr {
			t.Errorf("ReadVarString #%d wrong error got: %v, want: %v",
				i, err, test.readErr)
			continue
		}
	}
}

// TestVarStringOverflowErrors performs tests to ensure deserializing variable
// length strings intentionally crafted to use large values for the string
// length are handled properly. This could otherwise potentially be used as an
// attack vector.
func TestVarStringOverflowErrors(t *testing.T) {
	tests := []struct {
		buf []byte // Wire encoding
	}{
		{[]byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}},
		{[]byte{0xff, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}},
	}

	t.Logf("Running %d tests", len(tests))
	for i, test := range tests {
		// Decode
		rbuf := bytes.NewReader(test.buf)
		_, err := bmutil.ReadVarString(rbuf, maxMessagePayload)
		if err == nil {
			t.Errorf("ReadVarString #%d got no error", i)
			continue
		}
	}

}

// TestVarBytesWire tests encode and decode for variable length byte array.
func TestVarBytesWire(t *testing.T) {
	// bytes256 is a byte array that takes a 2-byte varint to encode.
	bytes256 := bytes.Repeat([]byte{0x01}, 256)

	tests := []struct {
		in  []byte // Byte Array to write
		buf []byte // Wire encoding
	}{
		// Empty byte array
		{[]byte{}, []byte{0x00}},
		// Single byte varint + byte array
		{[]byte{0x01}, []byte{0x01, 0x01}},
		// 2-byte varint + byte array
		{bytes256, append([]byte{0xfd, 0x01, 0x00}, bytes256...)},
	}

	t.Logf("Running %d tests", len(tests))
	for i, test := range tests {
		// Encode
		var buf bytes.Buffer
		err := bmutil.WriteVarBytes(&buf, test.in)
		if err != nil {
			t.Errorf("WriteVarBytes #%d error %v", i, err)
			continue
		}
		if !bytes.Equal(buf.Bytes(), test.buf) {
			t.Errorf("WriteVarBytes #%d\n got: %s want: %s", i,
				spew.Sdump(buf.Bytes()), spew.Sdump(test.buf))
			continue
		}

		// Decode
		rbuf := bytes.NewReader(test.buf)
		val, err := bmutil.ReadVarBytes(rbuf,
			maxMessagePayload, "test payload")
		if err != nil {
			t.Errorf("ReadVarBytes #%d error %v", i, err)
			continue
		}
		if !bytes.Equal(buf.Bytes(), test.buf) {
			t.Errorf("ReadVarBytes #%d\n got: %s want: %s", i,
				val, test.buf)
			continue
		}
	}
}

// TestVarBytesWireErrors performs negative tests against wire.encode and
// decode of variable length byte arrays to confirm error paths work correctly.
func TestVarBytesWireErrors(t *testing.T) {
	// bytes256 is a byte array that takes a 2-byte varint to encode.
	bytes256 := bytes.Repeat([]byte{0x01}, 256)

	tests := []struct {
		in       []byte // Byte Array to write
		buf      []byte // Wire encoding
		max      int    // Max size of fixed buffer to induce errors
		writeErr error  // Expected write error
		readErr  error  // Expected read error
	}{
		// Latest protocol version with intentional read/write errors.
		// Force errors on empty byte array.
		{[]byte{}, []byte{0x00}, 0, io.ErrShortWrite, io.EOF},
		// Force error on single byte varint + byte array.
		{[]byte{0x01, 0x02, 0x03}, []byte{0x04}, 2, io.ErrShortWrite, io.ErrUnexpectedEOF},
		// Force errors on 2-byte varint + byte array.
		{bytes256, []byte{0xfd}, 2, io.ErrShortWrite, io.ErrUnexpectedEOF},
	}

	t.Logf("Running %d tests", len(tests))
	for i, test := range tests {
		// Encode
		w := newFixedWriter(test.max)
		err := bmutil.WriteVarBytes(w, test.in)
		if err != test.writeErr {
			t.Errorf("WriteVarBytes #%d wrong error got: %v, want: %v",
				i, err, test.writeErr)
			continue
		}

		// Decode
		r := newFixedReader(test.max, test.buf)
		_, err = bmutil.ReadVarBytes(r,
			maxMessagePayload, "test payload")
		if err != test.readErr {
			t.Errorf("ReadVarBytes #%d wrong error got: %v, want: %v",
				i, err, test.readErr)
			continue
		}
	}
}

// TestVarBytesOverflowErrors performs tests to ensure deserializing variable
// length byte arrays intentionally crafted to use large values for the array
// length are handled properly. This could otherwise potentially be used as an
// attack vector.
func TestVarBytesOverflowErrors(t *testing.T) {
	tests := []struct {
		buf []byte // Wire encoding
	}{
		{[]byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}},
		{[]byte{0xff, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}},
	}

	t.Logf("Running %d tests", len(tests))
	for i, test := range tests {
		// Decode
		rbuf := bytes.NewReader(test.buf)
		_, err := bmutil.ReadVarBytes(rbuf,
			maxMessagePayload, "test payload")
		if err == nil {
			t.Errorf("ReadVarBytes #%d got no error ", i)
			continue
		}
	}
}
