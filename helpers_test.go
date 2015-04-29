// Originally derived from: btcsuite/btcd/wire/common.go
// Copyright (c) 2013-2015 Conformal Systems LLC.

// Copyright (c) 2015 Monetas
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package bmutil_test

import (
	"bytes"
	"encoding/hex"
	"testing"

	"github.com/monetas/bmutil"
)

// TestDoubleSha512 checks some test cases for DoubleSha512.
func TestDoubleSha512(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{
			"",
			"826df068457df5dd195b437ab7e7739ff75d2672183f02bb8e1089fabcf97bd9dc80110cf42dbc7cff41c78ecb68d8ba78abe6b5178dea3984df8c55541bf949",
		}, {
			".",
			"4d4da299f2e2b044f8bf0169c7d7141fe27b5642420a1997bc1aeafbd6b1f5502f47a53bb9801748ca332f581fe21d9d588b67f753a31fe8df27baca8e233712",
		}, {
			" ",
			"5cf0a3d5f5465e60ceea891fb3670be6b5d8d9989d811aa7844e938a93c0ea7602639d3db0ceeb63742bc2bfcc476a0b961e2d757f24e3662b3b4ad47fac34d4",
		}, {
			"Jackdaws love my big sphynx of quartz.",
			"1aa604755e9b20b10b4b997ac4d665fda90e0e813f6d6470630b6585b248e1ef6f0915cd735ecf45d12b3af8072843ce241d00a093fe029214e0ec2761fb92c1",
		}, {
			"The quick brown fox jumps over the lazy dog.",
			"363e3c576d54f8ea3d9b6810594ce734607ad04c4cef103c73548a845a183cee09658f9f8f3e44cbb940a2b7767e1002f920ae24de07451ab26263425290c94c",
		},
	}

	for _, test := range tests {
		byteSlice := []byte(test.input)
		result := bmutil.DoubleSha512(byteSlice)
		expected := bmutil.Sha512(bmutil.Sha512(byteSlice))
		if !bytes.Equal(expected, result) {
			t.Errorf("DoubleSha512 fails for case \"%s\" against Sha512: expected %s, got %s", byteSlice, expected, result)
		}
		expected, _ = hex.DecodeString(test.expected)
		if !bytes.Equal(expected, result) {
			t.Errorf("DoubleSha512 fails for case \"%s\" against preset string: expected %s, got %s", byteSlice, expected, result)
		}
	}
}
