// Copyright (c) 2015 Monetas
// Copyright 2016 Daniel Krawisz.
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package bmutil_test

import (
	"reflect"
	"testing"

	"github.com/DanielKrawisz/bmutil"
)

type addressTestPair struct {
	addrString string
	address    bmutil.Address
}

var addressTests = []addressTestPair{
	{"BM-2cV9RshwouuVKWLBoyH5cghj3kMfw5G7BJ", bmutil.Address{Version: 4,
		Stream: 1, Ripe: [20]byte{0, 118, 97, 129, 167, 56, 98, 210, 144, 213,
			33, 56, 250, 180, 161, 223, 177, 177, 12, 17}}},
	{"BM-2DBXxtaBSV37DsHjN978mRiMbX5rdKNvJ6", bmutil.Address{Version: 3,
		Stream: 1, Ripe: [20]byte{0, 214, 207, 196, 249, 74, 168, 190, 229, 104,
			152, 91, 102, 80, 2, 151, 51, 114, 110, 211}}},
	{"BM-omXeTjutKWmYgQJjmoZjAG3u3NmaLEdZK", bmutil.Address{Version: 2,
		Stream: 1, Ripe: [20]byte{0, 1, 171, 150, 119, 221, 37, 192, 14, 238,
			192, 25, 255, 242, 10, 139, 186, 251, 244, 218}}},
	{"BM-GtovgYdgs7qXPkoYaRgrLFuFKz1SFpsw", bmutil.Address{Version: 3,
		Stream: 1, Ripe: [20]byte{0, 0, 124, 201, 186, 238, 181, 209, 250, 143,
			180, 26, 106, 227, 40, 178, 123, 229, 34, 85}}},
	{"BM-2D7YvqcbRSv2j2zXmamTm4C3XGrTkZqdt3", bmutil.Address{Version: 3,
		Stream: 1, Ripe: [20]byte{0, 21, 243, 247, 60, 104, 72, 169, 139, 195,
			72, 196, 85, 228, 167, 173, 177, 1, 165, 242}}},
}

func TestEncodeAddress(t *testing.T) {
	for _, pair := range addressTests {
		v, err := pair.address.Encode()
		if err != nil {
			t.Error(
				"For", pair.addrString,
				"got error:", err.Error(),
			)
			continue
		}
		if v != pair.addrString {
			t.Error(
				"For", pair.address,
				"expected", pair.addrString,
				"got", v,
			)
		}
	}
}

func TestDecodeAddress(t *testing.T) {
	for _, pair := range addressTests {
		addr, err := bmutil.DecodeAddress(pair.addrString)
		if err != nil {
			t.Error(
				"For", pair.addrString,
				"got error:", err.Error(),
			)
			continue
		}
		if !reflect.DeepEqual(addr, &pair.address) {
			t.Error(
				"For", pair.addrString,
				"expected", pair.address,
				"got", addr,
			)
		}
	}
}

func TestAddressErrors(t *testing.T) {
	// Address.Encode
	addr := bmutil.Address{Version: 1, Stream: 1, Ripe: [20]byte{0, 21, 243,
		247, 60, 104, 72, 169, 139, 195, 72, 196, 85, 228, 167, 173, 177, 1,
		165, 242}}
	str, err := addr.Encode()
	if str != "" {
		t.Error("EncodeAddress: address string due to error not empty")
	}
	if err != bmutil.ErrUnknownAddressType {
		t.Errorf("EncodeAddress: unexpected error, expected UnknownAddressType"+
			" got %v", err)
	}

	// Address.Decode
	decodeAddressErrorAddresses := []string{
		// data too short
		"BM-554ddssdf",
		// checksum mismatch
		"BM-2DBXxtaBSV37DsHjN978mRiMbX5rdKNvJ2",
		// invalid v3 address, ripe length < 18
		"BM-4biUVd9M1g46fES4Ggz8ktmnfoJndYA",
		// invalid v3 address, ripe length > 20
		"BM-QYkxMN39XYE4WtRxHMGNPxLbcv4nWGSRtVdH",
		// invalid v4 address, null bytes in front
		"BM-2cShcu4VoVChUUc9GQnFrJtRe9NdmEoBUq",
		// invalid v4 address, ripe length < 4
		"BM-3xSpfkKJqnFf",
		// invalid v4 address, ripe length > 20
		"BM-YPRfqu7T4fXxxhEfAWCdpebVYRm7mkwr3M4u",
		// invalid address version
		"BM-9tSxgK6q4X6bNdEbyMRgGBcfnFC3MoW3Bp5",
	}

	for i, addr := range decodeAddressErrorAddresses {
		_, err := bmutil.DecodeAddress(addr)
		if err == nil {
			t.Errorf("DecodeAddress: for test #%d expected error got none", i)
		}
	}
}

// Test Tag, PrivateKey and PrivateKeySingleHash
func TestCalcHash(t *testing.T) {
	for _, pair := range addressTests {
		addr, err := bmutil.DecodeAddress(pair.addrString)
		if err != nil {
			t.Errorf("while decoding %s, got error %v", pair.addrString, err)
		}
		// TODO
		addr.PrivateKeySingleHash()
		addr.PrivateKey()
		addr.Tag()
	}
}
