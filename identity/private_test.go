// Copyright (c) 2015 Monetas
// Copyright 2016 Daniel Krawisz.
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package identity_test

import (
	"fmt"
	"testing"

	. "github.com/DanielKrawisz/bmutil"
	. "github.com/DanielKrawisz/bmutil/identity"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcutil/hdkeychain"
)

// Just check if generation of random address was successful
func TestNewRandom(t *testing.T) {
	// At least one zero in the beginning
	_, err := NewRandom(0)
	if err == nil {
		t.Error("for requiredZeros=0 expected error got none")
	}
	v, err := NewRandom(1)
	if err != nil {
		t.Error(err)
		return
	}
	signingkey, encryptionkey := v.ExportWIF()
	fmt.Println("Signing Key:", signingkey)
	fmt.Println("Encryption Key:", encryptionkey)
}

type deterministicAddressTest struct {
	passphrase string
	address    []string
}

var deterministicAddressTests = []deterministicAddressTest{
	{"hello", []string{"BM-2DB6AzjZvzM8NkS3HMYWMP9R1Rt778mhN8"}},
	{"general", []string{"BM-2DAV89w336ovy6BUJnfVRD5B9qipFbRgmr"}},
	{"privacy", []string{"BM-2D8hw9EzzMMJUYV44txMFqbtq3T7MCvyz7"}},
	{"news", []string{"BM-2D8ZrxtSU1jf7nnfvqVwRfCVh1Q8NW4td5"}},
	{"PHP", []string{"BM-2cUvgm9ScCJxig3cAkwNzD5iEw3rKJ7NeG"}},
	{"bmd123", []string{"BM-2cWezCUSS3RCs97RRoxpDTGSyBqpyBMicp",
		"BM-2cXr5HesNSa35SjpZN7usUCV19zy97LTtu",
		"BM-2cXLvxvcnRjmQMgsktFqzwkd69mhC7kzgz"}},
}

func TestNewDeterministic(t *testing.T) {
	for _, pair := range deterministicAddressTests {
		keys, err := NewDeterministic(pair.passphrase, 1, len(pair.address))

		if err != nil {
			t.Error(
				"for", pair.passphrase,
				"got error:", err.Error(),
			)
			continue
		}
		// Check to see if all IDs were generated correctly.
		for i, key := range keys {
			// Make sure to generate address of same version and stream
			addr, _ := DecodeAddress(pair.address[i])
			address := NewPrivateAddress(key, addr.Version(), addr.Stream()).Address().String()
			if address != pair.address[i] {
				t.Errorf("for passphrase %s #%d got %s expected %s",
					pair.passphrase, i, address, pair.address[i],
				)
			}
		}
	}
}

func TestNewHD(t *testing.T) {
	seed := []byte("somegoodrandomseedwouldbeusefulhere")

	masterKey, err := hdkeychain.NewMaster(seed, &chaincfg.MainNetParams)
	if err != nil {
		t.Fatal(err)
	}

	pvt, err := NewHD(masterKey, 0, DefaultStream)
	if err != nil {
		t.Fatal(err)
	}

	addr, _ := NewAddress(DefaultAddressVersion, DefaultStream, pvt.Hash())
	addrStr := addr.String()
	expectedAddr := "BM-2cUqid7xty9zteYmu7aKxYiDTzL4k5YYn7"
	if addrStr != expectedAddr {
		t.Errorf("invalid address, expected %s got %s", expectedAddr, addr)
	}

	// TODO add more test cases with key derivations
}

func TestNewDeterministicErrors(t *testing.T) {
	// NewDeterministic
	_, err := NewDeterministic("abcabc", 0, 1) // 0 initial zeros
	if err == nil {
		t.Error("NewDeterministic: 0 initial zeros, got no error")
	}
}
