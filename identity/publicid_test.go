// Copyright (c) 2015 Monetas
// Copyright 2016 Daniel Krawisz.
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package identity_test

import (
	"reflect"
	"testing"

	"github.com/DanielKrawisz/bmutil/identity"
	"github.com/DanielKrawisz/bmutil/pow"
)

func TestNewPublic(t *testing.T) {
	privAddr, err := identity.ImportWIF("BM-2cXm1jokUVp9Nn1kBtkeMjpxaLJuP3FwET",
		"5K3oNuMzVEWdrtyBAZXrPQwQTSmCGrAZS1groRDQVGDeccLim15",
		"5HzhkuimkuizxJyw9b7qnFEMtUrAXD25Y5AV1sZ964dSSXReKnb")
	if err != nil {
		t.Fatal("Could not create ID: ", err)
	}
	behavior := uint32(identity.BehaviorAck)
	data := &pow.Data{
		NonceTrialsPerByte: pow.DefaultNonceTrialsPerByte,
		ExtraBytes:         pow.DefaultExtraBytes,
	}
	id := identity.NewPublicFromWIF(privAddr, behavior, data)
	address := privAddr.Address()
	testId, err := identity.NewPublic(
		privAddr.PublicKey(),
		address.Version(), address.Stream(),
		behavior, data)

	if err != nil {
		t.Errorf("Could not create privateID: %s", err)
	}

	if !reflect.DeepEqual(id, testId) {
		t.Errorf("Created public identity not equal to original.")
	}
}
