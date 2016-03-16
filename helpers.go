// Originally derived from: btcsuite/btcd/wire/common.go
// Copyright (c) 2013-2015 Conformal Systems LLC.

// Copyright (c) 2015 Monetas
// Copyright 2016 Daniel Krawisz.
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package bmutil

import (
	"crypto/sha512"
)

// Sha512 returns the sha512 of the bytes
func Sha512(b []byte) []byte {
	t := sha512.Sum512(b)
	return t[:]
}

// DoubleSha512 returns the sha512^2 of the bytes
func DoubleSha512(b []byte) []byte {
	return Sha512(Sha512(b))
}
