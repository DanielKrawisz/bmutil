// Copyright (c) 2015 Monetas
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package pow

const (
	// If changed, these values will cause particularly unexpected behavior: You
	// won't be able to either send or receive messages because the proof of
	// work you do (or demand) won't match that done or demanded by others.
	// Don't change them!
	//
	// The amount of work that should be performed (and demanded) per byte of
	// the payload.
	DefaultNonceTrialsPerByte = 1000
	// To make sending short messages a little more difficult, this value is
	// added to the payload length for use in calculating the proof of work
	// target.
	DefaultExtraBytes = 1000
)
