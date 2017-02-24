// Copyright (c) 2015 Monetas
// Copyright 2016 Daniel Krawisz.
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package pow

import (
	"encoding/binary"
	"math"

	"github.com/DanielKrawisz/bmutil/hash"
)

// CalculateTarget calculates the target POW value. payloadLength includes the
// full length of the payload (inluding the width of the initial nonce field).
// ttl is the time difference (in seconds) between ExpiresTime and time.Now().
// Information about nonceTrials and extraBytes can be found at:
// https://bitmessage.org/wiki/Proof_of_work
func CalculateTarget(payloadLength, ttl uint64, data Data) uint64 {
	// All these type conversions are needed for interoperability with Python
	// which casts types back to int after performing division.
	return math.MaxUint64 / (data.NonceTrialsPerByte * (payloadLength + data.ExtraBytes +
		uint64(float64(ttl)*(float64(payloadLength)+float64(data.ExtraBytes))/
			math.Pow(2, 16))))
}

// DoSequential does the PoW sequentially and returns the nonce value.
func DoSequential(target uint64, initialHash []byte) Nonce {
	var nonce uint64
	nonceBytes := make([]byte, 8)
	trialValue := uint64(math.MaxUint64)

	for trialValue > target {
		nonce++
		binary.BigEndian.PutUint64(nonceBytes, nonce)

		resultHash := hash.DoubleSha512(append(nonceBytes, initialHash...))
		trialValue = binary.BigEndian.Uint64(resultHash[:8])
	}
	return Nonce(nonce)
}

// DoParallel does the POW using parallelCount number of goroutines and returns
// the nonce value.
func DoParallel(target uint64, initialHash []byte, parallelCount int) Nonce {
	done := make(chan bool)
	nonceValue := make(chan Nonce, 1)

	for i := 0; i < parallelCount; i++ {
		go func(j int) {
			nonce := uint64(j)
			nonceBytes := make([]byte, 8)
			trialValue := uint64(math.MaxUint64)

			for trialValue > target {
				select {
				case <-done: // some other goroutine already finished
					return
				default:
					nonce += uint64(parallelCount) // increment by parallelCount
					binary.BigEndian.PutUint64(nonceBytes, nonce)

					resultHash := hash.DoubleSha512(append(nonceBytes, initialHash...))
					trialValue = binary.BigEndian.Uint64(resultHash[:8])
				}
			}
			nonceValue <- Nonce(nonce)
			close(done)
		}(i)
	}
	return <-nonceValue
}
