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
func CalculateTarget(payloadLength, ttl uint64, data Data) Target {
	// All these type conversions are needed for interoperability with Python
	// which casts types back to int after performing division.
	return Target(math.MaxUint64 / (data.NonceTrialsPerByte * (payloadLength + data.ExtraBytes +
		uint64(float64(ttl)*(float64(payloadLength)+float64(data.ExtraBytes))/
			math.Pow(2, 16)))))
}

// Check whether the given message and nonce satisfy the given pow target.
func Check(target Target, nonce Nonce, message []byte) bool {
	hashData := make([]byte, 8+len(message))
	copy(hashData[:8], nonce.Bytes())
	copy(hashData[8:], message)
	resultHash := hash.DoubleSha512(hashData)

	powValue := binary.BigEndian.Uint64(resultHash[0:8])

	return powValue <= uint64(target)
}

// DoSequential does the PoW sequentially and returns the nonce value.
func DoSequential(target Target, initialHash []byte) Nonce {
	nonce := uint64(1)
	nonceBytes := make([]byte, 8)
	trialValue := uint64(math.MaxUint64)

	for {
		binary.BigEndian.PutUint64(nonceBytes, nonce)

		resultHash := hash.DoubleSha512(append(nonceBytes, initialHash...))
		trialValue = binary.BigEndian.Uint64(resultHash[:8])

		if trialValue <= uint64(target) {
			return Nonce(nonce)
		}

		nonce++
	}
}

// DoParallel does the POW using parallelCount number of goroutines and returns
// the nonce value.
func DoParallel(target Target, initialHash []byte, parallelCount int) Nonce {
	done := make(chan bool)
	nonceValue := make(chan Nonce, 1)

	for i := 0; i < parallelCount; i++ {
		go func(j int) {
			nonce := uint64(j) + 1
			nonceBytes := make([]byte, 8)
			trialValue := uint64(math.MaxUint64)

			for {
				select {
				case <-done: // some other goroutine already finished
					return
				default:
					binary.BigEndian.PutUint64(nonceBytes, nonce)

					resultHash := hash.DoubleSha512(append(nonceBytes, initialHash...))
					trialValue = binary.BigEndian.Uint64(resultHash[:8])

					if trialValue <= uint64(target) {
						nonceValue <- Nonce(nonce)
						close(done)
					}

					nonce += uint64(parallelCount) // increment by parallelCount
				}
			}
		}(i)
	}
	return <-nonceValue
}
