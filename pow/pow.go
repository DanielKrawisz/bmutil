// Copyright (c) 2015 Monetas
// Copyright 2016 Daniel Krawisz.
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package pow

import (
	"encoding/binary"
	"math"
	"time"

	"github.com/DanielKrawisz/bmutil"
	"github.com/DanielKrawisz/bmutil/wire"
)

// CalculateTarget calculates the target POW value. payloadLength includes the
// full length of the payload (inluding the width of the initial nonce field).
// ttl is the time difference (in seconds) between ExpiresTime and time.Now().
// Information about nonceTrials and extraBytes can be found at:
// https://bitmessage.org/wiki/Proof_of_work
func CalculateTarget(payloadLength, ttl, nonceTrials,
	extraBytes uint64) uint64 {
	// All these type conversions are needed for interoperability with Python
	// which casts types back to int after performing division.
	return math.MaxUint64 / (nonceTrials * (payloadLength + extraBytes +
		uint64(float64(ttl)*(float64(payloadLength)+float64(extraBytes))/
			math.Pow(2, 16))))
}

// Check checks if the POW that was done for an object message is sufficient.
// obj is a byte slice containing the object message.
func Check(msg *wire.MsgObject, extraBytes, nonceTrials uint64, refTime time.Time) bool {
	// calculate ttl from bytes 8-16 that contain ExpiresTime
	ttl := uint64(msg.ExpiresTime.Unix() - refTime.Unix())

	obj := wire.EncodeMessage(msg)
	msgHash := bmutil.Sha512(obj[8:]) // exclude nonce value in the beginning
	payloadLength := uint64(len(obj))

	hashData := make([]byte, 8+len(msgHash))
	copy(hashData[:8], obj[:8]) // nonce
	copy(hashData[8:], msgHash)
	resultHash := bmutil.DoubleSha512(hashData)

	powValue := binary.BigEndian.Uint64(resultHash[0:8])

	target := CalculateTarget(payloadLength, ttl, extraBytes,
		nonceTrials)

	return powValue <= target
}

// DoSequential does the PoW sequentially and returns the nonce value.
func DoSequential(target uint64, initialHash []byte) uint64 {
	var nonce uint64
	nonceBytes := make([]byte, 8)
	var trialValue uint64 = math.MaxUint64

	for trialValue > target {
		nonce++
		binary.BigEndian.PutUint64(nonceBytes, nonce)

		resultHash := bmutil.DoubleSha512(append(nonceBytes, initialHash...))
		trialValue = binary.BigEndian.Uint64(resultHash[:8])
	}
	return nonce
}

// DoParallel does the POW using parallelCount number of goroutines and returns
// the nonce value.
func DoParallel(target uint64, initialHash []byte, parallelCount int) uint64 {
	done := make(chan bool)
	nonceValue := make(chan uint64, 1)

	for i := 0; i < parallelCount; i++ {
		go func(j int) {
			nonce := uint64(j)
			nonceBytes := make([]byte, 8)
			var trialValue uint64 = math.MaxUint64

			for trialValue > target {
				select {
				case <-done: // some other goroutine already finished
					return
				default:
					nonce += uint64(parallelCount) // increment by parallelCount
					binary.BigEndian.PutUint64(nonceBytes, nonce)

					resultHash := bmutil.DoubleSha512(append(nonceBytes, initialHash...))
					trialValue = binary.BigEndian.Uint64(resultHash[:8])
				}
			}
			nonceValue <- nonce
			close(done)
		}(i)
	}
	return <-nonceValue
}
