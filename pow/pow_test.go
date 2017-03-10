// Copyright (c) 2015 Monetas
// Copyright 2016 Daniel Krawisz.
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package pow_test

import (
	"encoding/hex"
	"runtime"
	"testing"

	"github.com/DanielKrawisz/bmutil/pow"
)

const (
	nonceTrials = 1000
	extraBytes  = 1000
)

var data pow.Data = pow.Data{
	NonceTrialsPerByte: nonceTrials,
	ExtraBytes:         extraBytes,
}

func TestCalculateTarget(t *testing.T) {
	type test struct {
		payloadLen  uint64
		ttl         uint64
		targetValue uint64
	}

	// Calculated using Python code
	var tests = []test{
		{3402, 60 * 60 * 24 * 5, 551983724040},
		{563421, 60 * 60 * 24 * 28, 862017809},
		{87996, 60 * 60 * 24 * 90, 1732319784},
		{478622, 60 * 60 * 24 * 45, 637550899},
		{100, 10000, 14559387587773},
		{512, 124598, 4205824002213},
		{5489, 217856, 657426995748},
		{223848, 89471, 34686458185},
		{1543, 5466, 6695732876119},
		{241, 88965, 6306579170498},
		{1000320, 2419200, 485899565},
		{654896, 2419200, 741795910},
		{54563213, 24192000, 913366},
		{24, 500, 17892089305246},
		{24, 30, 18014398509481},
	}

	for n, tc := range tests {
		target := pow.CalculateTarget(tc.payloadLen, tc.ttl, data)
		if target != pow.Target(tc.targetValue) {
			t.Errorf("for test #%d got %d expected %d", n, target,
				tc.targetValue)
		}
	}
}

type doTest struct {
	target         uint64
	initialHashStr string
	nonce          pow.Nonce
}

var doTests = []doTest{
	{95074205888550, "11d7d735e16c0915ae5423e81fd9942ae56e33a220a6883623432e405fc892ecb58424951f8cf3def7a575fbe4951dd0cc8d589c14d8eea33ef3de56316a1543", pow.Nonce(439479)},
	{46960898983301, "8cc3ddca9fb88310d39e5309ddb062ac35c5bf82c9d7a74d5570d130a019f1373918a118a6ef6a93a524970bf7f4bc1a1454387ba82103fa75ec6d4d578b55cc", pow.Nonce(68242)},
	{46551748204442, "42c4351c941e532bdf8b792212d8bfa9c12352d17ae7463b33159891f114841019d5b2b304124c6e6fe17a84c030b8e69cd5b2f49d80985a0386c6e9b4955198", pow.Nonce(17070)},
	{71162788233849, "9f560a593c47ac426c6fc82e6fdfd63619da55c93643281b66e6153605a9406bec1585c07cb78177d71bfe5f2998d1a67ca5c3543ed0ceee942b5a3cec22d465", pow.Nonce(51173)},
	{59305083692270, "b04cc995bd6e9b773f855afd9950ce250d8db47889d3588372b0a42d8a47b1f4205729b9a657cf11e7133e60f28733f36b10ce8b4a16768e7da8a575dcf586e8", pow.Nonce(297668)},
	{32101869570011, "84582938b2e4d4a224170fb079a2494b0e4a0d16665d91b44bc1f2cdf595f5f31bdec6acbd7386dba4b619507af2e3291635828ae12a156c46d8c9dea868c3de", pow.Nonce(2434185)},
}

func TestDoSequential(t *testing.T) {
	for n, tc := range doTests {
		initialHash, _ := hex.DecodeString(tc.initialHashStr)
		nonce := pow.DoSequential(pow.Target(tc.target), initialHash)
		if nonce != tc.nonce {
			t.Errorf("for test #%d got %d expected %d", n, nonce, tc.nonce)
		}
	}
}

func TestDoParallel(t *testing.T) {
	runtime.GOMAXPROCS(runtime.NumCPU()) // for parallel PoW

	for n, tc := range doTests {
		initialHash, _ := hex.DecodeString(tc.initialHashStr)
		nonce := pow.DoParallel(pow.Target(tc.target), initialHash, runtime.NumCPU())
		if nonce < tc.nonce { // >= is permitted
			t.Errorf("for test #%d got %d expected %d", n, nonce, tc.nonce)
		}
	}

	runtime.GOMAXPROCS(1)
}

// TODO add benchmarks
