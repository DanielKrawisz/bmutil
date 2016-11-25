// Copyright (c) 2015 Monetas
// Copyright 2016 Daniel Krawisz.
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package pow_test

import (
	"encoding/hex"
	"runtime"
	"testing"
	"time"

	"github.com/DanielKrawisz/bmutil/pow"
	"github.com/DanielKrawisz/bmutil/wire"
)

const (
	nonceTrials = 1000
	extraBytes  = 1000
)

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
		target := pow.CalculateTarget(tc.payloadLen, tc.ttl,
			nonceTrials, extraBytes)
		if target != tc.targetValue {
			t.Errorf("for test #%d got %d expected %d", n, target,
				tc.targetValue)
		}
	}
}

type doTest struct {
	target         uint64
	initialHashStr string
	nonce          uint64
}

var doTests = []doTest{
	{95074205888550, "11d7d735e16c0915ae5423e81fd9942ae56e33a220a6883623432e405fc892ecb58424951f8cf3def7a575fbe4951dd0cc8d589c14d8eea33ef3de56316a1543", 439479},
	{46960898983301, "8cc3ddca9fb88310d39e5309ddb062ac35c5bf82c9d7a74d5570d130a019f1373918a118a6ef6a93a524970bf7f4bc1a1454387ba82103fa75ec6d4d578b55cc", 68242},
	{46551748204442, "42c4351c941e532bdf8b792212d8bfa9c12352d17ae7463b33159891f114841019d5b2b304124c6e6fe17a84c030b8e69cd5b2f49d80985a0386c6e9b4955198", 17070},
	{71162788233849, "9f560a593c47ac426c6fc82e6fdfd63619da55c93643281b66e6153605a9406bec1585c07cb78177d71bfe5f2998d1a67ca5c3543ed0ceee942b5a3cec22d465", 51173},
	{59305083692270, "b04cc995bd6e9b773f855afd9950ce250d8db47889d3588372b0a42d8a47b1f4205729b9a657cf11e7133e60f28733f36b10ce8b4a16768e7da8a575dcf586e8", 297668},
	{32101869570011, "84582938b2e4d4a224170fb079a2494b0e4a0d16665d91b44bc1f2cdf595f5f31bdec6acbd7386dba4b619507af2e3291635828ae12a156c46d8c9dea868c3de", 2434185},
}

func TestDoSequential(t *testing.T) {
	for n, tc := range doTests {
		initialHash, _ := hex.DecodeString(tc.initialHashStr)
		nonce := pow.DoSequential(tc.target, initialHash)
		if nonce != tc.nonce {
			t.Errorf("for test #%d got %d expected %d", n, nonce, tc.nonce)
		}
	}
}

func TestDoParallel(t *testing.T) {
	runtime.GOMAXPROCS(runtime.NumCPU()) // for parallel PoW

	for n, tc := range doTests {
		initialHash, _ := hex.DecodeString(tc.initialHashStr)
		nonce := pow.DoParallel(tc.target, initialHash, runtime.NumCPU())
		if nonce < tc.nonce { // >= is permitted
			t.Errorf("for test #%d got %d expected %d", n, nonce, tc.nonce)
		}
	}

	runtime.GOMAXPROCS(1)
}

func TestCheck(t *testing.T) {
	type test struct {
		payload string
	}
	tests := []test{
		{"000000000592A44000000000555F535F00000000030100D6CFC4F94AA8BEE568985B6650029733726ED3"},
		{"0000000000AFFFE700000000555F933400000000020100FE3ACFAE81F900ACB3FD28867750ACC0549DFE"},
		{"000000000245D15D00000000555F68C9000000000201003A210C6F3CDE297BD5A9D1BE22822F4BB3A124"},
		{"0000000000AA5FA800000000556B4D0200000000020100FE3ACFAE81F900ACB3FD28867750ACC0549DFE"},
		{"00000000007F8DE2000000005565C0F500000000020100FE3ACFAE81F900ACB3FD28867750ACC0549DFE"},
		{"0000000007D99E61000000005566AAA1000000000201000077FB004DFF82E4A76A279E0E3A6D722298A0"},
		{"000000000011935E00000000556D5FC00000000003010000AC0291E93F1E2380EA43C63DE826165D3AA2"},
		{"0000000000A8B73B00000000556D5ECE0000000003010076B2303F3C2926BABD723BE8C04C298D0291FE"},
		{"0000000000CFC8B500000000556F55860000000003010056506CB580AFDA208A10A2349ADE34A7FBD7E3"},
		{"00000000018C66A200000000556D5E3000000000030100036CD13F16FB3E8D2A49E17CD605F7423F5621"},
	}
	refTime := time.Unix(1432295555, 0) // 22 May 2015, 5:22 PM IST
	for n, tc := range tests {
		b, _ := hex.DecodeString(tc.payload)
		msg, _ := wire.DecodeMsgObject(b)
		if !pow.Check(msg, nonceTrials, extraBytes, refTime) {
			t.Errorf("for test #%d check returned false", n)
		}

		// change nonce
		header := msg.Header()
		header.Nonce = 0x00
		newMsg := wire.NewMsgObject(header, msg.Payload())

		if pow.Check(newMsg, nonceTrials, extraBytes, refTime) {
			t.Errorf("for test #%d check returned true", n)
		}
	}

	refTime = time.Unix(1434714755, 0) // +28 days
	for n, tc := range tests {
		b, _ := hex.DecodeString(tc.payload)
		msg, _ := wire.DecodeMsgObject(b)
		if pow.Check(msg, nonceTrials, extraBytes, refTime) {
			t.Errorf("for test #%d check returned true", n)
		}
	}
}

// TODO add benchmarks
