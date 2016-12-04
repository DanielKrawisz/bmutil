package wire_test

import (
	"bytes"
	"encoding/hex"
	"testing"
	"time"

	"github.com/DanielKrawisz/bmutil/pow"
	"github.com/DanielKrawisz/bmutil/wire"
	"github.com/DanielKrawisz/bmutil/wire/fixed"
	"github.com/DanielKrawisz/bmutil/wire/obj"
)

var pubkey = []wire.PubKey{
	wire.PubKey([wire.PubKeySize]byte{
		23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38,
		39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53, 54,
		55, 56, 57, 58, 59, 60, 61, 62, 63, 64, 65, 66, 67, 68, 69, 70,
		71, 72, 73, 74, 75, 76, 77, 78, 79, 80, 81, 82, 83, 84, 85, 86}),
	wire.PubKey([wire.PubKeySize]byte{
		87, 88, 89, 90, 91, 92, 93, 94, 95, 96, 97, 98, 99, 100, 101, 102,
		103, 104, 105, 106, 107, 108, 109, 110, 111, 112, 113, 114, 115, 116, 117, 118,
		119, 120, 121, 122, 123, 124, 125, 126, 127, 128, 129, 130, 131, 132, 133, 134,
		135, 136, 137, 138, 139, 140, 141, 142, 143, 144, 145, 146, 147, 148, 149, 150}),
}

var shahash = wire.ShaHash([wire.HashSize]byte{
	98, 99, 100, 101, 102, 103, 104, 105, 106, 107, 108, 109, 110, 111, 112, 113,
	114, 115, 116, 117, 118, 119, 120, 121, 122, 123, 124, 125, 126, 127, 128, 129})

var ripehash = wire.RipeHash([wire.RipeHashSize]byte{
	78, 79, 80, 81, 82, 83, 84, 85, 86, 87, 88, 89, 90, 91, 92, 93, 94, 95, 96, 97})

func TestObjectTypeString(t *testing.T) {
	// check if unknowns are handled properly
	str := wire.ObjectType(4).String()
	if str != "Unknown" {
		t.Errorf("expected Unknown got %s", str)
	}
	str = wire.ObjectType(985621).String()
	if str != "Unknown" {
		t.Errorf("expected Unknown got %s", str)
	}

	// check existing object types
	for i := wire.ObjectType(0); i < wire.ObjectType(4); i++ {
		str = i.String()
		if str == "Unknown" {
			t.Errorf("did not expect Unknown for %d", i)
		}
	}
}

// TestEncodeAndDecodeObjectHeader tests EncodeObjectHeader and DecodeObjectHeader
// It is not necessary to test separate cases for different object types.
func TestEncodeAndDecodeObjectHeader(t *testing.T) {
	tests := []*wire.ObjectHeader{
		wire.NewObjectHeader(pow.Nonce(123), time.Now(), wire.ObjectType(0), 0, 1),
		wire.NewObjectHeader(pow.Nonce(8390), time.Now().Add(-37*time.Hour), wire.ObjectType(66), 33, 17),
		wire.NewObjectHeader(pow.Nonce(65), time.Now().Add(5*time.Second), wire.ObjectType(2), 2, 8),
	}

	for i, test := range tests {
		buf := &bytes.Buffer{}
		err := test.Encode(buf)
		if err != nil {
			t.Errorf("Error encoding header in test case %d.", i)
		}
		header, err := wire.DecodeObjectHeader(buf)
		if err != nil {
			t.Errorf("Error decoding header in test case %d.", i)
		}
		if header.Nonce != test.Nonce {
			t.Errorf("Error on test case %d: nonce should be %x, got %x", i, test.Nonce, header.Nonce)
		}
		if header.Expiration().Unix() != test.Expiration().Unix() {
			t.Errorf("Error on test case %d: expire time should be %x, got %x",
				i, test.Expiration().Unix(), header.Expiration().Unix())
		}
		if header.ObjectType != test.ObjectType {
			t.Errorf("Error on test case %d: object type should be %d, got %d", i, test.ObjectType, header.ObjectType)
		}
		if header.Version != test.Version {
			t.Errorf("Error on test case %d: version should be %d, got %d", i, test.Version, header.Version)
		}
		if header.StreamNumber != test.StreamNumber {
			t.Errorf("Error on test case %d: stream should be %d, got %d", i, test.StreamNumber, header.StreamNumber)
		}
	}
}

// TestDecodeMsgObject tests DecodeMsgObject and checks if it returns an error if it should.
func TestDecodeMsgObject(t *testing.T) {
	expires := time.Now().Add(300 * time.Minute)

	tests := []struct {
		input       []byte // The input to the function.
		errExpected bool   // Whether an error is expected.
	}{
		{ // Error case: nil input.
			nil,
			true,
		},
		{ // Error case. Incomplete header.
			[]byte{},
			true,
		},
		{ // Valid case. Not a real object but we wouldn't know that.
			[]byte{
				0, 0, 0, 0, 0, 0, 0, 123, // Nonce
				0, 0, 0, 0, 85, 75, 111, 20, // Expiration
				0, 0, 0, 0,
				4, 1, 98, 99, 100, 101, 102, 103, 104, 105, 106, 107,
				108, 109, 110, 111, 112, 113, 114, 115, 116, 117, 118, 119, 120, 121, 122, 123,
				124, 125, 126},
			false,
		},
		{ // Valid case: GetPubKey object.
			[]byte{
				0, 0, 0, 0, 0, 0, 0, 123, 0, 0, 0, 0, 85, 75, 111, 20,
				0, 0, 0, 0, 4, 1, 98, 99, 100, 101, 102, 103, 104, 105, 106, 107,
				108, 109, 110, 111, 112, 113, 114, 115, 116, 117, 118, 119, 120, 121, 122, 123,
				124, 125, 126, 127, 128, 129},
			false,
		},
		{ // Valid case: PubKey object.
			wire.EncodeMessage(obj.NewEncryptedPubKey(543, expires, 1, &shahash, []byte{11, 12, 13, 14, 15, 16, 17, 18}).MsgObject()),
			false,
		},
		{ // Valid case: Msg object.
			wire.EncodeMessage(obj.NewMessage(765, expires, 1,
				[]byte{90, 87, 66, 45, 3, 2, 120, 101, 78, 78, 78, 7, 85, 55, 2, 23}).MsgObject()),
			false,
		},
		{ // Valid case: Broadcast object.
			wire.EncodeMessage(obj.NewTaggedBroadcast(876, expires, 1, &shahash,
				[]byte{90, 87, 66, 45, 3, 2, 120, 101, 78, 78, 78, 7, 85, 55, 2, 23}).MsgObject()),
			false,
		},
		{ // Valid case: unknown object.
			wire.EncodeMessage(wire.NewMsgObject(wire.NewObjectHeader(345, expires, wire.ObjectType(4), 1, 1), []byte{77, 82, 53, 48, 96, 1})),
			false,
		},
	}

	for i, test := range tests {
		if _, err := wire.DecodeMsgObject(test.input); (err != nil) != test.errExpected {
			t.Errorf("failed test case %d.", i)
		}
	}
}

// TestEncodeAndDecodeErrors checks some error cases in Encode and Decode
func TestEncodeAndDecodeErrors(t *testing.T) {
	obj := &wire.MsgObject{}
	if obj.Decode(bytes.NewReader([]byte{})) == nil {
		t.Error("object Decode should have returned an error.")
	}

	w := fixed.NewWriter(0)
	obj, _ = wire.DecodeMsgObject([]byte{
		0, 0, 0, 0, 0, 0, 0, 46, 0, 0, 0, 0, 85, 75, 111, 20,
		0, 0, 0, 0, 4, 1, 98, 99, 100, 101, 102, 103, 104, 105, 106, 107,
		108, 109, 110, 111, 112, 113, 114, 115, 116, 117, 118, 119, 120, 121, 122, 123,
		124, 125, 126, 127, 128, 129})
	if obj.Encode(w) == nil {
		t.Error("object Encode should have returned an error.")
	}
}

func TestCheck(t *testing.T) {
	type test struct {
		payload string
	}

	data := pow.Data{
		NonceTrialsPerByte: 1000,
		ExtraBytes:         1000,
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
		if !msg.CheckPow(data, refTime) {
			t.Errorf("for test #%d check returned false", n)
		}

		// change nonce
		header := msg.Header()
		header.Nonce = 0x00
		newMsg := wire.NewMsgObject(header, msg.Payload())

		if newMsg.CheckPow(data, refTime) {
			t.Errorf("for test #%d check returned true", n)
		}
	}

	refTime = time.Unix(1434714755, 0) // +28 days
	for n, tc := range tests {
		b, _ := hex.DecodeString(tc.payload)
		msg, _ := wire.DecodeMsgObject(b)
		if msg.CheckPow(data, refTime) {
			t.Errorf("for test #%d check returned true", n)
		}
	}
}

func TestCopy(t *testing.T) {
	expires := time.Now().Add(300 * time.Minute)

	getPubKey, _ := wire.DecodeMsgObject([]byte{
		0, 0, 0, 0, 0, 0, 0, 123, 0, 0, 0, 0, 85, 75, 111, 20,
		0, 0, 0, 0, 4, 1, 98, 99, 100, 101, 102, 103, 104, 105, 106, 107,
		108, 109, 110, 111, 112, 113, 114, 115, 116, 117, 118, 119, 120, 121, 122, 123,
		124, 125, 126, 127, 128, 129})

	pubKey := obj.NewEncryptedPubKey(543, expires, 1, &shahash, []byte{11, 12, 13, 14, 15, 16, 17, 18}).MsgObject()

	msg := obj.NewMessage(765, expires, 1,
		[]byte{90, 87, 66, 45, 3, 2, 120, 101, 78, 78, 78, 7, 85, 55, 2, 23}).MsgObject()

	broadcast := obj.NewTaggedBroadcast(876, expires, 1, &shahash,
		[]byte{90, 87, 66, 45, 3, 2, 120, 101, 78, 78, 78, 7, 85, 55, 2, 23}).MsgObject()

	unknown := wire.NewMsgObject(wire.NewObjectHeader(345, expires, wire.ObjectType(4), 1, 1), []byte{77, 82, 53, 48, 96, 1})

	tests := []struct {
		obj *wire.MsgObject
	}{
		{
			getPubKey,
		},
		{
			pubKey,
		},
		{
			msg,
		},
		{
			broadcast,
		},
		{
			unknown,
		},
	}

	for i, test := range tests {
		cp := test.obj.Copy()
		if cp == nil {
			t.Errorf("Copy is nil.")
			continue
		}

		if !bytes.Equal(wire.EncodeMessage(test.obj), wire.EncodeMessage(cp)) {
			t.Errorf("failed test case %d.", i)
		}
		test.obj.Payload()[0]++
		if bytes.Equal(wire.EncodeMessage(test.obj), wire.EncodeMessage(cp)) {
			t.Errorf("failed test case %d after original was altered.", i)
		}
	}
}

func TestNew(t *testing.T) {
	obj := wire.NewMsgObject(wire.NewObjectHeader(123, time.Now(), 3, 1, 1), []byte{1, 2, 3, 4, 5, 56})

	if obj == nil {
		t.Error("Failed to return object.")
	}

	if obj.Command() != wire.CmdObject {
		t.Error("Wrong command string:", obj.Command())
	}

	if obj.MaxPayloadLength() != wire.MaxPayloadOfMsgObject {
		t.Error("Wrong command string:", obj.MaxPayloadLength())
	}
}
