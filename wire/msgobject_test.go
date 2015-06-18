package wire_test

import (
	"bytes"
	"net"
	"testing"
	"time"

	"github.com/monetas/bmutil/wire"
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
	tests := []struct {
		nonce   uint64
		expires time.Time
		objType wire.ObjectType
		version uint64
		stream  uint64
	}{
		{
			nonce:   uint64(123),
			expires: time.Now(),
			objType: wire.ObjectType(0),
			version: 0,
			stream:  1,
		},
		{
			nonce:   uint64(8390),
			expires: time.Now().Add(-37 * time.Hour),
			objType: wire.ObjectType(66),
			version: 33,
			stream:  17,
		},
		{
			nonce:   uint64(65),
			expires: time.Now().Add(5 * time.Second),
			objType: wire.ObjectType(2),
			version: 2,
			stream:  8,
		},
	}

	for i, test := range tests {
		buf := &bytes.Buffer{}
		err := wire.EncodeMsgObjectHeader(buf, test.nonce, test.expires, test.objType, test.version, test.stream)
		if err != nil {
			t.Errorf("Error encoding header in test case %d.", i)
		}
		nonce, expires, objType, version, stream, err := wire.DecodeMsgObjectHeader(buf)
		if err != nil {
			t.Errorf("Error decoding header in test case %d.", i)
		}
		if nonce != test.nonce {
			t.Errorf("Error on test case %d: nonce should be %x, got %x", i, test.nonce, nonce)
		}
		if expires.Unix() != test.expires.Unix() {
			t.Errorf("Error on test case %d: expire time should be %x, got %x", i, test.expires.Unix(), expires.Unix())
		}
		if objType != test.objType {
			t.Errorf("Error on test case %d: object type should be %d, got %d", i, test.objType, objType)
		}
		if version != test.version {
			t.Errorf("Error on test case %d: version should be %d, got %d", i, test.version, version)
		}
		if stream != test.stream {
			t.Errorf("Error on test case %d: stream should be %d, got %d", i, test.stream, stream)
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
		{ // Error case. Incomplete body.
			[]byte{
				0, 0, 0, 0, 0, 0, 0, 123, 0, 0, 0, 0, 85, 75, 111, 20,
				0, 0, 0, 0, 4, 1, 98, 99, 100, 101, 102, 103, 104, 105, 106, 107,
				108, 109, 110, 111, 112, 113, 114, 115, 116, 117, 118, 119, 120, 121, 122, 123,
				124, 125, 126},
			true,
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
			wire.EncodeMessage(wire.NewMsgPubKey(543, expires, 4, 1, 2, &pubkey[0], &pubkey[1], 3, 5,
				[]byte{4, 5, 6, 7, 8, 9, 10}, &shahash, []byte{11, 12, 13, 14, 15, 16, 17, 18})),
			false,
		},
		{ // Valid case: Msg object.
			wire.EncodeMessage(wire.NewMsgMsg(765, expires, 1, 1,
				[]byte{90, 87, 66, 45, 3, 2, 120, 101, 78, 78, 78, 7, 85, 55, 2, 23},
				1, 1, 2, &pubkey[0], &pubkey[1], 3, 5, &ripehash, 1,
				[]byte{21, 22, 23, 24, 25, 26, 27, 28},
				[]byte{20, 21, 22, 23, 24, 25, 26, 27},
				[]byte{19, 20, 21, 22, 23, 24, 25, 26})),
			false,
		},
		{ // Valid case: Broadcast object.
			wire.EncodeMessage(wire.NewMsgBroadcast(876, expires, 1, 1, &shahash,
				[]byte{90, 87, 66, 45, 3, 2, 120, 101, 78, 78, 78, 7, 85, 55, 2, 23},
				1, 1, 2, &pubkey[0], &pubkey[1], 3, 5, 1,
				[]byte{27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41},
				[]byte{42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53, 54, 55, 56})),
			false,
		},
		{ // Valid case: unknown object.
			wire.EncodeMessage(wire.NewMsgUnknownObject(345, expires, wire.ObjectType(4), 1, 1, []byte{77, 82, 53, 48, 96, 1})),
			false,
		},
	}

	for i, test := range tests {
		if _, err := wire.DecodeMsgObject(test.input); (err != nil) != test.errExpected {
			t.Errorf("failed test case %d.", i)
		}
	}
}

func TestToMsgObject(t *testing.T) {
	expires := time.Now().Add(300 * time.Minute)

	tests := []struct {
		input       []byte       // The input to the function.
		msgType     wire.Message // An empty message of the correct type
		errExpected bool         // Whether an error is expected.
	}{
		{ // Invalid case: version message.
			wire.EncodeMessage(wire.NewMsgVersion(
				wire.NewNetAddressIPPort(net.ParseIP("127.0.0.1"), 8333, 1, 0),
				wire.NewNetAddressIPPort(net.ParseIP("192.168.0.1"), 8333, 1, 0),
				5555, []uint32{1})),
			&wire.MsgVersion{},
			true,
		},
		{ // Invalid case: ver ack message.
			wire.EncodeMessage(&wire.MsgVerAck{}),
			&wire.MsgVerAck{},
			true,
		},
		{ // Invalid case: addr message.
			wire.EncodeMessage(&wire.MsgAddr{}),
			&wire.MsgAddr{},
			true,
		},
		{ // Invalid case: inv message.
			wire.EncodeMessage(&wire.MsgInv{}),
			&wire.MsgInv{},
			true,
		},
		{ // Invalid case: get data message.
			wire.EncodeMessage(&wire.MsgGetData{}),
			&wire.MsgGetData{},
			true,
		},
		{ // Valid case: GetPubKey object.
			[]byte{
				0, 0, 0, 0, 0, 0, 0, 123, 0, 0, 0, 0, 85, 75, 111, 20,
				0, 0, 0, 0, 4, 1, 98, 99, 100, 101, 102, 103, 104, 105, 106, 107,
				108, 109, 110, 111, 112, 113, 114, 115, 116, 117, 118, 119, 120, 121, 122, 123,
				124, 125, 126, 127, 128, 129},
			&wire.MsgGetPubKey{},
			false,
		},
		{ // Valid case: PubKey object.
			wire.EncodeMessage(wire.NewMsgPubKey(543, expires, 4, 1, 2, &pubkey[0], &pubkey[1], 3, 5,
				[]byte{4, 5, 6, 7, 8, 9, 10}, &shahash, []byte{11, 12, 13, 14, 15, 16, 17, 18})),
			&wire.MsgPubKey{},
			false,
		},
		{ // Valid case: Msg object.
			wire.EncodeMessage(wire.NewMsgMsg(765, expires, 1, 1,
				[]byte{90, 87, 66, 45, 3, 2, 120, 101, 78, 78, 78, 7, 85, 55, 2, 23},
				1, 1, 2, &pubkey[0], &pubkey[1], 3, 5, &ripehash, 1,
				[]byte{21, 22, 23, 24, 25, 26, 27, 28},
				[]byte{20, 21, 22, 23, 24, 25, 26, 27},
				[]byte{19, 20, 21, 22, 23, 24, 25, 26})),
			&wire.MsgMsg{},
			false,
		},
		{ // Valid case: Broadcast object.
			wire.EncodeMessage(wire.NewMsgBroadcast(876, expires, 1, 1, &shahash,
				[]byte{90, 87, 66, 45, 3, 2, 120, 101, 78, 78, 78, 7, 85, 55, 2, 23},
				1, 1, 2, &pubkey[0], &pubkey[1], 3, 5, 1,
				[]byte{27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41},
				[]byte{42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53, 54, 55, 56})),
			&wire.MsgBroadcast{},
			false,
		},
		{ // Valid case: unknown object.
			wire.EncodeMessage(wire.NewMsgUnknownObject(345, expires, wire.ObjectType(4), 1, 1, []byte{77, 82, 53, 48, 96, 1})),
			&wire.MsgUnknownObject{},
			false,
		},
	}

	for i, test := range tests {
		test.msgType.Decode(bytes.NewReader(test.input))
		if _, err := wire.ToMsgObject(test.msgType); (err != nil) != test.errExpected {
			t.Errorf("failed test case %d.", i)
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

	pubKey, _ := wire.ToMsgObject(wire.NewMsgPubKey(543, expires, 4, 1, 2, &pubkey[0], &pubkey[1], 3, 5,
		[]byte{4, 5, 6, 7, 8, 9, 10}, &shahash, []byte{11, 12, 13, 14, 15, 16, 17, 18}))

	msg, _ := wire.ToMsgObject(wire.NewMsgMsg(765, expires, 1, 1,
		[]byte{90, 87, 66, 45, 3, 2, 120, 101, 78, 78, 78, 7, 85, 55, 2, 23},
		1, 1, 2, &pubkey[0], &pubkey[1], 3, 5, &ripehash, 1,
		[]byte{21, 22, 23, 24, 25, 26, 27, 28},
		[]byte{20, 21, 22, 23, 24, 25, 26, 27},
		[]byte{19, 20, 21, 22, 23, 24, 25, 26}))

	broadcast, _ := wire.ToMsgObject(wire.NewMsgBroadcast(876, expires, 1, 1, &shahash,
		[]byte{90, 87, 66, 45, 3, 2, 120, 101, 78, 78, 78, 7, 85, 55, 2, 23},
		1, 1, 2, &pubkey[0], &pubkey[1], 3, 5, 1,
		[]byte{27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41},
		[]byte{42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53, 54, 55, 56}))

	unknown, _ := wire.ToMsgObject(wire.NewMsgUnknownObject(345, expires, wire.ObjectType(4), 1, 1, []byte{77, 82, 53, 48, 96, 1}))

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
		copy := test.obj.Copy()
		if !bytes.Equal(wire.EncodeMessage(test.obj), wire.EncodeMessage(copy)) {
			t.Errorf("failed test case %d.", i)
		}
		test.obj.Payload[0]++
		if bytes.Equal(wire.EncodeMessage(test.obj), wire.EncodeMessage(copy)) {
			t.Errorf("failed test case %d after original was altered.", i)
		}
	}
}

func TestNew(t *testing.T) {
	obj := wire.NewMsgObject(123, time.Now(), 3, 1, 1, []byte{1, 2, 3, 4, 5, 56})

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
