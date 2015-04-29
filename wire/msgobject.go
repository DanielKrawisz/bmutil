// Copyright (c) 2015 Monetas
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package wire

import (
	"io"
	"time"

	"github.com/monetas/bmutil"
)

const (
	// The maximum payload of object message can be = 2^18 bytes.
	// (not to be confused with the object payload)
	MaxPayloadOfMsgObject = 262144
)

// ObjectType represents the type of object than an object message contains.
// Objects in bitmessage are things on the network that get propagated. This can
// include requests/responses for pubkeys, messages and broadcasts.
type ObjectType uint32

// There are five types of objects in bitmessage.
//  - GetPubKey: requests for public keys.
//  - PubKey: public keys sent in response.
//  - Msg: bitmessage messages.
//  - Broadcast: broadcast messages.
// An ObjectType can also take on other values representing unknown message types.
const (
	ObjectTypeGetPubKey ObjectType = 0
	ObjectTypePubKey    ObjectType = 1
	ObjectTypeMsg       ObjectType = 2
	ObjectTypeBroadcast ObjectType = 3
)

// obStrings is a map of service flags back to their constant names for pretty
// printing.
var obStrings = map[ObjectType]string{
	ObjectTypeGetPubKey: "GETPUBKEY",
	ObjectTypePubKey:    "PUBKEY",
	ObjectTypeMsg:       "MSG",
	ObjectTypeBroadcast: "BROADCAST",
}

// EncodeMsgObjectHeader encodes the object header to the given writer. Object
// header consists of Nonce, ExpiresTime, ObjectType, Version and Stream, in
// that order. Read Protocol Specifications for more information.
func EncodeMsgObjectHeader(w io.Writer, nonce uint64, expiresTime time.Time,
	objectType ObjectType, version uint64, streamNumber uint64) error {
	err := writeElements(w, nonce, expiresTime.Unix(), objectType)
	if err != nil {
		return err
	}
	if err = bmutil.WriteVarInt(w, version); err != nil {
		return err
	}
	if err = bmutil.WriteVarInt(w, streamNumber); err != nil {
		return err
	}
	return nil
}

// DecodeMsgObjectHeader decodes the object header from given reader. Object
// header consists of Nonce, ExpiresTime, ObjectType, Version and Stream, in
// that order. Read Protocol Specifications for more information.
func DecodeMsgObjectHeader(r io.Reader) (nonce uint64, expiresTime time.Time,
	objectType ObjectType, version uint64, streamNumber uint64, err error) {

	var sec int64
	err = readElements(r, &nonce, &sec, &objectType)
	if err != nil {
		return
	}

	expiresTime = time.Unix(sec, 0)
	if version, err = bmutil.ReadVarInt(r); err != nil {
		return
	}

	if streamNumber, err = bmutil.ReadVarInt(r); err != nil {
		return
	}
	return
}
