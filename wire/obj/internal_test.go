// Copyright 2016 Daniel Krawisz.
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package obj

import (
	"testing"
	"time"

	. "github.com/DanielKrawisz/bmutil"
	"github.com/DanielKrawisz/bmutil/hash"
	"github.com/DanielKrawisz/bmutil/pow"
	"github.com/DanielKrawisz/bmutil/wire"
)

func (b *TaglessBroadcast) SetHeader(h *wire.ObjectHeader) {
	b.header = h
}

func (b *TaggedBroadcast) SetHeader(h *wire.ObjectHeader) {
	b.header = h
}

func (p *GetPubKey) SetHeader(h *wire.ObjectHeader) {
	p.header = h
}

func (m *Message) SetHeader(h *wire.ObjectHeader) {
	m.header = h
}

func (p *SimplePubKey) SetHeader(h *wire.ObjectHeader) {
	p.header = h
}

func (p *ExtendedPubKey) SetHeader(h *wire.ObjectHeader) {
	p.header = h
}

func (p *EncryptedPubKey) SetHeader(h *wire.ObjectHeader) {
	p.header = h
}

func MakeAddress(t *testing.T, version, stream uint64, ripeBytes []byte) Address {
	var a Address
	var err error
	ripe, err := hash.NewRipe(ripeBytes)
	if err != nil {
		t.Fatalf("could not make a ripe hash: %s", err)
	}

	if version == 4 {
		a, err = NewAddress(version, stream, ripe)
	} else {
		a, err = NewDepricatedAddress(version, stream, ripe)
	}

	if err != nil {
		t.Fatalf("could not create address: %s", err)
	}

	return a
}

func MakeGetPubKey(
	nonce pow.Nonce,
	expiration time.Time,
	version, stream uint64,
	ripe *hash.Ripe,
	tag *hash.Sha) *GetPubKey {

	// Limit the timestamp to one second precision since the protocol
	// doesn't support better.
	return &GetPubKey{
		header: wire.NewObjectHeader(
			nonce,
			expiration,
			wire.ObjectTypeGetPubKey,
			version,
			stream),
		Ripe: ripe,
		Tag:  tag,
	}
}

// TstTaggedBroadcast is a broadcast from a v4 address (includes a tag).
func TstTaggedBroadcast() *TaggedBroadcast {
	return &TaggedBroadcast{
		header: wire.NewObjectHeader(
			123123, // 0x1e0f3
			time.Unix(0x495fab29, 0), // 2009-01-03 12:15:05 -0600 CST)
			wire.ObjectTypeBroadcast,
			TaggedBroadcastVersion,
			1),
		Tag: &hash.Sha{
			0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
			0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		},
		encrypted: []byte{
			0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
			0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
			0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
			0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
			0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
			0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
			0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
			0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		},
	}
}

// TstTaglessBroadcast is used in the various tests as a baseline Broadcast.
func TstTaglessBroadcast() *TaglessBroadcast {
	return &TaglessBroadcast{
		header: wire.NewObjectHeader(
			123123, // 0x1e0f3
			time.Unix(0x495fab29, 0), // 2009-01-03 12:15:05 -0600 CST)
			wire.ObjectTypeBroadcast,
			TaglessBroadcastVersion,
			1),
		encrypted: []byte{
			0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
			0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
			0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
			0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
			0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
			0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
			0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
			0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		},
	}
}

// TstBaseGetPubKey is used in the various tests as a baseline GetPubKey.
func TstBaseGetPubKey() *GetPubKey {
	return &GetPubKey{
		header: wire.NewObjectHeader(
			123123, // 0x1e0f3
			time.Unix(0x495fab29, 0), // 2009-01-03 12:15:05 -0600 CST)
			wire.ObjectTypeGetPubKey,
			3,
			1),
		Ripe: &hash.Ripe{1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
		Tag:  nil,
	}
}

// TstTagGetPubKey is a pubkey request for a v4 pubkey which includes a tag.
func TstTagGetPubKey() *GetPubKey {
	return &GetPubKey{
		header: wire.NewObjectHeader(
			123123, // 0x1e0f3
			time.Unix(0x495fab29, 0), // 2009-01-03 12:15:05 -0600 CST)
			wire.ObjectTypeGetPubKey,
			4,
			1),
		Ripe: nil,
		Tag: &hash.Sha{
			0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
			0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
	}
}

// TstInvalidVersion is a getpubkey message with unsupported version
func TstInvalidGetPubKeyVersion() *GetPubKey {
	return &GetPubKey{
		header: wire.NewObjectHeader(
			123123, // 0x1e0f3
			time.Unix(0x495fab29, 0), // 2009-01-03 12:15:05 -0600 CST)
			wire.ObjectTypeGetPubKey,
			5,
			1),
		Ripe: &hash.Ripe{1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
		Tag:  nil,
	}
}

// TstBaseMessage is used in the various tests as a baseline MsgMsg.
func TstBaseMessage() *Message {
	return &Message{
		header: wire.NewObjectHeader(
			123123, // 0x1e0f3
			time.Unix(0x495fab29, 0), // 2009-01-03 12:15:05 -0600 CST)
			wire.ObjectTypeMsg,
			2,
			1),
		Encrypted: []byte{
			0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
			0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
			0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
			0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
			0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
			0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
			0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
			0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		},
	}
}

// TstBasePubKey is used in the various tests as a baseline MsgPubKey.
func TstBasePubKey(pub1, pub2 *wire.PubKey) *SimplePubKey {
	return &SimplePubKey{
		header: wire.NewObjectHeader(
			123123, // 0x1e0f3
			time.Unix(0x495fab29, 0), // 2009-01-03 12:15:05 -0600 CST)
			wire.ObjectTypePubKey,
			2,
			1),
		data: &PubKeyData{
			Behavior:     0,
			Verification: pub1,
			Encryption:   pub2,
		},
	}
}

func TstExpandedPubKey(pub1, pub2 *wire.PubKey) *ExtendedPubKey {
	return &ExtendedPubKey{
		header: wire.NewObjectHeader(
			123123, // 0x1e0f3
			time.Unix(0x495fab29, 0), // 2009-01-03 12:15:05 -0600 CST)
			wire.ObjectTypePubKey,
			3,
			1),
		data: &PubKeyData{
			Behavior:     0,
			Verification: pub1,
			Encryption:   pub2,
			Pow: &pow.Data{
				NonceTrialsPerByte: 0,
				ExtraBytes:         0,
			},
		},
		Signature: []byte{0, 1, 2, 3},
	}
}

func TstEncryptedPubKey(tag *hash.Sha) *EncryptedPubKey {
	return &EncryptedPubKey{
		header: wire.NewObjectHeader(
			123123, // 0x1e0f3
			time.Unix(0x495fab29, 0), // 2009-01-03 12:15:05 -0600 CST)
			wire.ObjectTypePubKey,
			4,
			1),
		Tag:       tag,
		Encrypted: []byte{0, 1, 2, 3, 4, 5, 6, 7, 8},
	}
}
