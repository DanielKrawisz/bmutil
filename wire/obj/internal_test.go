// Copyright 2016 Daniel Krawisz.
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package obj

import (
	"time"

	"github.com/DanielKrawisz/bmutil/pow"
	"github.com/DanielKrawisz/bmutil/wire"
)

func (b *Broadcast) SetHeader(h *wire.ObjectHeader) {
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

// TaggedBroadcast is a broadcast from a v4 address (includes a tag).
func TaggedBroadcast() *Broadcast {
	return &Broadcast{
		header: &wire.ObjectHeader{
			Nonce:        123123,                   // 0x1e0f3
			ExpiresTime:  time.Unix(0x495fab29, 0), // 2009-01-03 12:15:05 -0600 CST)
			ObjectType:   wire.ObjectTypeBroadcast,
			Version:      5,
			StreamNumber: 1,
		},
		Tag: &wire.ShaHash{
			0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
			0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		},
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

// BaseBroadcast is used in the various tests as a baseline Broadcast.
func BaseBroadcast() *Broadcast {
	return &Broadcast{
		header: &wire.ObjectHeader{
			Nonce:        123123,                   // 0x1e0f3
			ExpiresTime:  time.Unix(0x495fab29, 0), // 2009-01-03 12:15:05 -0600 CST)
			ObjectType:   wire.ObjectTypeBroadcast,
			Version:      2,
			StreamNumber: 1,
		},
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

// BaseGetPubKey is used in the various tests as a baseline GetPubKey.
func BaseGetPubKey() *GetPubKey {
	return &GetPubKey{
		header: &wire.ObjectHeader{
			Nonce:        123123,                   // 0x1e0f3
			ExpiresTime:  time.Unix(0x495fab29, 0), // 2009-01-03 12:15:05 -0600 CST)
			ObjectType:   wire.ObjectTypeGetPubKey,
			Version:      3,
			StreamNumber: 1,
		},
		Ripe: &wire.RipeHash{1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
		Tag:  nil,
	}
}

// TagGetPubKey is a pubkey request for a v4 pubkey which includes a tag.
func TagGetPubKey() *GetPubKey {
	return &GetPubKey{
		header: &wire.ObjectHeader{
			Nonce:        123123,                   // 0x1e0f3
			ExpiresTime:  time.Unix(0x495fab29, 0), // 2009-01-03 12:15:05 -0600 CST)
			ObjectType:   wire.ObjectTypeGetPubKey,
			Version:      4,
			StreamNumber: 1,
		},
		Ripe: nil,
		Tag: &wire.ShaHash{
			0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
			0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
	}
}

// InvalidVersion is a getpubkey message with unsupported version
func InvalidGetPubKeyVersion() *GetPubKey {
	return &GetPubKey{
		header: &wire.ObjectHeader{
			Nonce:        123123,                   // 0x1e0f3
			ExpiresTime:  time.Unix(0x495fab29, 0), // 2009-01-03 12:15:05 -0600 CST)
			ObjectType:   wire.ObjectTypeGetPubKey,
			Version:      5,
			StreamNumber: 1,
		},
		Ripe: &wire.RipeHash{1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
		Tag:  nil,
	}
}

// BaseMessage is used in the various tests as a baseline MsgMsg.
func BaseMessage() *Message {
	return &Message{
		header: &wire.ObjectHeader{
			Nonce:        123123,                   // 0x1e0f3
			ExpiresTime:  time.Unix(0x495fab29, 0), // 2009-01-03 12:15:05 -0600 CST)
			ObjectType:   wire.ObjectTypeMsg,
			Version:      2,
			StreamNumber: 1,
		},
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
		header: &wire.ObjectHeader{
			Nonce:        123123,                   // 0x1e0f3
			ExpiresTime:  time.Unix(0x495fab29, 0), // 2009-01-03 12:15:05 -0600 CST)
			ObjectType:   wire.ObjectTypePubKey,
			Version:      2,
			StreamNumber: 1,
		},
		Data: &PubKeyData{
			Behavior:        0,
			VerificationKey: pub1,
			EncryptionKey:   pub2,
		},
	}
}

func TstExpandedPubKey(pub1, pub2 *wire.PubKey) *ExtendedPubKey {
	return &ExtendedPubKey{
		header: &wire.ObjectHeader{
			Nonce:        123123,                   // 0x1e0f3
			ExpiresTime:  time.Unix(0x495fab29, 0), // 2009-01-03 12:15:05 -0600 CST)
			ObjectType:   wire.ObjectTypePubKey,
			Version:      3,
			StreamNumber: 1,
		},
		Data: &PubKeyData{
			Behavior:        0,
			VerificationKey: pub1,
			EncryptionKey:   pub2,
			Pow: &pow.Data{
				NonceTrialsPerByte: 0,
				ExtraBytes:         0,
			},
		},
		Signature: []byte{0, 1, 2, 3},
	}
}

func TstEncryptedPubKey(tag *wire.ShaHash) *EncryptedPubKey {
	return &EncryptedPubKey{
		header: &wire.ObjectHeader{
			Nonce:        123123,                   // 0x1e0f3
			ExpiresTime:  time.Unix(0x495fab29, 0), // 2009-01-03 12:15:05 -0600 CST)
			ObjectType:   wire.ObjectTypePubKey,
			Version:      4,
			StreamNumber: 1,
		},
		Tag:       tag,
		Encrypted: []byte{0, 1, 2, 3, 4, 5, 6, 7, 8},
	}
}
