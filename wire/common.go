// Originally derived from: btcsuite/btcd/wire/common.go
// Copyright (c) 2013-2015 Conformal Systems LLC.

// Copyright (c) 2015 Monetas
// Copyright 2016 Daniel Krawisz.
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package wire

import (
	"crypto/rand"
	"encoding/binary"
	"io"
	"time"
)

// ReadElement reads the next sequence of bytes from r using big endian
// depending on the concrete type of element pointed to.
func ReadElement(r io.Reader, element interface{}) error {
	var scratch [8]byte

	// Attempt to read the element based on the concrete type via fast
	// type assertions first.
	switch e := element.(type) {
	case *int32:
		b := scratch[0:4]
		_, err := io.ReadFull(r, b)
		if err != nil {
			return err
		}
		*e = int32(binary.BigEndian.Uint32(b))
		return nil

	case *uint32:
		b := scratch[0:4]
		_, err := io.ReadFull(r, b)
		if err != nil {
			return err
		}
		*e = binary.BigEndian.Uint32(b)
		return nil

	case *ObjectType:
		b := scratch[0:4]
		_, err := io.ReadFull(r, b)
		if err != nil {
			return err
		}
		*e = ObjectType(binary.BigEndian.Uint32(b))
		return nil

	case *int64:
		b := scratch[0:8]
		_, err := io.ReadFull(r, b)
		if err != nil {
			return err
		}
		*e = int64(binary.BigEndian.Uint64(b))
		return nil

	case *uint64:
		b := scratch[0:8]
		_, err := io.ReadFull(r, b)
		if err != nil {
			return err
		}
		*e = binary.BigEndian.Uint64(b)
		return nil

	case *bool:
		b := scratch[0:1]
		_, err := io.ReadFull(r, b)
		if err != nil {
			return err
		}
		if b[0] == 0x00 {
			*e = false
		} else {
			*e = true
		}
		return nil

	// Message header checksum.
	case *[4]byte:
		_, err := io.ReadFull(r, e[:])
		if err != nil {
			return err
		}
		return nil

	// Message header command.
	case *[CommandSize]byte:
		_, err := io.ReadFull(r, e[:])
		if err != nil {
			return err
		}
		return nil

	// Message timestamp.
	case *time.Time:
		b := scratch[0:8]
		_, err := io.ReadFull(r, b)
		if err != nil {
			return err
		}
		*e = time.Unix(int64(binary.BigEndian.Uint64(b)), 0)
		return nil

	// IP address.
	case *[16]byte:
		_, err := io.ReadFull(r, e[:])
		if err != nil {
			return err
		}
		return nil

	case *ShaHash:
		_, err := io.ReadFull(r, e[:])
		if err != nil {
			return err
		}
		return nil

	case *RipeHash:
		_, err := io.ReadFull(r, e[:])
		if err != nil {
			return err
		}
		return nil

	case *PubKey:
		_, err := io.ReadFull(r, e[:])
		if err != nil {
			return err
		}
		return nil

	case *ServiceFlag:
		b := scratch[0:8]
		_, err := io.ReadFull(r, b)
		if err != nil {
			return err
		}
		*e = ServiceFlag(binary.BigEndian.Uint64(b))
		return nil

	case *BitmessageNet:
		b := scratch[0:4]
		_, err := io.ReadFull(r, b)
		if err != nil {
			return err
		}
		*e = BitmessageNet(binary.BigEndian.Uint32(b))
		return nil
	}

	// Fall back to the slower binary.Read if a fast path was not available
	// above.
	return binary.Read(r, binary.BigEndian, element)
}

// ReadElements reads multiple items from r.  It is equivalent to multiple
// calls to readElement.
func ReadElements(r io.Reader, elements ...interface{}) error {
	for _, element := range elements {
		err := ReadElement(r, element)
		if err != nil {
			return err
		}
	}
	return nil
}

// WriteElement writes the big endian representation of element to w.
func WriteElement(w io.Writer, element interface{}) error {
	var scratch [8]byte

	// Attempt to write the element based on the concrete type via fast
	// type assertions first.
	switch e := element.(type) {
	case int32:
		b := scratch[0:4]
		binary.BigEndian.PutUint32(b, uint32(e))
		_, err := w.Write(b)
		if err != nil {
			return err
		}
		return nil

	case uint32:
		b := scratch[0:4]
		binary.BigEndian.PutUint32(b, e)
		_, err := w.Write(b)
		if err != nil {
			return err
		}
		return nil

	case ObjectType:
		b := scratch[0:4]
		binary.BigEndian.PutUint32(b, uint32(e))
		_, err := w.Write(b)
		if err != nil {
			return err
		}
		return nil

	case int64:
		b := scratch[0:8]
		binary.BigEndian.PutUint64(b, uint64(e))
		_, err := w.Write(b)
		if err != nil {
			return err
		}
		return nil

	case uint64:
		b := scratch[0:8]
		binary.BigEndian.PutUint64(b, e)
		_, err := w.Write(b)
		if err != nil {
			return err
		}
		return nil

	case bool:
		b := scratch[0:1]
		if e == true {
			b[0] = 0x01
		} else {
			b[0] = 0x00
		}
		_, err := w.Write(b)
		if err != nil {
			return err
		}
		return nil

	// Message header checksum.
	case [4]byte:
		_, err := w.Write(e[:])
		if err != nil {
			return err
		}
		return nil

	// Message header command.
	case [CommandSize]uint8:
		_, err := w.Write(e[:])
		if err != nil {
			return err
		}
		return nil

	// Message timestamp.
	case time.Time:
		b := scratch[0:8]
		binary.BigEndian.PutUint64(b, uint64(e.Unix()))
		_, err := w.Write(b)
		if err != nil {
			return err
		}
		return nil

	// IP address.
	case [16]byte:
		_, err := w.Write(e[:])
		if err != nil {
			return err
		}
		return nil

	case *ShaHash:
		_, err := w.Write(e[:])
		if err != nil {
			return err
		}
		return nil

	case *RipeHash:
		_, err := w.Write(e[:])
		if err != nil {
			return err
		}
		return nil

	case *PubKey:
		_, err := w.Write(e[:])
		if err != nil {
			return err
		}
		return nil

	case ServiceFlag:
		b := scratch[0:8]
		binary.BigEndian.PutUint64(b, uint64(e))
		_, err := w.Write(b)
		if err != nil {
			return err
		}
		return nil

	case BitmessageNet:
		b := scratch[0:4]
		binary.BigEndian.PutUint32(b, uint32(e))
		_, err := w.Write(b)
		if err != nil {
			return err
		}
		return nil
	}

	// Fall back to the slower binary.Write if a fast path was not available
	// above.
	return binary.Write(w, binary.BigEndian, element)
}

// WriteElements writes multiple items to w.  It is equivalent to multiple
// calls to writeElement.
func WriteElements(w io.Writer, elements ...interface{}) error {
	for _, element := range elements {
		err := WriteElement(w, element)
		if err != nil {
			return err
		}
	}
	return nil
}

// randomUint64 returns a cryptographically random uint64 value.  This
// unexported version takes a reader primarily to ensure the error paths
// can be properly tested by passing a fake reader in the tests.
func randomUint64(r io.Reader) (uint64, error) {
	var b [8]byte
	_, err := io.ReadFull(r, b[:])
	if err != nil {
		return 0, err
	}
	return binary.BigEndian.Uint64(b[:]), nil
}

// RandomUint64 returns a cryptographically random uint64 value.
func RandomUint64() (uint64, error) {
	return randomUint64(rand.Reader)
}
