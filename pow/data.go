// Copyright 2016 Daniel Krawisz.
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package pow

import (
	"io"
	"fmt"

	"github.com/DanielKrawisz/bmutil"
)

// Data contains parameters affecting the difficulty required by a particular public key.
type Data struct {
	NonceTrialsPerByte uint64
	ExtraBytes         uint64
}

// Encode writes the data in pow.Data to a writer.
func (pd *Data) Encode(w io.Writer) error {
	if err := bmutil.WriteVarInt(w, pd.NonceTrialsPerByte); err != nil {
		return err
	}

	if err := bmutil.WriteVarInt(w, pd.ExtraBytes); err != nil {
		return err
	}

	return nil
}

// Decode reads a pow.Data from a reader.
func (pd *Data) Decode(r io.Reader) (err error) {
	pd.NonceTrialsPerByte, err = bmutil.ReadVarInt(r)
	if err != nil {
		return
	}

	pd.ExtraBytes, err = bmutil.ReadVarInt(r)
	if err != nil {
		return
	}

	return
}

func (pd *Data) String() string {
	return fmt.Sprintf("{%d, %d}", pd.NonceTrialsPerByte, pd.ExtraBytes)
}
