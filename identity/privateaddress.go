package identity

import (
	"bytes"
	"errors"

	. "github.com/DanielKrawisz/bmutil"
)

// PrivateAddress contains private keys and the parameters necessary
// to derive an address from it.
type PrivateAddress struct {
	private *PrivateKey
	version uint64
	stream  uint64
}

// NewPrivateAddress constructs a PrivateAddress.
func NewPrivateAddress(key *PrivateKey, version, stream uint64) *PrivateAddress {
	return &PrivateAddress{
		private: key,
		version: version,
		stream:  stream,
	}
}

// public turns a PrivateAddress  object into publicAddress.
func (id *PrivateAddress) public() *publicAddress {
	return &publicAddress{
		PublicKey: *id.private.Public(),
		version:   id.version,
		stream:    id.stream,
	}
}

// Address constructs the Bitmessage address object corresponding to
// this PrivateAddress
func (id *PrivateAddress) Address() Address {
	return id.public().Address()
}

// PrivateKey returns the private key corresponding to this address.
func (id *PrivateAddress) PrivateKey() *PrivateKey {
	return id.private
}

// PublicKey returns the public key.
func (id *PrivateAddress) PublicKey() *PublicKey {
	return id.private.Public()
}

// ExportWIF exports a Private identity to WIF for storage on disk or use by
// other software. It exports the private signing key and private
// encryption key.
func (id *PrivateAddress) ExportWIF() (address, signingKeyWif, decryptionKeyWif string) {
	address = id.Address().String()
	signingKeyWif, decryptionKeyWif = id.private.ExportWIF()
	return
}

// ImportWIF creates a Private identity from the Bitmessage address and Wallet
// Import Format (WIF) signing and encryption keys.
func ImportWIF(addrStr, signingKeyWif, decryptionKeyWif string) (*PrivateAddress, error) {
	// (Try to) decode address
	addr, err := DecodeAddress(addrStr)
	if err != nil {
		return nil, err
	}

	privSigningKey, err := DecodeWIF(signingKeyWif)
	if err != nil {
		err = errors.New("signing key decode failed: " + err.Error())
		return nil, err
	}
	privDecryptionKey, err := DecodeWIF(decryptionKeyWif)
	if err != nil {
		err = errors.New("encryption key decode failed: " + err.Error())
		return nil, err
	}

	priv := &PrivateAddress{
		private: &PrivateKey{
			Signing:    privSigningKey,
			Decryption: privDecryptionKey,
		},
		version: addr.Version(),
		stream:  addr.Stream(),
	}

	// check if the address given is consistent with the private keys.
	address := priv.Address()
	if !bytes.Equal(address.RipeHash()[:], addr.RipeHash()[:]) {
		return nil, errors.New("address does not correspond to private keys")
	}
	return priv, nil
}
