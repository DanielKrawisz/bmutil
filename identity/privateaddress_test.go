package identity_test

import (
	"testing"

	"github.com/DanielKrawisz/bmutil/identity"
)

type addressImportExportTest struct {
	address       string
	signingkey    string
	encryptionkey string
}

// Taken from https://bitmessage.ch/nuked/
var addressImportExportTests = []addressImportExportTest{
	{"BM-2cVLR8vzEu6QUjGkYAPHQQTUenPVC62f9B",
		"5JvnKKDF1vWDBnnjCPGMVVzsX2EinsXbiiJj7JUwZ9La4xJ9FWt",
		"5JTYsHKSzDx6636UatMppek1QzKYL8b5RLeZdayHoi1Qa5yJjJS"},
	{"BM-2cUuzjWQjDWyDfYHL9C93jcJYKW1B8JyS5",
		"5KWFoFRXVHraujrFWuXfNn1fnP4euVUq79QnMWE2QPv3kWhbjs1",
		"5JYcPUZuMjzgSHmsmcsQcpzFGqM7DdEVtxwNjRZg7KfUTqmepFh"},
}

// Need to figure out a way to improve testing for this.
func TestImportExport(t *testing.T) {
	for _, pair := range addressImportExportTests {
		v, err := identity.ImportWIF(pair.address, pair.signingkey,
			pair.encryptionkey)
		if err != nil {
			t.Error(
				"for", pair.address,
				"got error:", err.Error(),
			)
		}

		address, signingkey, encryptionkey := v.ExportWIF()

		if address != pair.address || signingkey != pair.signingkey ||
			encryptionkey != pair.encryptionkey {
			t.Error(
				"for", pair.address,
				"got address:", address,
				"signingkey:", signingkey,
				"encryptionkey:", encryptionkey,
				"expected", pair.address, pair.signingkey, pair.encryptionkey,
			)
		}
	}
}

func TestImportWIFErrors(t *testing.T) {
	var err error
	// invalid address
	_, err = identity.ImportWIF("BM-9tSxgK6q4X6bNdEbyMRgGBcfnFC3MoW3Bp5", "",
		"")
	if err == nil {
		t.Error("ImportWIF: invalid address, got no error")
	}

	// invalid signing key
	_, err = identity.ImportWIF("BM-2cWgt4u3shyzQ8vP56uzMSe2iajy8r4Hxe",
		"sd5f48erdfoiopadsfa5d6sf405", "")
	if err == nil {
		t.Error("ImportWIF: invalid signing key, got no error")
	}

	// invalid encryption key
	_, err = identity.ImportWIF("BM-2cV9RshwouuVKWLBoyH5cghj3kMfw5G7BJ",
		"5KHBtHsy9eWz6fFZzJCNMVVJ3r4m7AbuzYRE3hwkKZ2H7BEZrGU",
		"sd5f48erdfoiopadsfa5d6sf405")
	if err == nil {
		t.Error("ImportWIF: invalid encryption key, got no error")
	}

	// address does not match
	_, err = identity.ImportWIF("BM-2DB6AzjZvzM8NkS3HMYWMP9R1Rt778mhN8",
		"5JXVjG9CNFh17kCawPxCtekJBei9gv6hzmawBGFkuciTCMaxeJD",
		"5KQC3fHBCUNyBoXeEpgphrqa314Cvy4beS21Zg1rvrj1FY3Tgqb")
	if err == nil {
		t.Error("ImportWIF: address mismatch, got no error")
	}
}
