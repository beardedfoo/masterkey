package masterkey

import (
	"bytes"
	"crypto/md5"
	"crypto/rand"
	"fmt"
	"io"
	"testing"
)

// Ensures different sizes of master keys are supported
func TestMasterKeyLen(t *testing.T) {
	for x := 0; x < 4096; x++ {
		// Generate a master key of `x` len
		m := make([]byte, x)
		n, _ := io.ReadFull(rand.Reader, m)
		if n != len(m) {
			t.Fatalf("failed to create master key material")
		}
		k := New(m)

		// Generate a 4096-bit subkey
		_, err := k.SubKey("test", 4096)
		if err != nil {
			t.Fatalf("failed to generate subkey")
		}
	}
}

// Ensure different sizes of subkeys are supported
func TestSubKeyLen(t *testing.T) {
	m := make([]byte, 32)
	for x := 0; x < 4096; x++ {
		// Generate a 256-bit master key
		n, _ := io.ReadFull(rand.Reader, m)
		if n != len(m) {
			t.Fatalf("failed to create master key material")
		}
		k := New(m)

		// Generate a subKey of len `x`
		subKey, err := k.SubKey("test", x)
		if err != nil {
			t.Fatalf("error generating subkey: %v", err)
		}

		// Ensure the key is of the proper len
		if len(subKey) != x {
			t.Fatalf("unexpected subkey len")
		}
	}
}

// Ensure different masterkey and subKeyID values generate unique keys
func TestKeyVariance(t *testing.T) {
	hashes := make(map[[md5.Size]byte]int)
	masterKeyIterations := 1000
	subKeyIterations := 1000

	// Generate many different masterkeys
	m := make([]byte, 32)
	for masterKeyID := 0; masterKeyID < masterKeyIterations; masterKeyID++ {
		// Generate a random master key
		n, _ := io.ReadFull(rand.Reader, m)
		if n != len(m) {
			t.Fatalf("failed to create master key material")
		}
		k := New(m)

		// Generate many different subkeys from this master key
		for subKeyID := 0; subKeyID < subKeyIterations; subKeyID++ {
			subKey, err := k.SubKey(fmt.Sprintf("subkey-%v", subKeyID), 32)
			if err != nil {
				t.Fatalf("error generating subkey: %v", subKey)
			}

			// Store the hash of this subkey
			hashes[md5.Sum(subKey)] = 1
		}
	}

	// Ensure every subkey was unique
	if len(hashes) != masterKeyIterations*subKeyIterations {
		t.Fatalf("too few subkey values were generated")
	}
}

// Ensure keys are deterministic
func TestKeyDeterministic(t *testing.T) {
	// Generate a random master key
	m := make([]byte, 32)
	n, _ := io.ReadFull(rand.Reader, m)
	if n != len(m) {
		t.Fatalf("failed to create master key material")
	}
	k := New(m)

	// Generate the same subkey many times and ensure it is the same
	subKeyID := "foo"
	subKeyLen := 4096
	original, _ := k.SubKey(subKeyID, subKeyLen)
	for x := 0; x < 1000; x++ {
		subKey, _ := k.SubKey(subKeyID, subKeyLen)
		if !bytes.Equal(original, subKey) {
			t.Fatalf("mismatched subkey given same subKeyID/subKeyLen")
		}
	}
}
