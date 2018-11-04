// Package masterkey manages the creation of cryptographic subkeys from master keys.
package masterkey

import (
	"crypto/sha256"
	"io"

	"golang.org/x/crypto/hkdf"
)

// New returns a MasterKey struct
func New(material []byte) MasterKey {
	return MasterKey{material: material}
}

// MasterKey is a crypto key that rather than being used directly generates
// subkeys that are used for different purposes
type MasterKey struct {
	material []byte
}

// SubKey returns a deterministcally generated subkey of `size` bytes
func (m MasterKey) SubKey(id string, size int) ([]byte, error) {
	material := make([]byte, size)
	kdf := hkdf.New(sha256.New, m.material, nil, []byte(id))
	if _, err := io.ReadFull(kdf, material); err != nil {
		return nil, err
	}
	return material, nil
}
