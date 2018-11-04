// Perform AES-256-CBC encryption using a 4096-bit masterkey and derived subkeys for encryption and IV materials.
package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"crypto/rand"
	"fmt"
	"io"
	"log"

	"github.com/beardedfoo/masterkey"
)

// ExampleAES256CBC demonstrates how to derive a key and IV for CBC mode
func ExampleAES256CBC() {
	// Generate a random plaintext
	plaintext := make([]byte, aes.BlockSize*4)
	if n, _ := io.ReadFull(rand.Reader, plaintext); n != len(plaintext) {
		log.Fatalf("failed to create a plaintext")
	}
	log.Printf("generated plaintext: %v", plaintext)

	// Generate a random 4096-bit master key
	material := make([]byte, 4096/8)
	if n, _ := io.ReadFull(rand.Reader, material); n != len(material) {
		log.Fatalf("failed to create master key material")
	}
	k := masterkey.New(material)
	log.Printf("generated master key: %v", material)

	// Create a 256-bit encryption key for CBC
	encKey, err := k.SubKey("encryption", 256/8)
	if err != nil {
		log.Fatalf("error creating encryption subkey: %v", err)
	}
	log.Printf("generated encryption subkey: %v", encKey)

	// Create an IV for this plaintext
	checksum := md5.Sum(plaintext)
	ivID := fmt.Sprintf("iv-%v", checksum)
	iv, err := k.SubKey(ivID, aes.BlockSize)
	if err != nil {
		log.Fatalf("error creating iv material: %v", err)
	}
	log.Printf("generated iv: %v", iv)

	// Create the AES block cipher
	block, err := aes.NewCipher(encKey)
	if err != nil {
		log.Fatalf("error creating block cipher: %v", err)
	}

	// Create the CBC encrypter with the IV
	cbc := cipher.NewCBCEncrypter(block, iv)
	ciphertext := make([]byte, len(plaintext))

	// Perform the encryption
	cbc.CryptBlocks(ciphertext, plaintext)
	log.Printf("ciphertext: %v", ciphertext)
}

func main() {
	ExampleAES256CBC()
}
