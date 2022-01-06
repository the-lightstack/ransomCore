package main

import (
	"bytes"
	"testing"
)

func TestEncryptionDecryption(t *testing.T) {

	plain := []byte("This text shall remain secret!")
	key := []byte("ZHNDAAXTVJBWOLVEXLNATWPDKJJGGRSH")
	nonce := make([]byte, 12)

	GenerateNonceValue(nonce)
	gcmCipher := GetCipher(key)
	result := EncryptBytes(gcmCipher, plain, nonce)

	restored_plain := DecryptBytes(gcmCipher, result, nonce)

	if bytes.Compare(restored_plain, plain) != 0 {
		t.Fatalf("Decrypted data didn't match plain text")
	}
}
