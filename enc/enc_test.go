package enc

import (
	"fmt"
	"testing"
)

func TestGenerateKey(t *testing.T) {
	key, err := GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey() returned an error: %v", err)
	}
	if len(key) != 32 {
		t.Errorf("Expected key length of 32 bytes, got %d bytes", len(key))
	}
	fmt.Printf("Generated Key:%x", key)
}

func TestEncryptDecrypt(t *testing.T) {
	key, err := GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey() returned an error: %v", err)
	}

	plainText := []byte("Hello, World!")
	cipherText, err := Encrypt(plainText, key)
	if err != nil {
		t.Fatalf("Encrypt() returned an error: %v", err)
	}
	fmt.Printf("Cipher Text:%s\n", cipherText)

	decryptedText, err := Decrypt(cipherText, key)
	if err != nil {
		t.Fatalf("Decrypt() returned an error: %v", err)
	}

	if string(decryptedText) != string(plainText) {
		t.Errorf("Decrypted text does not match original plaintext. Got '%s', expected '%s'", decryptedText, plainText)
	}
	fmt.Printf("Decrypted Text:%s\n", decryptedText)
}
