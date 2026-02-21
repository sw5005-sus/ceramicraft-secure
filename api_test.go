package ceramicraftsecure

import (
	"testing"

	"github.com/sw5005-sus/ceramicraft-secure/test"
)

func TestEncryptDecrypt(t *testing.T) {
	test.LoadEnvFile(".env")
	Init() // Ensure the key manager is initialized
	plainText := "Hello, Ceramicraft!"
	cipherText, err := AesEncrypt(plainText)
	if err != nil {
		t.Fatalf("AesEncrypt() returned an error: %v", err)
	}
	if cipherText == "" {
		t.Errorf("Expected non-empty cipher text, got empty string")
	}
	t.Logf("Cipher Text: %s", cipherText)

	decryptedText, err := AesDecrypt(cipherText)
	if err != nil {
		t.Fatalf("AesDecrypt() returned an error: %v", err)
	}
	if decryptedText != plainText {
		t.Errorf("Decrypted text does not match original. Got: %s, want: %s", decryptedText, plainText)
	}
}
