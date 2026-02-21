package enc

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"io"
)

func GenerateKey() ([]byte, error) {
	key := make([]byte, 32) // AES-256 requires a 32-byte key
	if _, err := rand.Read(key); err != nil {
		return nil, err
	}
	return key, nil
}

// Encrypt plainText using AES-GCM with the provided key. The function returns the encrypted data as a base64-encoded string.
func Encrypt(plainText []byte, key []byte) (string, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	// GCM requires a unique nonce for each encryption operation. The nonce is not secret, but it should be unique to prevent replay attacks.
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}

	// Seal appends the output to the nonce, so the final ciphertext will contain the nonce followed by the encrypted data. This way, we can easily extract the nonce during decryption.
	cipherText := gcm.Seal(nonce, nonce, plainText, nil)
	return base64.StdEncoding.EncodeToString(cipherText), nil
}

// Decrypt Base64-encoded cryptoText using AES-GCM with the provided key. The function returns the decrypted data as a byte slice.
func Decrypt(cryptoText string, key []byte) ([]byte, error) {
	data, _ := base64.StdEncoding.DecodeString(cryptoText)
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonceSize := gcm.NonceSize()
	if len(data) < nonceSize {
		return nil, errors.New("ciphertext too short")
	}

	nonce, cipherText := data[:nonceSize], data[nonceSize:]
	return gcm.Open(nil, nonce, cipherText, nil)
}
