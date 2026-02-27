package sign

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"io"
)

func GenerateHmacSha256Key() (string, error) {
	key := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		return "", err
	}
	return hex.EncodeToString(key), nil
}

func GenHmacSha256(key []byte, data string) string {
	// Implementation of HMAC-SHA256 generation
	// This is a placeholder. You should implement the actual HMAC generation logic here.
	h := hmac.New(sha256.New, key)
	h.Write([]byte(data))
	return hex.EncodeToString(h.Sum(nil))
}

func VerifyHmacSha256(key []byte, data string, signature string) bool {
	newSig := GenHmacSha256(key, data)
	return hmac.Equal([]byte(newSig), []byte(signature))
}
