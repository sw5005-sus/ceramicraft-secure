package ceramicraftsecure

import (
	"encoding/hex"
	"fmt"

	"github.com/sw5005-sus/ceramicraft-secure/enc"
	"github.com/sw5005-sus/ceramicraft-secure/sign"
	"github.com/sw5005-sus/ceramicraft-secure/vault"
)

var keyManager vault.IKeyManager

func Init() {
	keyManager = vault.GetKeyManager()
}

const (
	aesKeyName  = "aes_key"
	hmacKeyName = "hmac_key"
)

func AesEncrypt(plainText string) (string, error) {
	version := keyManager.GetLatestVersion()
	aesKey, err := getKey(aesKeyName, version)
	if err != nil {
		return "", err
	}
	cipherText, err := enc.Encrypt([]byte(plainText), aesKey)
	if err != nil {
		return "", fmt.Errorf("encryption failed: %w", err)
	}
	return fmt.Sprintf("v%d:%s", version, cipherText), nil
}

func AesDecrypt(cipherText string) (string, error) {
	var version int
	var encText string
	_, err := fmt.Sscanf(cipherText, "v%d:%s", &version, &encText)
	if err != nil {
		return "", fmt.Errorf("invalid ciphertext format: %w", err)
	}

	aesKey, err := getKey(aesKeyName, version)
	if err != nil {
		return "", err
	}
	plainBytes, err := enc.Decrypt(encText, aesKey)
	if err != nil {
		return "", fmt.Errorf("decryption failed: %w", err)
	}
	return string(plainBytes), nil
}

func GenHmacSha256(data string) (string, error) {
	version := keyManager.GetLatestVersion()
	hmacKey, err := getKey(hmacKeyName, version)
	if err != nil {
		return "", err
	}
	signature := sign.GenHmacSha256(hmacKey, data)
	return fmt.Sprintf("v%d:%s", version, signature), nil
}

func VerifyHmacSha256(data string, signature string) (bool, error) {
	var version int
	var sig string
	_, err := fmt.Sscanf(signature, "v%d:%s", &version, &sig)
	if err != nil {
		return false, fmt.Errorf("invalid signature format: %w", err)
	}

	hmacKey, err := getKey(hmacKeyName, version)
	if err != nil {
		return false, err
	}
	return sign.VerifyHmacSha256(hmacKey, data, sig), nil
}

func getKey(keyName string, version int) ([]byte, error) {
	aesKeyHex, err := keyManager.GetSecConfigByKey(keyName, version)
	if err != nil {
		return nil, err
	}
	aesKey, err := hex.DecodeString(aesKeyHex.(string))
	if err != nil {
		return nil, fmt.Errorf("failed to decode AES key from hex: %w", err)
	}
	return aesKey, nil
}
