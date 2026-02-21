package ceramicraftsecure

import (
	"encoding/hex"
	"fmt"

	"github.com/sw5005-sus/ceramicraft-secure/enc"
	"github.com/sw5005-sus/ceramicraft-secure/vault"
)

var keyManager vault.IKeyManager

func Init() {
	keyManager = vault.GetKeyManager()
}

const aesKeyName = "aes_key"

func AesEncrypt(plainText string) (string, error) {
	version := keyManager.GetLatestVersion()
	aesKey, err := getAesKey(version)
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

	aesKey, err := getAesKey(version)
	if err != nil {
		return "", err
	}
	plainBytes, err := enc.Decrypt(encText, aesKey)
	if err != nil {
		return "", fmt.Errorf("decryption failed: %w", err)
	}
	return string(plainBytes), nil
}

func getAesKey(version int) ([]byte, error) {
	aesKeyHex, err := keyManager.GetSecConfigByKey(aesKeyName, version)
	if err != nil {
		return nil, err
	}
	aesKey, err := hex.DecodeString(aesKeyHex.(string))
	if err != nil {
		return nil, fmt.Errorf("failed to decode AES key from hex: %w", err)
	}
	return aesKey, nil
}
