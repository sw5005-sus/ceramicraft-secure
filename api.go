package ceramicraftsecure

import (
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"

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
	encTmplate  = "v%d.%s"
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
	return fmt.Sprintf(encTmplate, version, cipherText), nil
}

func AesDecrypt(cipherText string) (string, error) {
	version, encText, err := parseEncryptedData(cipherText)
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
	return fmt.Sprintf(encTmplate, version, signature), nil
}

func VerifyHmacSha256(data, signature string) (bool, error) {
	var version int
	var sig string
	version, sig, err := parseEncryptedData(signature)
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
	keyHex, err := keyManager.GetSecConfigByKey(keyName, version)
	if err != nil {
		return nil, err
	}
	keyStr, ok := keyHex.(string)
	if !ok {
		return nil, fmt.Errorf("invalid key format: expected string, got %T", keyHex)
	}
	key, err := hex.DecodeString(keyStr)
	if err != nil {
		return nil, fmt.Errorf("failed to decode AES key from hex: %w", err)
	}
	if len(key) == 0 {
		return nil, fmt.Errorf("key is empty after decoding")
	}
	return key, nil
}

func parseEncryptedData(input string) (int, string, error) {
	if input == "" {
		return 0, "", fmt.Errorf("empty input data")
	}

	// split the input into version and payload using the first dot as the delimiter
	parts := strings.SplitN(input, ".", 2)
	if len(parts) != 2 {
		return 0, "", fmt.Errorf("invalid format: missing delimiter or payload")
	}

	// prefix should be in the format "v1", "v2", etc. We need to extract the version number.
	versionStr := parts[0]
	if len(versionStr) < 2 || versionStr[0] != 'v' {
		return 0, "", fmt.Errorf("invalid format: version prefix 'v' not found")
	}

	// parse the version number
	version, err := strconv.Atoi(versionStr[1:])
	if err != nil {
		return 0, "", fmt.Errorf("invalid version number: %w", err)
	}

	return version, parts[1], nil
}
