package vault

import (
	"fmt"
	"testing"

	"github.com/sw5005-sus/ceramicraft-secure/test"
)

func TestLoadSecConfig(t *testing.T) {
	err := test.LoadEnvFile("../.env")
	if err != nil {
		t.Fatalf("Failed to load .env file: %v", err)
	}
	keyManager := GetKeyManager()                            // Ensure the Vault client is initialized and secConfig is loaded
	value, err := keyManager.GetSecConfigByKey("aes_key", 1) // Attempt to retrieve a key to verify secConfig is loaded
	if err != nil {
		t.Fatalf("Failed to get sec config by key: %v", err)
	}
	if value == nil {
		t.Errorf("Expected value for 'test_key' in version 1, got nil")
	}
	fmt.Println(value)
}
