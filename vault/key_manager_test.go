package vault

import (
	"fmt"
	"testing"

	api "github.com/hashicorp/vault/api"
	"go.uber.org/mock/gomock"
)

func TestGetSecConfigByKey(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	mockVaultProxy := NewMockIVaultProxy(ctrl)
	mockVaultProxy.EXPECT().
		GetVersion(gomock.Any(), engineName, secPath, 1).
		Return(&api.KVSecret{Data: map[string]interface{}{"aes_key": "v1"}}, nil).
		AnyTimes()
	keyManager := &KeyManager{
		secConfig:       map[int]map[string]interface{}{2: {"aes_key": "v2"}},
		vClientInstance: mockVaultProxy,
		latestVersion:   2,
	}

	// Test case 1: Valid key with latest version
	value, err := keyManager.GetSecConfigByKey("aes_key", 2)
	if err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}
	if value != "v2" {
		t.Errorf("Expected value for 'aes_key' in version 1, got nil")
	}

	// Test case 2: Valid key with old version
	value, err = keyManager.GetSecConfigByKey("aes_key", 1) // 0 should fetch the latest version
	if err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}
	if value != "v1" {
		t.Errorf("Expected value for 'aes_key' in latest version, got nil")
	}

	// Test case 3: Invalid version
	value, err = keyManager.GetSecConfigByKey("aes_key", 0)
	if err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}
	if value != "v2" {
		t.Errorf("Expected nil for invalid key, got: %v", value)
	}

	// Test case 4: Non-existent key
	_, err = keyManager.GetSecConfigByKey("non_existent_key", 2)
	if err == nil {
		t.Fatalf("Expected error for non-existent key, got: %v", err)
	}
}

func TestLoadVersions(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	mockVaultProxy := NewMockIVaultProxy(ctrl)
	keyManager := &KeyManager{
		vClientInstance: mockVaultProxy,
	}

	// Test case 1: Successful load of versions
	mockVaultProxy.EXPECT().
		GetVersionsAsList(gomock.Any(), engineName, secPath).
		Return([]api.KVVersionMetadata{{Version: 1}, {Version: 2}, {Version: 3}, {Version: 4}, {Version: 5}}, nil).
		Times(1)

	versions, err := keyManager.loadVersions(5)
	if err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}
	if len(versions) != 5 {
		t.Errorf("Expected 5 versions, got: %d", len(versions))
	}
	if versions[0] != 5 || versions[4] != 1 {
		t.Errorf("Expected versions 1 to 5, got: %v", versions)
	}

	// Test case 2: Limit less than available versions
	mockVaultProxy.EXPECT().
		GetVersionsAsList(gomock.Any(), engineName, secPath).
		Return([]api.KVVersionMetadata{{Version: 1}, {Version: 2}, {Version: 3}, {Version: 4}, {Version: 5}}, nil).
		Times(1)
	versions, err = keyManager.loadVersions(3)
	if err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}
	if len(versions) != 3 {
		t.Errorf("Expected 3 versions, got: %d", len(versions))
	}
	if versions[0] != 5 || versions[2] != 3 {
		t.Errorf("Expected versions 1 to 3, got: %v", versions)
	}

	// Test case 3: Error while fetching versions
	mockVaultProxy.EXPECT().
		GetVersionsAsList(gomock.Any(), engineName, secPath).
		Return(nil, fmt.Errorf("vault error"))

	versions, err = keyManager.loadVersions(5)
	if err == nil {
		t.Fatalf("Expected error, got none")
	}
	if versions != nil {
		t.Errorf("Expected nil versions, got: %v", versions)
	}
}

// func TestLoadSecConfig(t *testing.T) {
// 	err := test.LoadEnvFile("../.env")
// 	if err != nil {
// 		t.Fatalf("Failed to load .env file: %v", err)
// 	}
// 	keyManager := GetKeyManager()                            // Ensure the Vault client is initialized and secConfig is loaded
// 	value, err := keyManager.GetSecConfigByKey("aes_key", 1) // Attempt to retrieve a key to verify secConfig is loaded
// 	if err != nil {
// 		t.Fatalf("Failed to get sec config by key: %v", err)
// 	}
// 	if value == nil {
// 		t.Errorf("Expected value for 'test_key' in version 1, got nil")
// 	}
// 	fmt.Println(value)
// }
