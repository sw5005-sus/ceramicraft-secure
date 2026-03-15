package vault

import (
	"context"
	"fmt"
	"log"
	"slices"
	"sync"
	"time"
)

//go:generate mockgen -source=$GOFILE -destination=mock_$GOFILE -package=$GOPACKAGE
type IKeyManager interface {
	GetSecConfigByKey(key string, version int) (interface{}, error)
	GetLatestVersion() int
}

type KeyManager struct {
	vClientInstance IVaultProxy
	secConfig       map[int]map[string]interface{}
	latestVersion   int
}

var (
	vclientSyncOnce    sync.Once
	keyManagerInstance IKeyManager
)

func GetKeyManager() IKeyManager {
	vclientSyncOnce.Do(func() {
		instance := &KeyManager{}
		instance.Init()
		keyManagerInstance = instance
	})
	return keyManagerInstance
}

const (
	engineName = "secrets"
	secPath    = "secret/ceramicraft/sec_config"
)

func (k *KeyManager) Init() {
	k.vClientInstance = GetVaultProxy()
	tmpConfig, tmpLatestVer, err := k.loadSecConfig()
	if err != nil {
		log.Fatalf("Failed to load secret configuration: %v", err)
	}
	k.secConfig = tmpConfig
	k.latestVersion = tmpLatestVer
	k.startSecConfigRefreshTimer()
}

func (k *KeyManager) GetLatestVersion() int {
	return k.latestVersion
}

func (k *KeyManager) GetSecConfigByKey(key string, version int) (interface{}, error) {
	if version <= 0 || version > k.latestVersion {
		version = k.latestVersion
	}
	if _, ok := k.secConfig[version]; ok {
		value, exists := k.secConfig[version][key]
		if !exists {
			return nil, fmt.Errorf("key '%s' not found in secret configuration", key)
		}
		return value, nil
	}
	ret, err := k.vClientInstance.GetVersion(context.Background(), engineName, secPath, version)
	if err != nil {
		return nil, fmt.Errorf("failed to read secret version %d from Vault: %w", version, err)
	}
	if ret == nil || ret.Data == nil {
		return nil, fmt.Errorf("secret version %d not found in Vault", version)
	}
	return ret.Data[key], nil
}

var refreshInterval = time.Minute

func (k *KeyManager) startSecConfigRefreshTimer() {
	ticker := time.NewTicker(refreshInterval)
	go func() {
		for range ticker.C {
			tmpConfig, tmpLatestVer, err := k.loadSecConfig()
			if err != nil {
				log.Printf("Failed to refresh secret configuration: %v", err)
				continue
			}
			k.secConfig = tmpConfig
			k.latestVersion = tmpLatestVer
		}
	}()
}

var versionLimit = 5

func (k *KeyManager) loadSecConfig() (map[int]map[string]interface{}, int, error) {
	versions, err := k.loadVersions(versionLimit)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to load secret versions: %w", err)
	}
	ret := make(map[int]map[string]interface{})
	for _, version := range versions {
		ret[version] = make(map[string]interface{})
		secret, err := k.vClientInstance.GetVersion(context.Background(), engineName, secPath, version)
		if err != nil {
			return nil, 0, fmt.Errorf("failed to read secret from Vault: %w", err)
		}
		ret[version] = secret.Data
	}
	return ret, versions[0], nil
}

func (k *KeyManager) loadVersions(limit int) ([]int, error) {
	metadata, err := k.vClientInstance.GetVersionsAsList(context.Background(), engineName, secPath)
	if err != nil {
		return nil, fmt.Errorf("failed to get secret metadata from Vault: %w", err)
	}
	slices.Reverse(metadata)
	size := min(len(metadata), limit)
	metadata = metadata[:size]
	var versions []int
	for _, data := range metadata {
		versions = append(versions, data.Version)
	}
	return versions, nil
}
