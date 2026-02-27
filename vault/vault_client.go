package vault

import (
	"context"
	"fmt"
	"log"
	"os"
	"sync"
	"time"

	"github.com/hashicorp/vault/api"
)

//go:generate mockgen -source=$GOFILE -destination=mock_$GOFILE -package=$GOPACKAGE
type IVaultProxy interface {
	GetVersion(ctx context.Context, engineName, secPath string, version int) (*api.KVSecret, error)
	GetVersionsAsList(ctx context.Context, engineName, secPath string) ([]api.KVVersionMetadata, error)
}

type vaultProxy struct {
	client *api.Client
}

var (
	vaultProxyInstance IVaultProxy
	vaultSyncOnce      sync.Once
)

func GetVaultProxy() IVaultProxy {
	vaultSyncOnce.Do(func() {
		client, err := createVaultClient()
		if err != nil {
			log.Fatalf("Failed to create Vault client: %v", err)
		}
		vaultProxyInstance = &vaultProxy{client: client}
	})
	return vaultProxyInstance
}

func (v *vaultProxy) GetVersion(ctx context.Context, engineName, secPath string, version int) (*api.KVSecret, error) {
	return v.client.KVv2(engineName).GetVersion(ctx, secPath, version)
}

func (v *vaultProxy) GetVersionsAsList(ctx context.Context, engineName, secPath string) ([]api.KVVersionMetadata, error) {
	return v.client.KVv2(engineName).GetVersionsAsList(ctx, secPath)
}

type VaultAuthConfig struct {
	RoleID    string
	SecretID  string
	RootToken string
}

func createVaultClient() (*api.Client, error) {
	config := api.DefaultConfig()
	vaultAddr := os.Getenv("VAULT_ADDR")
	if vaultAddr == "" {
		return nil, fmt.Errorf("VAULT_ADDR environment variable is not set")
	}
	config.Address = vaultAddr
	client, err := api.NewClient(config)
	if err != nil {
		return nil, fmt.Errorf("failed to create Vault client: %w", err)
	}

	authConfig := getAuthConfigFromEnv()
	// check if AppRole credentials are set, if not fallback to static token

	if authConfig.RoleID != "" && authConfig.SecretID != "" {
		err := loginAndMaintain(client, authConfig)
		if err != nil {
			return nil, fmt.Errorf("failed to authenticate with AppRole: %w", err)
		}
	} else {
		// [local] read Token from env
		token := authConfig.RootToken
		client.SetToken(token)
		log.Println("Authenticated via Static Token")
	}

	return client, nil
}

func loginAndMaintain(client *api.Client, authConfig *VaultAuthConfig) error {
	// 1. AppRole login obtain initial token
	secret, err := client.Logical().Write("auth/approle/login", map[string]interface{}{
		"role_id":   authConfig.RoleID,
		"secret_id": authConfig.SecretID,
	})
	if err != nil {
		return err
	}

	token := secret.Auth.ClientToken
	client.SetToken(token)
	log.Println("Vault logged in successfully")

	// 2. lifecycle management
	go manageTokenLifecycle(client, secret)
	return nil
}

func manageTokenLifecycle(client *api.Client, authSecret *api.Secret) {
	// renwewal and expiration handling using LifetimeWatcher
	watcher, err := client.NewLifetimeWatcher(&api.LifetimeWatcherInput{
		Secret: authSecret,
	})
	if err != nil {
		log.Printf("Failed to create watcher: %v", err)
		return
	}

	go watcher.Start()

	for {
		select {
		case <-watcher.DoneCh():
			log.Println("Token expired or max TTL reached, re-logging in...")
			err := loginAndMaintain(client, getAuthConfigFromEnv())
			if err != nil {
				log.Printf("Failed to re-login: %v", err)
			}
			return
		case renewal := <-watcher.RenewCh():
			// renewal success
			log.Printf("Token renewed at %s", renewal.RenewedAt.Format(time.RFC3339))
		}
	}
}

func getAuthConfigFromEnv() *VaultAuthConfig {
	return &VaultAuthConfig{
		RoleID:    os.Getenv("VAULT_ROLE_ID"),
		SecretID:  os.Getenv("VAULT_SECRET_ID"),
		RootToken: os.Getenv("VAULT_TOKEN"),
	}
}
