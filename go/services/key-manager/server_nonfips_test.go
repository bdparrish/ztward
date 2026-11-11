//go:build !fips

package key_manager

import (
	"context"
	"testing"

	"github.com/bdparrish/ztward/go/config"
	"github.com/bdparrish/ztward/go/pkg/security/encryption"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func TestServer_CreateInitialKey(t *testing.T) {
	srv := newTestKeyManagerServer(t, encryption.RSA2048)
	cfg := &config.Config{}
	cfg.Encryption.Algorithm = "RSA-2048"

	// This should succeed and create a key
	srv.createInitialKey(cfg, KeyType_KEY_TYPE_RSA_2048)

	// Verify a key was created
	keys, err := srv.ListKeys(context.Background(), &ListKeysRequest{})
	if err != nil {
		t.Fatalf("ListKeys: %v", err)
	}
	if len(keys.Keys) == 0 {
		t.Error("expected at least one key after createInitialKey")
	}
}

func TestServer_GetAuthService(t *testing.T) {
	srv := newTestKeyManagerServer(t, encryption.RSA2048)
	// For test server, auth service is nil
	as := srv.GetAuthService()
	if as != nil {
		t.Error("expected nil auth service for test server")
	}
}

// TestCreateKey_WithExpiresAt exercises the ExpiresAt assignment branch.
func TestCreateKey_WithExpiresAt(t *testing.T) {
	srv := newTestKeyManagerServer(t, encryption.RSA2048)
	ctx := context.Background()

	// Build a timestamppb.Timestamp for a future expiry via timestamppb.Now().
	expiresAt := timestamppb.Now()
	resp, err := srv.CreateKey(ctx, &CreateKeyRequest{
		Name:         "expiring-key",
		KeyType:      KeyType_KEY_TYPE_RSA_2048,
		ProviderType: KeyProviderType_KEY_PROVIDER_TYPE_SOFTWARE,
		ExpiresAt:    expiresAt,
	})
	if err != nil {
		t.Fatalf("CreateKey with ExpiresAt error = %v", err)
	}
	if resp.Key.ExpiresAt == nil {
		t.Fatal("expected ExpiresAt to be set on created key")
	}
}

// TestCreateKey_WithMetadata exercises the metadata copy branch.
func TestCreateKey_WithMetadata(t *testing.T) {
	srv := newTestKeyManagerServer(t, encryption.RSA2048)
	ctx := context.Background()

	resp, err := srv.CreateKey(ctx, &CreateKeyRequest{
		Name:         "metadata-key",
		KeyType:      KeyType_KEY_TYPE_RSA_2048,
		ProviderType: KeyProviderType_KEY_PROVIDER_TYPE_SOFTWARE,
		Metadata:     map[string]string{"env": "prod", "team": "security"},
	})
	if err != nil {
		t.Fatalf("CreateKey with Metadata error = %v", err)
	}
	if resp.Key.Metadata["env"] != "prod" {
		t.Errorf("expected metadata env=prod, got %v", resp.Key.Metadata)
	}
}

// TestCreateKey_WithProviderConfig exercises the ProviderConfig configuration branch.
func TestCreateKey_WithProviderConfig(t *testing.T) {
	srv := newTestKeyManagerServer(t, encryption.RSA2048)
	ctx := context.Background()

	// Provide a config that the software provider will accept (or at least not error on)
	resp, err := srv.CreateKey(ctx, &CreateKeyRequest{
		Name:           "config-key",
		KeyType:        KeyType_KEY_TYPE_RSA_2048,
		ProviderType:   KeyProviderType_KEY_PROVIDER_TYPE_SOFTWARE,
		ProviderConfig: map[string]string{"max_age_hours": "8760"},
	})
	if err != nil {
		t.Fatalf("CreateKey with ProviderConfig error = %v", err)
	}
	if resp.Key == nil {
		t.Fatal("expected non-nil key")
	}
}

// TestCreateKey_WithRotationSchedule exercises the rotation schedule branch.
func TestCreateKey_WithRotationSchedule(t *testing.T) {
	srv := newTestKeyManagerServer(t, encryption.RSA2048)
	ctx := context.Background()

	resp, err := srv.CreateKey(ctx, &CreateKeyRequest{
		Name:                 "rotation-key",
		KeyType:              KeyType_KEY_TYPE_RSA_2048,
		ProviderType:         KeyProviderType_KEY_PROVIDER_TYPE_SOFTWARE,
		RotationPolicy:       RotationPolicy_ROTATION_POLICY_TIME_BASED,
		RotationIntervalDays: 30,
	})
	if err != nil {
		t.Fatalf("CreateKey with rotation schedule error = %v", err)
	}
	if resp.Key == nil {
		t.Fatal("expected non-nil key")
	}
}
