//go:build !fips

package key_manager

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"testing"
	"time"

	"github.com/bdparrish/ztward/go/pkg/security/encryption"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// TestGetActiveKeyForClient_ExpiredKey covers the "key is expired" skip path.
func TestGetActiveKeyForClient_ExpiredKey(t *testing.T) {
	store := NewInMemoryClientKeyStore()
	ctx := context.Background()

	priv, _ := rsa.GenerateKey(rand.Reader, 2048)
	der, _ := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	pemStr := string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))

	pastTime := time.Now().Add(-1 * time.Hour)
	key := &Key{
		KeyId:        "expired-client-key-final",
		ClientId:     "expiry-user-final",
		PublicKeyPem: pemStr,
		KeyType:      KeyType_KEY_TYPE_RSA_2048,
		Status:       KeyStatus_KEY_STATUS_ACTIVE,
		CreatedAt:    timestamppb.Now(),
		ExpiresAt:    timestamppb.New(pastTime), // already expired
	}
	if err := store.RegisterKey(ctx, key); err != nil {
		t.Fatalf("RegisterKey: %v", err)
	}

	_, err := store.GetActiveKeyForClient(ctx, "expiry-user-final")
	if err == nil {
		t.Fatal("expected error: no active key because only key is expired")
	}
}

// TestGetActiveKeyForClient_OrphanKeyID covers the `if !exists { continue }` branch
// where a keyID is in clientKeys but the corresponding key is missing from keys.
func TestGetActiveKeyForClient_OrphanKeyID(t *testing.T) {
	store := NewInMemoryClientKeyStore()
	ctx := context.Background()

	// Directly insert an orphan keyID into clientKeys without a corresponding key record
	store.mu.Lock()
	store.clientKeys["orphan-user"] = []string{"missing-key-id"}
	store.mu.Unlock()

	_, err := store.GetActiveKeyForClient(ctx, "orphan-user")
	if err == nil {
		t.Fatal("expected error when orphan key ID exists without corresponding key record")
	}
}

// TestDeleteKey_ExternallyManaged covers the externally managed key rejection branch.
func TestDeleteKey_ExternallyManaged(t *testing.T) {
	srv := newTestKeyManagerServer(t, encryption.RSA2048)
	ctx := context.Background()

	// Create a regular key
	cr, err := srv.CreateKey(ctx, &CreateKeyRequest{
		Name:         "ext-managed-key",
		KeyType:      KeyType_KEY_TYPE_RSA_2048,
		ProviderType: KeyProviderType_KEY_PROVIDER_TYPE_SOFTWARE,
	})
	if err != nil {
		t.Fatalf("CreateKey error = %v", err)
	}
	keyID := cr.Key.KeyId

	// Mark it as externally managed
	key, _ := srv.keyStore.GetKey(ctx, keyID)
	key.ExternallyManaged = true
	srv.keyStore.StoreKey(ctx, key)

	_, err = srv.DeleteKey(ctx, &DeleteKeyRequest{KeyId: keyID})
	if err == nil {
		t.Fatal("expected error for externally managed key")
	}
}

// TestDeleteKey_InUseWithoutForce covers the "key in use" + not forced branch.
func TestDeleteKey_InUseWithoutForce(t *testing.T) {
	srv := newTestKeyManagerServer(t, encryption.RSA2048)
	ctx := context.Background()

	cr, err := srv.CreateKey(ctx, &CreateKeyRequest{
		Name:         "in-use-key",
		KeyType:      KeyType_KEY_TYPE_RSA_2048,
		ProviderType: KeyProviderType_KEY_PROVIDER_TYPE_SOFTWARE,
	})
	if err != nil {
		t.Fatalf("CreateKey error = %v", err)
	}
	keyID := cr.Key.KeyId

	// Mark key as in-use
	key, _ := srv.keyStore.GetKey(ctx, keyID)
	key.UsageCount = 5
	srv.keyStore.StoreKey(ctx, key)

	resp, err := srv.DeleteKey(ctx, &DeleteKeyRequest{KeyId: keyID, Force: false})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.Success {
		t.Fatal("expected Success=false for in-use key without force")
	}
}

// TestDeleteKey_ForceDeleteInUse covers the force delete path.
func TestDeleteKey_ForceDeleteInUse(t *testing.T) {
	srv := newTestKeyManagerServer(t, encryption.RSA2048)
	ctx := context.Background()

	cr, err := srv.CreateKey(ctx, &CreateKeyRequest{
		Name:         "force-delete-key",
		KeyType:      KeyType_KEY_TYPE_RSA_2048,
		ProviderType: KeyProviderType_KEY_PROVIDER_TYPE_SOFTWARE,
	})
	if err != nil {
		t.Fatalf("CreateKey error = %v", err)
	}
	keyID := cr.Key.KeyId

	// Mark key as in-use
	key, _ := srv.keyStore.GetKey(ctx, keyID)
	key.UsageCount = 3
	srv.keyStore.StoreKey(ctx, key)

	resp, err := srv.DeleteKey(ctx, &DeleteKeyRequest{KeyId: keyID, Force: true})
	if err != nil {
		t.Fatalf("DeleteKey with Force=true error = %v", err)
	}
	if !resp.Success {
		t.Errorf("expected Success=true for force delete, got: %s", resp.Message)
	}
}
