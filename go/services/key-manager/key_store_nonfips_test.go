//go:build !fips

package key_manager

import (
	"context"
	"testing"

	"google.golang.org/protobuf/types/known/timestamppb"
)

func TestInMemoryKeyStore_StoreKey_Nil(t *testing.T) {
	store := NewInMemoryKeyStore()
	err := store.StoreKey(context.Background(), nil)
	if err == nil {
		t.Fatal("expected error for nil key")
	}
}

func TestInMemoryKeyStore_StoreKeyPair_Nil(t *testing.T) {
	store := NewInMemoryKeyStore()
	err := store.StoreKeyPair(context.Background(), nil)
	if err == nil {
		t.Fatal("expected error for nil key pair")
	}
}

func TestInMemoryKeyStore_StoreKey_EmptyID(t *testing.T) {
	store := NewInMemoryKeyStore()
	err := store.StoreKey(context.Background(), &Key{})
	if err == nil {
		t.Fatal("expected error for empty key ID")
	}
}

func TestInMemoryKeyStore_StoreKeyPair_EmptyID(t *testing.T) {
	store := NewInMemoryKeyStore()
	err := store.StoreKeyPair(context.Background(), &KeyPair{})
	if err == nil {
		t.Fatal("expected error for empty key pair ID")
	}
}

func TestInMemoryKeyStore_ListKeys_WithFilters(t *testing.T) {
	store := NewInMemoryKeyStore()
	ctx := context.Background()

	_ = store.StoreKey(ctx, &Key{
		KeyId:        "filter-key-1",
		KeyType:      KeyType_KEY_TYPE_RSA_2048,
		Status:       KeyStatus_KEY_STATUS_ACTIVE,
		ProviderType: KeyProviderType_KEY_PROVIDER_TYPE_SOFTWARE,
	})
	_ = store.StoreKey(ctx, &Key{
		KeyId:        "filter-key-2",
		KeyType:      KeyType_KEY_TYPE_ECC_P256,
		Status:       KeyStatus_KEY_STATUS_REVOKED,
		ProviderType: KeyProviderType_KEY_PROVIDER_TYPE_SOFTWARE,
	})

	// Filter by status
	keys, err := store.ListKeys(ctx, map[string]interface{}{
		"status": KeyStatus_KEY_STATUS_ACTIVE,
	})
	if err != nil {
		t.Fatalf("ListKeys: %v", err)
	}
	if len(keys) != 1 || keys[0].KeyId != "filter-key-1" {
		t.Errorf("expected 1 active key, got %d", len(keys))
	}

	// Filter by provider_type
	allKeys, err := store.ListKeys(ctx, map[string]interface{}{
		"provider_type": KeyProviderType_KEY_PROVIDER_TYPE_SOFTWARE,
	})
	if err != nil {
		t.Fatalf("ListKeys: %v", err)
	}
	if len(allKeys) != 2 {
		t.Errorf("expected 2 software keys, got %d", len(allKeys))
	}
}

func TestCoverageGaps2_KeyStore_StoreKey_Nil(t *testing.T) {
	store := NewInMemoryKeyStore()
	err := store.StoreKey(context.Background(), nil)
	if err == nil {
		t.Fatal("expected error for nil key in StoreKey")
	}
}

func TestCoverageGaps2_KeyStore_UpdateKey_Nil(t *testing.T) {
	store := NewInMemoryKeyStore()
	err := store.UpdateKey(context.Background(), nil)
	if err == nil {
		t.Fatal("expected error for nil key in UpdateKey")
	}
}

func TestCoverageGaps2_KeyStore_UpdateKey_EmptyID(t *testing.T) {
	store := NewInMemoryKeyStore()
	err := store.UpdateKey(context.Background(), &Key{KeyId: ""})
	if err == nil {
		t.Fatal("expected error for empty key ID in UpdateKey")
	}
}

func TestCoverageGaps2_KeyStore_StoreKeyPair_Nil(t *testing.T) {
	store := NewInMemoryKeyStore()
	err := store.StoreKeyPair(context.Background(), nil)
	if err == nil {
		t.Fatal("expected error for nil key pair in StoreKeyPair")
	}
}

func TestCoverageGaps2_KeyStore_ListKeys_ProviderTypeMismatch(t *testing.T) {
	store := NewInMemoryKeyStore()
	ctx := context.Background()

	// Store a SOFTWARE key
	err := store.StoreKey(ctx, &Key{
		KeyId:        "sw-key",
		KeyType:      KeyType_KEY_TYPE_RSA_2048,
		ProviderType: KeyProviderType_KEY_PROVIDER_TYPE_SOFTWARE,
		Status:       KeyStatus_KEY_STATUS_ACTIVE,
		CreatedAt:    timestamppb.Now(),
	})
	if err != nil {
		t.Fatalf("StoreKey: %v", err)
	}

	// Filter for HSM — the SOFTWARE key should NOT match, triggering return false
	keys, err := store.ListKeys(ctx, map[string]interface{}{
		"provider_type": KeyProviderType_KEY_PROVIDER_TYPE_HSM,
	})
	if err != nil {
		t.Fatalf("ListKeys: %v", err)
	}
	if len(keys) != 0 {
		t.Errorf("expected 0 keys for HSM filter, got %d", len(keys))
	}
}
