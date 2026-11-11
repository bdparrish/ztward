//go:build !fips

package key_manager

import (
	"context"
	"testing"
	"time"

	"github.com/bdparrish/ztward/go/pkg/security/encryption"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func TestRotationManager_PerformRotation_KeyNotInStore(t *testing.T) {
	srv := newTestKeyManagerServer(t, encryption.RSA2048)
	ctx := context.Background()

	// Call PerformRotation with a key ID that doesn't exist in the key store
	rm := srv.rotationManager
	_, err := rm.PerformRotation(ctx, "nonexistent-rotation-key")
	if err == nil {
		t.Fatal("expected error for nonexistent key")
	}
}

func TestCoverageGaps2_RotationManager_UpdateRotationJob_TimeBased(t *testing.T) {
	keyStore := NewInMemoryKeyStore()
	factory := NewDefaultProviderFactory(encryption.RSA2048)
	rm := NewDefaultKeyRotationManager(keyStore, factory)

	// Schedule a rotation job first so UpdateRotationJob finds it
	ctx := context.Background()
	err := keyStore.StoreKey(ctx, &Key{
		KeyId:        "rotate-key",
		KeyType:      KeyType_KEY_TYPE_RSA_2048,
		ProviderType: KeyProviderType_KEY_PROVIDER_TYPE_SOFTWARE,
		Status:       KeyStatus_KEY_STATUS_ACTIVE,
		CreatedAt:    timestamppb.Now(),
	})
	if err != nil {
		t.Fatalf("StoreKey: %v", err)
	}

	err = rm.ScheduleRotation("rotate-key", RotationPolicy_ROTATION_POLICY_TIME_BASED, 24*time.Hour)
	if err != nil {
		t.Fatalf("ScheduleRotation: %v", err)
	}

	// UpdateRotationJob with TIME_BASED hits the specific uncovered switch branch
	err = rm.UpdateRotationJob("rotate-key", RotationPolicy_ROTATION_POLICY_TIME_BASED, 48*time.Hour)
	if err != nil {
		t.Fatalf("UpdateRotationJob: %v", err)
	}
}

func TestCoverageGaps2_RotationManager_PerformRotation_GetKeyError(t *testing.T) {
	keyStore := NewInMemoryKeyStore()
	factory := NewDefaultProviderFactory(encryption.RSA2048)
	rm := NewDefaultKeyRotationManager(keyStore, factory)

	ctx := context.Background()

	// First store the key so ScheduleRotation succeeds
	err := keyStore.StoreKey(ctx, &Key{
		KeyId:        "ephemeral-key",
		KeyType:      KeyType_KEY_TYPE_RSA_2048,
		ProviderType: KeyProviderType_KEY_PROVIDER_TYPE_SOFTWARE,
		Status:       KeyStatus_KEY_STATUS_ACTIVE,
		CreatedAt:    timestamppb.Now(),
	})
	if err != nil {
		t.Fatalf("StoreKey: %v", err)
	}

	err = rm.ScheduleRotation("ephemeral-key", RotationPolicy_ROTATION_POLICY_TIME_BASED, 24*time.Hour)
	if err != nil {
		t.Fatalf("ScheduleRotation: %v", err)
	}

	// Now delete the key so PerformRotation's GetKey call fails
	if err := keyStore.DeleteKey(ctx, "ephemeral-key"); err != nil {
		t.Fatalf("DeleteKey: %v", err)
	}

	// PerformRotation will try GetKey("ephemeral-key") → not found → error path (line 258-261)
	_, err = rm.PerformRotation(ctx, "ephemeral-key")
	if err == nil {
		t.Fatal("expected error from PerformRotation for deleted key")
	}
}

func TestCoverageGaps2_RotationManager_PerformRotation_ProviderError(t *testing.T) {
	keyStore := NewInMemoryKeyStore()
	rm := NewDefaultKeyRotationManager(keyStore, &failingProviderFactory{})

	ctx := context.Background()

	// Store the key so GetKey succeeds
	err := keyStore.StoreKey(ctx, &Key{
		KeyId:        "prov-fail-key",
		KeyType:      KeyType_KEY_TYPE_RSA_2048,
		ProviderType: KeyProviderType_KEY_PROVIDER_TYPE_SOFTWARE,
		Status:       KeyStatus_KEY_STATUS_ACTIVE,
		CreatedAt:    timestamppb.Now(),
	})
	if err != nil {
		t.Fatalf("StoreKey: %v", err)
	}

	err = rm.ScheduleRotation("prov-fail-key", RotationPolicy_ROTATION_POLICY_TIME_BASED, 24*time.Hour)
	if err != nil {
		t.Fatalf("ScheduleRotation: %v", err)
	}

	// PerformRotation: GetKey succeeds, then GetProvider fails (line 269-271)
	_, err = rm.PerformRotation(ctx, "prov-fail-key")
	if err == nil {
		t.Fatal("expected error from PerformRotation when provider is unavailable")
	}
}
