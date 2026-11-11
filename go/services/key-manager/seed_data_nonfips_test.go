//go:build !fips

package key_manager

import (
	"testing"

	"github.com/bdparrish/ztward/go/pkg/security/encryption"
)

func TestCoverageGaps2_SeedData_InvalidProviderType(t *testing.T) {
	srv := newTestKeyManagerServer(t, encryption.RSA2048)

	seed := &KeyManagerSeedData{
		Keys: []KeySeed{
			{
				Name:         "test-key-bad-provider",
				KeyType:      "RSA_2048",
				ProviderType: "NONEXISTENT_PROVIDER_TYPE",
			},
		},
	}
	// applyKeyManagerSeedData should warn about invalid provider_type but not return error
	err := srv.applyKeyManagerSeedData(seed, KeyType_KEY_TYPE_RSA_2048)
	if err != nil {
		t.Fatalf("applyKeyManagerSeedData unexpected error: %v", err)
	}
}

func TestCoverageGaps2_SeedData_InvalidRotationPolicy(t *testing.T) {
	srv := newTestKeyManagerServer(t, encryption.RSA2048)

	seed := &KeyManagerSeedData{
		Keys: []KeySeed{
			{
				Name:           "test-key-bad-rotation",
				KeyType:        "RSA_2048",
				RotationPolicy: "NONEXISTENT_ROTATION_POLICY",
			},
		},
	}
	err := srv.applyKeyManagerSeedData(seed, KeyType_KEY_TYPE_RSA_2048)
	if err != nil {
		t.Fatalf("applyKeyManagerSeedData unexpected error: %v", err)
	}
}

func TestCoverageGaps2_SeedData_CreateKeyFails(t *testing.T) {
	srv := newTestKeyManagerServerWithFIPS(t, encryption.RSA2048, true)

	seed := &KeyManagerSeedData{
		Keys: []KeySeed{
			{
				Name:    "ecc-key-fips-should-fail",
				KeyType: "ECC_P256",
			},
		},
	}
	// In FIPS mode CreateKey for ECC should fail, triggering the error log path
	err := srv.applyKeyManagerSeedData(seed, KeyType_KEY_TYPE_ECC_P256)
	if err != nil {
		t.Fatalf("applyKeyManagerSeedData unexpected top-level error: %v", err)
	}
}
