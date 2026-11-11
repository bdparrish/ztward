//go:build !fips

package key_manager

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"strings"
	"testing"

	"github.com/bdparrish/ztward/go/pkg/security/encryption"
	"github.com/cloudflare/circl/kem/kyber/kyber1024"
	"github.com/cloudflare/circl/kem/kyber/kyber512"
	"github.com/cloudflare/circl/kem/kyber/kyber768"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func TestUnwrapDEK_FIPSRejectsNonRSAKey(t *testing.T) {
	ctx := context.Background()
	srv := newTestKeyManagerServerWithFIPS(t, encryption.RSA2048, true)

	// Seed an ECC key into the key store so it can be found
	eccKey := &Key{
		KeyId:        "ecc-key-1",
		KeyType:      KeyType_KEY_TYPE_ECC_P256,
		ProviderType: KeyProviderType_KEY_PROVIDER_TYPE_SOFTWARE,
		Status:       KeyStatus_KEY_STATUS_ACTIVE,
		CreatedAt:    timestamppb.Now(),
	}
	if err := srv.keyStore.StoreKey(ctx, eccKey); err != nil {
		t.Fatalf("seed ECC key: %v", err)
	}

	resp, err := srv.dekService.UnwrapDEK(ctx, &UnwrapDEKRequest{
		Subject:      "test-user",
		Resource:     "test-resource",
		KeyId:        "ecc-key-1",
		EncryptedDek: []byte("fake-encrypted-dek"),
		ClientKeyId:  "client-1",
		Action:       "unwrap_dek",
	})
	if err != nil {
		t.Fatalf("UnwrapDEK returned error: %v", err)
	}
	if resp.AccessGranted {
		t.Error("expected access denied for ECC key in FIPS mode")
	}
	if !strings.Contains(resp.AccessReason, "not allowed in FIPS mode") {
		t.Errorf("expected FIPS rejection reason, got: %s", resp.AccessReason)
	}
}

func TestUnwrapDEK_ProviderFactoryError(t *testing.T) {
	ctx := context.Background()
	srv := newTestKeyManagerServer(t, encryption.RSA2048)

	// Seed a key with a provider type the factory doesn't support (use a large int)
	key := &Key{
		KeyId:        "hsm-key-1",
		KeyType:      KeyType_KEY_TYPE_RSA_2048,
		ProviderType: KeyProviderType(9999), // truly unknown provider
		Status:       KeyStatus_KEY_STATUS_ACTIVE,
		CreatedAt:    timestamppb.Now(),
	}
	if err := srv.keyStore.StoreKey(ctx, key); err != nil {
		t.Fatalf("seed key: %v", err)
	}

	resp, err := srv.dekService.UnwrapDEK(ctx, &UnwrapDEKRequest{
		Subject:      "test-user",
		Resource:     "test-resource",
		KeyId:        "hsm-key-1",
		EncryptedDek: []byte("fake-encrypted-dek"),
		ClientKeyId:  "client-1",
		Action:       "unwrap_dek",
	})
	if err != nil {
		t.Fatalf("UnwrapDEK returned error: %v", err)
	}
	if resp.AccessGranted {
		t.Error("expected access denied for unknown provider type")
	}
	if !strings.Contains(resp.AccessReason, "Failed to create key provider") {
		t.Errorf("expected provider factory error reason, got: %s", resp.AccessReason)
	}
}

func TestEncryptDEKForSubject_FIPSRejectsNonApprovedKey(t *testing.T) {
	svc := &DEKUnwrappingService{fipsEnabled: true}
	edPub, _, _ := ed25519.GenerateKey(rand.Reader)
	subjectKey := &Key{KeyType: KeyType_KEY_TYPE_UNSPECIFIED}

	_, _, err := svc.encryptDEKForSubject(subjectKey, edPub, []byte("test-dek"), "subject-1")
	if err == nil {
		t.Fatal("expected error for non-approved subject key in FIPS mode")
	}
	if !strings.Contains(err.Error(), "not allowed in FIPS mode") {
		t.Errorf("expected FIPS rejection, got: %v", err)
	}
}

func TestEncryptDEKForSubject_UnsupportedKeyType_Ed25519(t *testing.T) {
	svc := &DEKUnwrappingService{fipsEnabled: false}
	_, edPub, _ := ed25519.GenerateKey(rand.Reader)
	subjectKey := &Key{KeyType: KeyType_KEY_TYPE_UNSPECIFIED}

	_, _, err := svc.encryptDEKForSubject(subjectKey, edPub, []byte("test-dek"), "subject-1")
	if err == nil {
		t.Fatal("expected error for ed25519 (unsupported) subject key type")
	}
	if !strings.Contains(err.Error(), "unsupported public key type") {
		t.Errorf("expected unsupported key type error, got: %v", err)
	}
}

func TestDEKPublicKeyToPEM_Ed25519(t *testing.T) {
	_, edPub, _ := ed25519.GenerateKey(rand.Reader)
	_, _, err := publicKeyToPEM(edPub)
	if err == nil {
		t.Fatal("expected error for ed25519 key")
	}
	if !strings.Contains(err.Error(), "unsupported public key type") {
		t.Errorf("expected unsupported key type error, got: %v", err)
	}
}

func TestCoverageGaps2_DEKService_FIPS_RejectsKyberServiceKey(t *testing.T) {
	ctx := context.Background()

	// Create a FIPS-enabled server
	srv := newTestKeyManagerServerWithFIPS(t, encryption.RSA2048, true)

	// Seed a Kyber-512 key directly into the key store (bypassing FIPS validation)
	kyberKey := &Key{
		KeyId:        "kyber-fips-test-key",
		KeyType:      KeyType_KEY_TYPE_KYBER_512,
		ProviderType: KeyProviderType_KEY_PROVIDER_TYPE_SOFTWARE,
		Status:       KeyStatus_KEY_STATUS_ACTIVE,
		CreatedAt:    timestamppb.Now(),
	}
	if err := srv.keyStore.StoreKey(ctx, kyberKey); err != nil {
		t.Fatalf("StoreKey: %v", err)
	}

	// UnwrapDEK should return denied because Kyber is not FIPS-allowed
	req := &UnwrapDEKRequest{
		Subject:      "user1",
		Resource:     "resource1",
		KeyId:        "kyber-fips-test-key",
		ClientKeyId:  "client-key-1",
		EncryptedDek: []byte("dummy-dek"),
	}
	resp, err := srv.dekService.UnwrapDEK(ctx, req)
	if err != nil {
		t.Fatalf("UnwrapDEK unexpected error: %v", err)
	}
	if resp.AccessGranted {
		t.Error("UnwrapDEK should deny access for Kyber key in FIPS mode")
	}
	if !strings.Contains(resp.AccessReason, "not allowed in FIPS mode") {
		t.Errorf("expected FIPS denial reason, got: %s", resp.AccessReason)
	}
}

func TestCoverageGaps2_DEKService_ProviderFactoryFailure(t *testing.T) {
	ctx := context.Background()

	keyStore := NewInMemoryKeyStore()
	clientKeyStore := NewInMemoryClientKeyStore()

	// Seed a key into the store
	serviceKey := &Key{
		KeyId:        "no-provider-key",
		KeyType:      KeyType_KEY_TYPE_RSA_2048,
		ProviderType: KeyProviderType_KEY_PROVIDER_TYPE_SOFTWARE,
		Status:       KeyStatus_KEY_STATUS_ACTIVE,
		CreatedAt:    timestamppb.Now(),
	}
	if err := keyStore.StoreKey(ctx, serviceKey); err != nil {
		t.Fatalf("StoreKey: %v", err)
	}

	// Create DEKUnwrappingService with a factory that always fails GetProvider
	dekSvc := NewDEKUnwrappingService(keyStore, &failingProviderFactory{}, clientKeyStore, false)

	req := &UnwrapDEKRequest{
		Subject:      "user1",
		Resource:     "resource1",
		KeyId:        "no-provider-key",
		ClientKeyId:  "ck1",
		EncryptedDek: []byte("dummy-encrypted-dek"),
	}
	resp, err := dekSvc.UnwrapDEK(ctx, req)
	if err != nil {
		t.Fatalf("UnwrapDEK unexpected error: %v", err)
	}
	if resp.AccessGranted {
		t.Error("UnwrapDEK should deny access when provider factory fails")
	}
	if !strings.Contains(resp.AccessReason, "Failed to create key provider") {
		t.Errorf("expected provider failure reason, got: %s", resp.AccessReason)
	}
}

func TestCoverageGaps2_DEKService_RegisterClientPublicKey_BadDER(t *testing.T) {
	srv := newTestKeyManagerServer(t, encryption.RSA2048)

	// A PEM block that decodes successfully but contains garbage DER bytes
	badDERPEM := string(pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: []byte("this-is-not-valid-der-asn1-data"),
	}))

	err := srv.dekService.RegisterClientPublicKey(context.Background(), "user1", badDERPEM)
	if err == nil {
		t.Fatal("expected error for bad DER in RegisterClientPublicKey")
	}
	if !strings.Contains(err.Error(), "failed to parse public key") {
		t.Errorf("expected 'failed to parse public key' error, got: %v", err)
	}
}

func TestCoverageGaps2_DEKService_UnwrapDEK_EncryptForSubjectFails(t *testing.T) {
	ctx := context.Background()
	srv := newTestKeyManagerServer(t, encryption.RSA2048)

	// Create a service key that can actually decrypt a DEK
	createResp, err := srv.CreateKey(ctx, &CreateKeyRequest{
		Name:         "service-key-for-ed25519-test",
		KeyType:      KeyType_KEY_TYPE_RSA_2048,
		ProviderType: KeyProviderType_KEY_PROVIDER_TYPE_SOFTWARE,
	})
	if err != nil {
		t.Fatalf("CreateKey: %v", err)
	}
	keyID := createResp.Key.KeyId

	// Encrypt a DEK with the service key
	provider, err := srv.providerFactory.GetProvider(KeyProviderType_KEY_PROVIDER_TYPE_SOFTWARE)
	if err != nil {
		t.Fatalf("GetProvider: %v", err)
	}
	plainDEK := []byte("test-dek-32-bytes-padding-xyz123")
	encryptedDEK, err := provider.Encrypt(ctx, keyID, plainDEK)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	// Generate an Ed25519 public key — x509.ParsePKIXPublicKey returns ed25519.PublicKey
	// which is not *rsa.PublicKey or *ecdsa.PublicKey, so encryptDEKForSubject hits default.
	edPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate Ed25519 key: %v", err)
	}
	edDERBytes, err := x509.MarshalPKIXPublicKey(edPub)
	if err != nil {
		t.Fatalf("marshal Ed25519 public key: %v", err)
	}
	edPEM := string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: edDERBytes}))

	// Register the Ed25519 key as a client key directly (bypassing type checks)
	clientKeyID := "ed25519-client-key"
	clientKey := &Key{
		KeyId:        clientKeyID,
		ClientId:     "ed25519-user",
		PublicKeyPem: edPEM,
		KeyType:      KeyType_KEY_TYPE_UNSPECIFIED, // unknown so parsePublicKeyPEM hits default fallback
		Status:       KeyStatus_KEY_STATUS_ACTIVE,
		CreatedAt:    timestamppb.Now(),
		Metadata:     make(map[string]string),
	}
	if err := srv.clientKeyStore.RegisterKey(ctx, clientKey); err != nil {
		t.Fatalf("RegisterKey (Ed25519 client): %v", err)
	}

	req := &UnwrapDEKRequest{
		Subject:      "ed25519-user",
		Resource:     "resource1",
		KeyId:        keyID,
		ClientKeyId:  clientKeyID,
		EncryptedDek: encryptedDEK,
	}
	resp, err := srv.dekService.UnwrapDEK(ctx, req)
	if err != nil {
		t.Fatalf("UnwrapDEK unexpected error: %v", err)
	}
	if resp.AccessGranted {
		t.Error("UnwrapDEK should deny when encryptDEKForSubject fails for Ed25519 key")
	}
}

// TestPublicKeyToPEMForKyber_Default covers the default (non-Kyber) path.
func TestPublicKeyToPEMForKyber_Default(t *testing.T) {
	provider := NewSoftwareKeyProvider(nil)
	_, handled, err := provider.publicKeyToPEMForKyber("not-a-kyber-key")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if handled {
		t.Fatal("expected handled=false for non-Kyber key")
	}
}

// TestPublicKeyToPEMForKyber_All covers all three Kyber public key conversions.
func TestPublicKeyToPEMForKyber_All(t *testing.T) {
	provider := NewSoftwareKeyProvider(nil)

	pub512, _, _ := kyber512.GenerateKeyPair(rand.Reader)
	pemStr, handled, err := provider.publicKeyToPEMForKyber(pub512)
	if err != nil || !handled || pemStr == "" {
		t.Fatalf("publicKeyToPEMForKyber kyber512 failed: handled=%v err=%v", handled, err)
	}

	pub768, _, _ := kyber768.GenerateKeyPair(rand.Reader)
	pemStr, handled, err = provider.publicKeyToPEMForKyber(pub768)
	if err != nil || !handled || pemStr == "" {
		t.Fatalf("publicKeyToPEMForKyber kyber768 failed: handled=%v err=%v", handled, err)
	}

	pub1024, _, _ := kyber1024.GenerateKeyPair(rand.Reader)
	pemStr, handled, err = provider.publicKeyToPEMForKyber(pub1024)
	if err != nil || !handled || pemStr == "" {
		t.Fatalf("publicKeyToPEMForKyber kyber1024 failed: handled=%v err=%v", handled, err)
	}
}
