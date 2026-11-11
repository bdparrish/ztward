//go:build !fips

package key_manager

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"strings"
	"testing"

	"github.com/cloudflare/circl/kem/kyber/kyber512"
	"github.com/cloudflare/circl/kem/kyber/kyber768"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func TestClientKeyStore_PublicKeyToPEM_RSA1024(t *testing.T) {
	store := NewInMemoryClientKeyStore()
	priv, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatalf("generate RSA-1024: %v", err)
	}
	_, _, err = store.publicKeyToPEM(&priv.PublicKey)
	if err == nil {
		t.Fatal("expected error for RSA-1024")
	}
	if !strings.Contains(err.Error(), "unsupported RSA key size") {
		t.Errorf("expected unsupported RSA size, got: %v", err)
	}
}

func TestClientKeyStore_PublicKeyToPEM_ECCP224(t *testing.T) {
	store := NewInMemoryClientKeyStore()
	priv, err := ecdsa.GenerateKey(elliptic.P224(), rand.Reader)
	if err != nil {
		t.Fatalf("generate P224: %v", err)
	}
	_, _, err = store.publicKeyToPEM(&priv.PublicKey)
	if err == nil {
		t.Fatal("expected error for P-224")
	}
	if !strings.Contains(err.Error(), "unsupported ECC curve") {
		t.Errorf("expected unsupported ECC curve, got: %v", err)
	}
}

func TestClientKeyStore_PublicKeyToPEM_Ed25519(t *testing.T) {
	store := NewInMemoryClientKeyStore()
	_, edPub, _ := ed25519.GenerateKey(rand.Reader)
	_, _, err := store.publicKeyToPEM(edPub)
	if err == nil {
		t.Fatal("expected error for ed25519 key")
	}
	if !strings.Contains(err.Error(), "unsupported public key type") {
		t.Errorf("expected unsupported key type error, got: %v", err)
	}
}

func TestStoreClientPublicKey_UnsupportedKeyType(t *testing.T) {
	store := NewInMemoryClientKeyStore()
	_, edPub, _ := ed25519.GenerateKey(rand.Reader)
	err := store.StoreClientPublicKey(context.Background(), "subject-1", edPub)
	if err == nil {
		t.Fatal("expected error for ed25519 key")
	}
	if !strings.Contains(err.Error(), "failed to convert public key to PEM") {
		t.Errorf("expected conversion error, got: %v", err)
	}
}

func TestGetClientPublicKey_ParseError(t *testing.T) {
	store := NewInMemoryClientKeyStore()
	ctx := context.Background()

	// Register a valid key first, then corrupt the PEM in-place
	rsaPriv, _ := rsa.GenerateKey(rand.Reader, 2048)
	derBytes, _ := x509.MarshalPKIXPublicKey(&rsaPriv.PublicKey)
	validPEM := string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: derBytes}))
	goodKey := &Key{
		KeyId:        "bad-pem-key",
		ClientId:     "bad-user",
		PublicKeyPem: validPEM,
		KeyType:      KeyType_KEY_TYPE_RSA_2048,
		Status:       KeyStatus_KEY_STATUS_ACTIVE,
		CreatedAt:    timestamppb.Now(),
	}
	if err := store.RegisterKey(ctx, goodKey); err != nil {
		t.Fatalf("RegisterKey: %v", err)
	}
	// Now corrupt the PEM and clear the parsed key cache
	store.mu.Lock()
	if k, ok := store.keys["bad-pem-key"]; ok {
		k.PublicKeyPem = "not-valid-pem"
	}
	delete(store.parsedKeyCache, "bad-pem-key")
	store.mu.Unlock()

	_, err := store.GetClientPublicKey(ctx, "bad-user")
	if err == nil {
		t.Fatal("expected error for bad PEM in GetClientPublicKey")
	}
	if !strings.Contains(err.Error(), "failed to parse public key") {
		t.Errorf("expected parse error, got: %v", err)
	}
}

func TestParsePublicKeyPEM_RSAPEMAsECC(t *testing.T) {
	store := NewInMemoryClientKeyStore()
	// Generate RSA PEM
	rsaPriv, _ := rsa.GenerateKey(rand.Reader, 2048)
	derBytes, _ := x509.MarshalPKIXPublicKey(&rsaPriv.PublicKey)
	pemStr := string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: derBytes}))

	// Try to parse as ECC - should fail with type mismatch
	_, err := store.parsePublicKeyPEM(pemStr, KeyType_KEY_TYPE_ECC_P256)
	if err == nil {
		t.Fatal("expected error parsing RSA PEM as ECC key type")
	}
	if !strings.Contains(err.Error(), "expected ECDSA public key") {
		t.Errorf("expected ECDSA type mismatch error, got: %v", err)
	}
}

func TestParsePublicKeyPEM_ECCPEMAsRSA(t *testing.T) {
	store := NewInMemoryClientKeyStore()
	// Generate ECC PEM
	eccPriv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	derBytes, _ := x509.MarshalPKIXPublicKey(&eccPriv.PublicKey)
	pemStr := string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: derBytes}))

	// Try to parse as RSA - should fail with type mismatch
	_, err := store.parsePublicKeyPEM(pemStr, KeyType_KEY_TYPE_RSA_2048)
	if err == nil {
		t.Fatal("expected error parsing ECC PEM as RSA key type")
	}
	if !strings.Contains(err.Error(), "expected RSA public key") {
		t.Errorf("expected RSA type mismatch error, got: %v", err)
	}
}

func TestParsePublicKeyPEM_InvalidDERForECC(t *testing.T) {
	store := NewInMemoryClientKeyStore()
	badPEM := string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: []byte("garbage")}))
	_, err := store.parsePublicKeyPEM(badPEM, KeyType_KEY_TYPE_ECC_P256)
	if err == nil {
		t.Fatal("expected error for invalid DER in ECC parsePublicKeyPEM")
	}
}

func TestParsePublicKeyPEM_KyberInvalidSize(t *testing.T) {
	store := NewInMemoryClientKeyStore()
	badPEM := string(pem.EncodeToMemory(&pem.Block{Type: "KYBER PUBLIC KEY", Bytes: []byte("short")}))
	_, err := store.parsePublicKeyPEM(badPEM, KeyType_KEY_TYPE_KYBER_512)
	if err == nil {
		t.Fatal("expected error for invalid Kyber key size")
	}
}

// TestClientKeyStore_PublicKeyToPEM_RSA3072 covers the RSA-3072 branch.
func TestClientKeyStore_PublicKeyToPEM_RSA3072(t *testing.T) {
	store := NewInMemoryClientKeyStore()
	priv, err := rsa.GenerateKey(rand.Reader, 3072)
	if err != nil {
		t.Fatalf("GenerateKey RSA-3072: %v", err)
	}
	pemStr, kt, err := store.publicKeyToPEM(&priv.PublicKey)
	if err != nil {
		t.Fatalf("publicKeyToPEM RSA-3072 error = %v", err)
	}
	if kt != KeyType_KEY_TYPE_RSA_3072 {
		t.Errorf("expected KEY_TYPE_RSA_3072, got %v", kt)
	}
	if pemStr == "" {
		t.Error("expected non-empty PEM")
	}
}

// TestClientKeyStore_PublicKeyToPEM_RSA4096 covers the RSA-4096 branch.
func TestClientKeyStore_PublicKeyToPEM_RSA4096(t *testing.T) {
	store := NewInMemoryClientKeyStore()
	priv, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		t.Fatalf("GenerateKey RSA-4096: %v", err)
	}
	pemStr, kt, err := store.publicKeyToPEM(&priv.PublicKey)
	if err != nil {
		t.Fatalf("publicKeyToPEM RSA-4096 error = %v", err)
	}
	if kt != KeyType_KEY_TYPE_RSA_4096 {
		t.Errorf("expected KEY_TYPE_RSA_4096, got %v", kt)
	}
	if pemStr == "" {
		t.Error("expected non-empty PEM")
	}
}

// TestClientKeyStore_PublicKeyToPEM_ECCP384 covers the ECC P-384 branch.
func TestClientKeyStore_PublicKeyToPEM_ECCP384(t *testing.T) {
	store := NewInMemoryClientKeyStore()
	priv, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey P384: %v", err)
	}
	pemStr, kt, err := store.publicKeyToPEM(&priv.PublicKey)
	if err != nil {
		t.Fatalf("publicKeyToPEM P384 error = %v", err)
	}
	if kt != KeyType_KEY_TYPE_ECC_P384 {
		t.Errorf("expected KEY_TYPE_ECC_P384, got %v", kt)
	}
	if pemStr == "" {
		t.Error("expected non-empty PEM")
	}
}

// TestClientKeyStore_PublicKeyToPEM_ECCP521 covers the ECC P-521 branch.
func TestClientKeyStore_PublicKeyToPEM_ECCP521(t *testing.T) {
	store := NewInMemoryClientKeyStore()
	priv, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey P521: %v", err)
	}
	pemStr, kt, err := store.publicKeyToPEM(&priv.PublicKey)
	if err != nil {
		t.Fatalf("publicKeyToPEM P521 error = %v", err)
	}
	if kt != KeyType_KEY_TYPE_ECC_P521 {
		t.Errorf("expected KEY_TYPE_ECC_P521, got %v", kt)
	}
	if pemStr == "" {
		t.Error("expected non-empty PEM")
	}
}

// TestClientKeyStore_PublicKeyToPEM_KyberKey covers the Kyber public key branch.
func TestClientKeyStore_PublicKeyToPEM_KyberKey(t *testing.T) {
	store := NewInMemoryClientKeyStore()
	pub512, _, err := kyber512.GenerateKeyPair(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKeyPair kyber512: %v", err)
	}

	pemStr, kt, err := store.publicKeyToPEM(pub512)
	if err != nil {
		t.Fatalf("publicKeyToPEM Kyber512 error = %v", err)
	}
	if kt != KeyType_KEY_TYPE_KYBER_512 {
		t.Errorf("expected KEY_TYPE_KYBER_512, got %v", kt)
	}
	if pemStr == "" {
		t.Error("expected non-empty PEM")
	}
}

// TestClientKeyStore_PublicKeyToPEM_UnsupportedType covers the unsupported key type branch.
func TestClientKeyStore_PublicKeyToPEM_UnsupportedType(t *testing.T) {
	store := NewInMemoryClientKeyStore()
	type weirdKey struct{}
	_, _, err := store.publicKeyToPEM(weirdKey{})
	if err == nil {
		t.Fatal("expected error for unsupported public key type")
	}
}

// TestStoreClientPublicKey_RSA exercises StoreClientPublicKey with RSA key.
func TestStoreClientPublicKey_RSA(t *testing.T) {
	store := NewInMemoryClientKeyStore()
	ctx := context.Background()

	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	err = store.StoreClientPublicKey(ctx, "alice-store-rsa", &priv.PublicKey)
	if err != nil {
		t.Fatalf("StoreClientPublicKey: %v", err)
	}

	// Retrieve back
	pubKey, err := store.GetClientPublicKey(ctx, "alice-store-rsa")
	if err != nil {
		t.Fatalf("GetClientPublicKey: %v", err)
	}
	if pubKey == nil {
		t.Fatal("expected non-nil public key")
	}
}

// TestStoreClientPublicKey_ECC exercises StoreClientPublicKey with ECC key.
func TestStoreClientPublicKey_ECC(t *testing.T) {
	store := NewInMemoryClientKeyStore()
	ctx := context.Background()

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	err = store.StoreClientPublicKey(ctx, "bob-store-ecc", &priv.PublicKey)
	if err != nil {
		t.Fatalf("StoreClientPublicKey ECC: %v", err)
	}
}

// TestStoreClientPublicKey_Kyber exercises StoreClientPublicKey with Kyber key.
func TestStoreClientPublicKey_Kyber(t *testing.T) {
	store := NewInMemoryClientKeyStore()
	ctx := context.Background()

	pub, _, err := kyber768.GenerateKeyPair(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKeyPair kyber768: %v", err)
	}

	err = store.StoreClientPublicKey(ctx, "charlie-store-kyber", pub)
	if err != nil {
		t.Fatalf("StoreClientPublicKey Kyber768: %v", err)
	}
}

// TestStoreClientPublicKey_EmptySubject covers the empty subject branch.
func TestStoreClientPublicKey_EmptySubject(t *testing.T) {
	store := NewInMemoryClientKeyStore()
	ctx := context.Background()

	priv, _ := rsa.GenerateKey(rand.Reader, 2048)
	err := store.StoreClientPublicKey(ctx, "", &priv.PublicKey)
	if err == nil {
		t.Fatal("expected error for empty subject")
	}
}

// TestStoreClientPublicKey_NilKey covers the nil key branch.
func TestStoreClientPublicKey_NilKey(t *testing.T) {
	store := NewInMemoryClientKeyStore()
	ctx := context.Background()

	err := store.StoreClientPublicKey(ctx, "dave-nil-key", nil)
	if err == nil {
		t.Fatal("expected error for nil public key")
	}
}

// TestGetClientPublicKey_CacheMiss covers the "not cached → parse" path.
func TestGetClientPublicKey_CacheMiss(t *testing.T) {
	store := NewInMemoryClientKeyStore()
	ctx := context.Background()

	priv, _ := rsa.GenerateKey(rand.Reader, 2048)
	der, _ := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	pemStr := string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))

	key := &Key{
		KeyId:        "cache-miss-key",
		ClientId:     "alice-cache",
		PublicKeyPem: pemStr,
		KeyType:      KeyType_KEY_TYPE_RSA_2048,
		Status:       KeyStatus_KEY_STATUS_ACTIVE,
		CreatedAt:    timestamppb.Now(),
	}
	if err := store.RegisterKey(ctx, key); err != nil {
		t.Fatalf("RegisterKey: %v", err)
	}

	// Delete from cache to force re-parse
	store.mu.Lock()
	delete(store.parsedKeyCache, "cache-miss-key")
	store.mu.Unlock()

	pub, err := store.GetClientPublicKey(ctx, "alice-cache")
	if err != nil {
		t.Fatalf("GetClientPublicKey (cache miss): %v", err)
	}
	if pub == nil {
		t.Fatal("expected non-nil public key")
	}
}

// TestListKeysForClient_OrphanKeyID covers the `if !exists { continue }` branch.
func TestListKeysForClient_OrphanKeyID(t *testing.T) {
	store := NewInMemoryClientKeyStore()
	ctx := context.Background()

	// Insert orphan keyID
	store.mu.Lock()
	store.clientKeys["orphan-list-user"] = []string{"missing-key-id"}
	store.mu.Unlock()

	keys, err := store.ListKeysForClient(ctx, "orphan-list-user", true)
	if err != nil {
		t.Fatalf("ListKeysForClient unexpected error: %v", err)
	}
	if len(keys) != 0 {
		t.Errorf("expected 0 keys for orphan user, got %d", len(keys))
	}
}

func TestCoverageGaps2_ClientKeyStore_StoreRSA1024(t *testing.T) {
	store := NewInMemoryClientKeyStore()
	priv, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatalf("generate RSA-1024: %v", err)
	}
	// StoreClientPublicKey calls publicKeyToPEM internally – RSA-1024 must fail.
	err = store.StoreClientPublicKey(context.Background(), "user1", &priv.PublicKey)
	if err == nil {
		t.Fatal("expected error for RSA-1024 in StoreClientPublicKey")
	}
	if !strings.Contains(err.Error(), "unsupported RSA") {
		t.Errorf("expected 'unsupported RSA' error, got: %v", err)
	}
}

// Also test publicKeyToPEM directly for RSA-1024.
func TestCoverageGaps2_ClientKeyStore_PublicKeyToPEM_RSA1024(t *testing.T) {
	store := NewInMemoryClientKeyStore()
	priv, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatalf("generate RSA-1024: %v", err)
	}
	_, _, err = store.publicKeyToPEM(&priv.PublicKey)
	if err == nil {
		t.Fatal("expected error for RSA-1024 in publicKeyToPEM")
	}
	if !strings.Contains(err.Error(), "unsupported RSA") {
		t.Errorf("expected 'unsupported RSA' error, got: %v", err)
	}
}

func TestCoverageGaps2_ClientKeyStore_StoreECCP224(t *testing.T) {
	store := NewInMemoryClientKeyStore()
	priv, err := ecdsa.GenerateKey(elliptic.P224(), rand.Reader)
	if err != nil {
		t.Fatalf("generate P-224: %v", err)
	}
	err = store.StoreClientPublicKey(context.Background(), "user2", &priv.PublicKey)
	if err == nil {
		t.Fatal("expected error for P-224 in StoreClientPublicKey")
	}
	if !strings.Contains(err.Error(), "unsupported ECC curve") {
		t.Errorf("expected 'unsupported ECC curve' error, got: %v", err)
	}
}

// Also test publicKeyToPEM directly for P-224.
func TestCoverageGaps2_ClientKeyStore_PublicKeyToPEM_P224(t *testing.T) {
	store := NewInMemoryClientKeyStore()
	priv, err := ecdsa.GenerateKey(elliptic.P224(), rand.Reader)
	if err != nil {
		t.Fatalf("generate P-224: %v", err)
	}
	_, _, err = store.publicKeyToPEM(&priv.PublicKey)
	if err == nil {
		t.Fatal("expected error for P-224 in publicKeyToPEM")
	}
	if !strings.Contains(err.Error(), "unsupported ECC curve") {
		t.Errorf("expected 'unsupported ECC curve' error, got: %v", err)
	}
}

func TestCoverageGaps2_ClientKeyStore_ParsePublicKeyPEM_KyberBadBytes(t *testing.T) {
	store := NewInMemoryClientKeyStore()

	// Encode garbage bytes as a PEM block so pem.Decode succeeds
	// but parseKyberPublicKeyFromPEM fails (bad Kyber bytes).
	garbageBytes := []byte("this-is-not-a-real-kyber-public-key")
	pemData := string(pem.EncodeToMemory(&pem.Block{
		Type:  "KYBER-512 PUBLIC KEY",
		Bytes: garbageBytes,
	}))

	_, err := store.parsePublicKeyPEM(pemData, KeyType_KEY_TYPE_KYBER_512)
	if err == nil {
		t.Fatal("expected error parsing invalid Kyber public key PEM")
	}
}

func TestCoverageGaps2_ClientKeyStore_GetClientPublicKey_ParseError(t *testing.T) {
	store := NewInMemoryClientKeyStore()
	ctx := context.Background()

	// Register a valid RSA-2048 key
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate RSA-2048: %v", err)
	}
	err = store.StoreClientPublicKey(ctx, "parse-error-subject", &priv.PublicKey)
	if err != nil {
		t.Fatalf("StoreClientPublicKey: %v", err)
	}

	// Find the stored key and tamper with its PublicKeyPem to be invalid
	activeKey, err := store.GetActiveKeyForClient(ctx, "parse-error-subject")
	if err != nil {
		t.Fatalf("GetActiveKeyForClient: %v", err)
	}

	store.mu.Lock()
	if k, ok := store.keys[activeKey.KeyId]; ok {
		k.PublicKeyPem = string(pem.EncodeToMemory(&pem.Block{
			Type:  "PUBLIC KEY",
			Bytes: []byte("not-valid-der-bytes"),
		}))
	}
	// Clear the parsed key cache so it must re-parse
	delete(store.parsedKeyCache, activeKey.KeyId)
	store.mu.Unlock()

	// GetClientPublicKey should now fail when trying to parse the tampered PEM
	_, err = store.GetClientPublicKey(ctx, "parse-error-subject")
	if err == nil {
		t.Fatal("expected error when parsing tampered public key PEM")
	}
}

// TestParsePublicKeyPEM_RSA3072 covers the RSA-3072 parse branch.
func TestParsePublicKeyPEM_RSA3072(t *testing.T) {
	store := NewInMemoryClientKeyStore()
	pemStr := makeRSAPubKeyPEM(t, 3072)

	key, err := store.parsePublicKeyPEM(pemStr, KeyType_KEY_TYPE_RSA_3072)
	if err != nil {
		t.Fatalf("parsePublicKeyPEM RSA3072 error = %v", err)
	}
	if key == nil {
		t.Fatal("expected non-nil key")
	}
}

// TestParsePublicKeyPEM_RSA4096 covers the RSA-4096 parse branch.
func TestParsePublicKeyPEM_RSA4096(t *testing.T) {
	store := NewInMemoryClientKeyStore()
	pemStr := makeRSAPubKeyPEM(t, 4096)

	key, err := store.parsePublicKeyPEM(pemStr, KeyType_KEY_TYPE_RSA_4096)
	if err != nil {
		t.Fatalf("parsePublicKeyPEM RSA4096 error = %v", err)
	}
	if key == nil {
		t.Fatal("expected non-nil key")
	}
}

// TestParsePublicKeyPEM_InvalidPEM covers the nil block error.
func TestParsePublicKeyPEM_InvalidPEM(t *testing.T) {
	store := NewInMemoryClientKeyStore()

	_, err := store.parsePublicKeyPEM("not-a-pem", KeyType_KEY_TYPE_RSA_2048)
	if err == nil {
		t.Fatal("expected error for invalid PEM")
	}
}

// TestParsePublicKeyPEM_ECCWrongContent covers the type-assert failure for ECC.
func TestParsePublicKeyPEM_ECCWrongContent(t *testing.T) {
	store := NewInMemoryClientKeyStore()
	// RSA public key PEM passed as ECC type — will parse DER but type assertion fails
	rsaPEM := makeRSAPubKeyPEM(t, 2048)

	_, err := store.parsePublicKeyPEM(rsaPEM, KeyType_KEY_TYPE_ECC_P256)
	if err == nil {
		t.Fatal("expected error when RSA key is parsed as ECC type")
	}
}

// TestParsePublicKeyPEM_RSAWrongContent covers the type-assert failure for RSA.
func TestParsePublicKeyPEM_RSAWrongContent(t *testing.T) {
	store := NewInMemoryClientKeyStore()
	eccPEM := makeECCPubKeyPEM(t, elliptic.P256())

	_, err := store.parsePublicKeyPEM(eccPEM, KeyType_KEY_TYPE_RSA_2048)
	if err == nil {
		t.Fatal("expected error when ECC key is parsed as RSA type")
	}
}

// TestParsePublicKeyPEM_DefaultFallback covers the default generic parse branch.
func TestParsePublicKeyPEM_DefaultFallback(t *testing.T) {
	store := NewInMemoryClientKeyStore()
	// KEY_TYPE_UNSPECIFIED hits the default case — should still parse a valid RSA PEM
	rsaPEM := makeRSAPubKeyPEM(t, 2048)

	key, err := store.parsePublicKeyPEM(rsaPEM, KeyType_KEY_TYPE_UNSPECIFIED)
	if err != nil {
		t.Fatalf("parsePublicKeyPEM default branch error = %v", err)
	}
	if key == nil {
		t.Fatal("expected non-nil key for default branch")
	}
}
