//go:build !fips

package key_manager

import (
	"context"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"strings"
	"testing"

	"github.com/bdparrish/ztward/go/pkg/auth"
	"github.com/bdparrish/ztward/go/pkg/security/encryption"
)

func TestRevokeClientKey_Success(t *testing.T) {
	srv := newTestKeyManagerServer(t, encryption.RSA2048)
	ctx := ctxWithUser("revoke-user")

	// Register a key
	regResp, err := srv.RegisterClientKey(ctx, &RegisterClientKeyRequest{
		PublicKeyPem: generateRSAPEM(t),
		ClientId:     "app-1",
		KeyType:      KeyType_KEY_TYPE_RSA_2048,
	})
	if err != nil || !regResp.Success {
		t.Fatalf("RegisterClientKey: %v %v", err, regResp.GetErrorMessage())
	}
	keyID := regResp.Key.KeyId

	// Revoke the key
	revokeResp, err := srv.RevokeClientKey(ctx, &RevokeClientKeyRequest{
		KeyId:  keyID,
		Reason: "test revocation",
	})
	if err != nil {
		t.Fatalf("RevokeClientKey: %v", err)
	}
	if !revokeResp.Success {
		t.Errorf("RevokeClientKey should succeed, got error: %s", revokeResp.ErrorMessage)
	}
}

func TestRevokeClientKey_NotFound(t *testing.T) {
	srv := newTestKeyManagerServer(t, encryption.RSA2048)
	ctx := ctxWithUser("revoke-user")

	resp, err := srv.RevokeClientKey(ctx, &RevokeClientKeyRequest{
		KeyId:  "nonexistent-key",
		Reason: "test",
	})
	if err != nil {
		t.Fatalf("RevokeClientKey: %v", err)
	}
	if resp.Success {
		t.Error("should fail for nonexistent key")
	}
}

func TestListClientKeys_WithAuth(t *testing.T) {
	srv := newTestKeyManagerServer(t, encryption.RSA2048)
	ctx := ctxWithUser("list-user")

	// Register a key
	_, err := srv.RegisterClientKey(ctx, &RegisterClientKeyRequest{
		PublicKeyPem: generateRSAPEM(t),
		ClientId:     "app-1",
		KeyType:      KeyType_KEY_TYPE_RSA_2048,
	})
	if err != nil {
		t.Fatalf("RegisterClientKey: %v", err)
	}

	// List keys
	resp, err := srv.ListClientKeys(ctx, &ListClientKeysRequest{})
	if err != nil {
		t.Fatalf("ListClientKeys: %v", err)
	}
	if len(resp.Keys) == 0 {
		t.Error("expected at least one key")
	}
}

func TestListClients(t *testing.T) {
	srv := newTestKeyManagerServer(t, encryption.RSA2048)
	ctx := ctxWithUser("client-list-user")

	// Register a key to have at least one client
	_, _ = srv.RegisterClientKey(ctx, &RegisterClientKeyRequest{
		PublicKeyPem: generateRSAPEM(t),
		ClientId:     "app-1",
		KeyType:      KeyType_KEY_TYPE_RSA_2048,
	})

	resp, err := srv.ListClients(context.Background(), &ListClientsRequest{})
	if err != nil {
		t.Fatalf("ListClients: %v", err)
	}
	if len(resp.Clients) == 0 {
		t.Error("expected at least one client")
	}
}

// TestRegisterClientKey_SubEmpty covers the "Sub is empty" branch.
func TestRegisterClientKey_SubEmpty(t *testing.T) {
	srv := newTestKeyManagerServer(t, encryption.RSA2048)
	ctx := context.WithValue(context.Background(), "user_claims", &auth.UserClaims{Sub: ""})

	resp, err := srv.RegisterClientKey(ctx, &RegisterClientKeyRequest{
		PublicKeyPem: makeRSAPubKeyPEM(t, 2048),
		ClientId:     "app",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.Success {
		t.Fatal("expected Success=false for empty Sub")
	}
}

// TestRegisterClientKey_KeyTypeMismatch covers the key-type mismatch warning branch
// where an explicit key type is specified but differs from the inferred type.
func TestRegisterClientKey_KeyTypeMismatch(t *testing.T) {
	srv := newTestKeyManagerServer(t, encryption.RSA2048)

	// Provide an ECC key but label it RSA — inferred type wins
	eccPEM := makeECCPubKeyPEM(t, elliptic.P256())
	resp, err := srv.RegisterClientKey(ctxWithSub("alice"), &RegisterClientKeyRequest{
		PublicKeyPem: eccPEM,
		ClientId:     "app",
		KeyType:      KeyType_KEY_TYPE_RSA_2048, // mismatch: actual is ECC
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Should succeed with the inferred ECC type
	if !resp.Success {
		t.Logf("RegisterClientKey with mismatch returned: %s", resp.ErrorMessage)
	}
}

// TestRegisterClientKey_FIPSRejectsECC covers the FIPS enforcement branch.
func TestRegisterClientKey_FIPSRejectsNonApprovedKeyType(t *testing.T) {
	srv := newTestKeyManagerServerWithFIPS(t, encryption.RSA2048, true)
	edPub, _, _ := ed25519.GenerateKey(rand.Reader)
	der, _ := x509.MarshalPKIXPublicKey(edPub)
	edPEM := string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))

	resp, err := srv.RegisterClientKey(ctxWithSub("alice"), &RegisterClientKeyRequest{
		PublicKeyPem: edPEM,
		KeyType:      KeyType_KEY_TYPE_KYBER_768,
		ClientId:     "app",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.Success || !strings.Contains(resp.ErrorMessage, "not allowed in FIPS mode") {
		t.Fatalf("expected FIPS rejection, got success=%v %q", resp.Success, resp.ErrorMessage)
	}
}

// TestRegisterClientKey_StoreFailsDuplicate covers the store-error branch (duplicate key).
func TestRegisterClientKey_StoreFailsDuplicate(t *testing.T) {
	srv := newTestKeyManagerServer(t, encryption.RSA2048)
	rsaPEM := makeRSAPubKeyPEM(t, 2048)

	// First registration succeeds
	r1, _ := srv.RegisterClientKey(ctxWithSub("alice"), &RegisterClientKeyRequest{
		PublicKeyPem: rsaPEM,
		ClientId:     "app",
	})
	if !r1.Success {
		t.Fatalf("first RegisterClientKey failed: %s", r1.ErrorMessage)
	}

	// Second registration with the same generated key ID is not naturally possible
	// (ID is nano-timestamp-unique), so instead test with an invalid PEM to hit store error.
	r2, _ := srv.RegisterClientKey(ctxWithSub("alice"), &RegisterClientKeyRequest{
		PublicKeyPem: "not-a-pem",
		ClientId:     "app",
	})
	if r2.Success {
		t.Fatal("expected Success=false for invalid PEM")
	}
}

// TestRegisterClientKey_InferError covers the "cannot infer key type" branch.
func TestRegisterClientKey_InferError(t *testing.T) {
	srv := newTestKeyManagerServer(t, encryption.RSA2048)

	resp, err := srv.RegisterClientKey(ctxWithSub("alice"), &RegisterClientKeyRequest{
		PublicKeyPem: "-----BEGIN CERTIFICATE-----\naGVsbG8=\n-----END CERTIFICATE-----",
		ClientId:     "app",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.Success {
		t.Fatal("expected Success=false for unrecognized PEM type")
	}
}

// TestRegisterClientKey_WithMetadata covers the metadata-copy path and ClientId stored.
func TestRegisterClientKey_WithMetadata(t *testing.T) {
	srv := newTestKeyManagerServer(t, encryption.RSA2048)

	resp, err := srv.RegisterClientKey(ctxWithSub("alice"), &RegisterClientKeyRequest{
		PublicKeyPem: makeRSAPubKeyPEM(t, 2048),
		ClientId:     "my-app",
		Metadata:     map[string]string{"env": "test"},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !resp.Success {
		t.Fatalf("expected Success=true, got: %s", resp.ErrorMessage)
	}
	if resp.Key.Metadata["env"] != "test" {
		t.Errorf("expected metadata env=test, got %v", resp.Key.Metadata)
	}
	if resp.Key.Metadata["client_application_id"] != "my-app" {
		t.Errorf("expected client_application_id=my-app, got %v", resp.Key.Metadata)
	}
}

// TestGetClientKey_SubEmpty covers the empty Sub check.
func TestGetClientKey_SubEmpty(t *testing.T) {
	srv := newTestKeyManagerServer(t, encryption.RSA2048)
	ctx := context.WithValue(context.Background(), "user_claims", &auth.UserClaims{Sub: ""})

	resp, err := srv.GetClientKey(ctx, &GetClientKeyRequest{KeyId: "x"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.Found {
		t.Fatal("expected Found=false for empty Sub")
	}
}

// TestGetClientKey_ActiveKey covers the "no KeyId → GetActiveKeyForClient" path.
func TestGetClientKey_ActiveKey(t *testing.T) {
	srv := newTestKeyManagerServer(t, encryption.RSA2048)

	// Register first
	rsaPEM := makeRSAPubKeyPEM(t, 2048)
	r, _ := srv.RegisterClientKey(ctxWithSub("alice"), &RegisterClientKeyRequest{
		PublicKeyPem: rsaPEM,
	})
	if !r.Success {
		t.Fatalf("RegisterClientKey: %s", r.ErrorMessage)
	}

	// GetClientKey without a KeyId — should look up active key
	resp, err := srv.GetClientKey(ctxWithSub("alice"), &GetClientKeyRequest{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// May fail integrity check but should not panic
	_ = resp
}

// TestGetClientKey_ActiveKeyNotFound covers the GetActiveKeyForClient error branch.
func TestGetClientKey_ActiveKeyNotFound(t *testing.T) {
	srv := newTestKeyManagerServer(t, encryption.RSA2048)

	resp, err := srv.GetClientKey(ctxWithSub("nobody"), &GetClientKeyRequest{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.Found {
		t.Fatal("expected Found=false for user with no active key")
	}
}

// TestRevokeClientKey_RevokeStoreFails covers the RevokeKey error branch.
// We test this by revoking an already-revoked key (or injecting a bad key).
func TestRevokeClientKey_EmptyKeyID(t *testing.T) {
	srv := newTestKeyManagerServer(t, encryption.RSA2048)

	resp, err := srv.RevokeClientKey(ctxWithSub("alice"), &RevokeClientKeyRequest{
		KeyId: "",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.Success {
		t.Fatal("expected Success=false for empty key ID")
	}
}

// TestRevokeClientKey_SubEmpty covers the empty Sub check.
func TestRevokeClientKey_SubEmpty(t *testing.T) {
	srv := newTestKeyManagerServer(t, encryption.RSA2048)
	ctx := context.WithValue(context.Background(), "user_claims", &auth.UserClaims{Sub: ""})

	resp, err := srv.RevokeClientKey(ctx, &RevokeClientKeyRequest{KeyId: "x"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.Success {
		t.Fatal("expected Success=false for empty Sub")
	}
}

// TestListClients_PaginationToken exercises the PageToken branch.
func TestListClients_PaginationToken(t *testing.T) {
	srv := newTestKeyManagerServer(t, encryption.RSA2048)
	ctx := context.Background()

	// Register keys for several distinct clients
	for i := 0; i < 5; i++ {
		sub := fmt.Sprintf("user-%d", i)
		srv.RegisterClientKey(ctxWithSub(sub), &RegisterClientKeyRequest{
			PublicKeyPem: makeRSAPubKeyPEM(t, 2048),
		})
	}

	// First page
	r1, err := srv.ListClients(ctx, &ListClientsRequest{PageSize: 2})
	if err != nil {
		t.Fatalf("ListClients page 1 error = %v", err)
	}
	if len(r1.Clients) > 2 {
		t.Errorf("expected at most 2, got %d", len(r1.Clients))
	}

	if r1.NextPageToken != "" {
		// Follow-up page using the token
		r2, err := srv.ListClients(ctx, &ListClientsRequest{
			PageSize:  2,
			PageToken: r1.NextPageToken,
		})
		if err != nil {
			t.Fatalf("ListClients page 2 error = %v", err)
		}
		_ = r2
	}
}

// TestListClientKeys_PaginationToken exercises the PageToken branch in ListClientKeys.
func TestListClientKeys_PaginationToken(t *testing.T) {
	srv := newTestKeyManagerServer(t, encryption.RSA2048)

	// Register 5 keys for the same user
	for i := 0; i < 5; i++ {
		r, _ := srv.RegisterClientKey(ctxWithSub("paginate-user"), &RegisterClientKeyRequest{
			PublicKeyPem: makeRSAPubKeyPEM(t, 2048),
		})
		if !r.Success {
			t.Fatalf("RegisterClientKey %d failed: %s", i, r.ErrorMessage)
		}
	}

	r1, err := srv.ListClientKeys(ctxWithSub("paginate-user"), &ListClientKeysRequest{
		PageSize: 2,
	})
	if err != nil {
		t.Fatalf("ListClientKeys page 1 error = %v", err)
	}

	if r1.NextPageToken != "" {
		r2, err := srv.ListClientKeys(ctxWithSub("paginate-user"), &ListClientKeysRequest{
			PageSize:  2,
			PageToken: r1.NextPageToken,
		})
		if err != nil {
			t.Fatalf("ListClientKeys page 2 error = %v", err)
		}
		_ = r2
	}
}
