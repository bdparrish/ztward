package key_manager

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"strings"
	"testing"
	"time"

	"github.com/bdparrish/ztward/go/pkg/security/encryption"

	"google.golang.org/protobuf/types/known/timestamppb"
)

func rsaPublicPEM(t *testing.T) string {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate RSA key: %v", err)
	}
	der, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		t.Fatalf("marshal public key: %v", err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
}

func registerClientKey(t *testing.T, store ClientKeyStore, keyID, owner string, expiresAt *timestamppb.Timestamp, pemStr string) {
	t.Helper()
	err := store.RegisterKey(context.Background(), &Key{
		KeyId:        keyID,
		ClientId:     owner,
		PublicKeyPem: pemStr,
		KeyType:      KeyType_KEY_TYPE_RSA_2048,
		Status:       KeyStatus_KEY_STATUS_ACTIVE,
		CreatedAt:    timestamppb.Now(),
		ExpiresAt:    expiresAt,
		Metadata:     map[string]string{},
	})
	if err != nil {
		t.Fatalf("RegisterKey(%s): %v", keyID, err)
	}
}

func TestUsableClientKey(t *testing.T) {
	ctx := context.Background()
	store := NewInMemoryClientKeyStore()
	pemStr := rsaPublicPEM(t)
	registerClientKey(t, store, "active", "alice", timestamppb.New(time.Now().Add(time.Hour)), pemStr)
	registerClientKey(t, store, "no-expiry", "alice", nil, pemStr)
	registerClientKey(t, store, "revoked", "alice", nil, pemStr)
	registerClientKey(t, store, "expired", "alice", timestamppb.New(time.Now().Add(-time.Minute)), pemStr)
	if err := store.RevokeKey(ctx, "revoked", "compromised"); err != nil {
		t.Fatalf("RevokeKey: %v", err)
	}

	tests := []struct {
		name, keyID, subject, wantErr string
	}{
		{"active key owned by subject", "active", "alice", ""},
		{"key without expiry", "no-expiry", "alice", ""},
		{"unknown key", "missing", "alice", "not found"},
		{"revoked key", "revoked", "alice", "not active"},
		{"expired key", "expired", "alice", "expired"},
		{"key owned by another subject", "active", "mallory", "does not belong"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key, err := usableClientKey(ctx, store, tt.keyID, tt.subject)
			if tt.wantErr == "" {
				if err != nil || key == nil {
					t.Fatalf("usableClientKey() = %v, %v; want key", key, err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("usableClientKey() error = %v, want containing %q", err, tt.wantErr)
			}
		})
	}
}

func TestRewrapClientDEK_RejectsRevokedClientKey(t *testing.T) {
	ctx := context.Background()
	srv := newTestKeyManagerServer(t, encryption.RSA2048)
	registerClientKey(t, srv.clientKeyStore, "alice-key", "alice", nil, rsaPublicPEM(t))
	if err := srv.clientKeyStore.RevokeKey(ctx, "alice-key", "compromised"); err != nil {
		t.Fatalf("RevokeKey: %v", err)
	}

	_, err := srv.RewrapClientDEK(ctx, &RewrapClientDEKRequest{
		Subject:          "alice",
		ClientKeyId:      "alice-key",
		ClientWrappedDek: make([]byte, 256),
		ServiceKeyId:     "service-key",
	})
	if err == nil || !strings.Contains(err.Error(), "not active") {
		t.Fatalf("RewrapClientDEK() error = %v, want rejection of revoked key", err)
	}
}

// UnwrapDEK re-encrypts the DEK to the client key, so a revoked (possibly
// compromised) key must never receive it.
func TestUnwrapDEK_RejectsRevokedClientKey(t *testing.T) {
	ctx := context.Background()
	srv := newTestKeyManagerServer(t, encryption.RSA2048)

	created, err := srv.CreateKey(ctx, &CreateKeyRequest{
		Name:         "service-key-revocation-test",
		KeyType:      KeyType_KEY_TYPE_RSA_2048,
		ProviderType: KeyProviderType_KEY_PROVIDER_TYPE_SOFTWARE,
	})
	if err != nil {
		t.Fatalf("CreateKey: %v", err)
	}
	provider, err := srv.providerFactory.GetProvider(KeyProviderType_KEY_PROVIDER_TYPE_SOFTWARE)
	if err != nil {
		t.Fatalf("GetProvider: %v", err)
	}
	encryptedDEK, err := provider.Encrypt(ctx, created.Key.KeyId, []byte("test-dek-32-bytes-padding-xyz123"))
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	registerClientKey(t, srv.clientKeyStore, "alice-key", "alice", nil, rsaPublicPEM(t))

	unwrap := func() *UnwrapDEKResponse {
		resp, err := srv.dekService.UnwrapDEK(ctx, &UnwrapDEKRequest{
			Subject:      "alice",
			Resource:     "resource1",
			KeyId:        created.Key.KeyId,
			ClientKeyId:  "alice-key",
			EncryptedDek: encryptedDEK,
		})
		if err != nil {
			t.Fatalf("UnwrapDEK: %v", err)
		}
		return resp
	}

	if resp := unwrap(); !resp.AccessGranted {
		t.Fatalf("control: active key should be granted, got %q", resp.AccessReason)
	}

	if err := srv.clientKeyStore.RevokeKey(ctx, "alice-key", "compromised"); err != nil {
		t.Fatalf("RevokeKey: %v", err)
	}
	if resp := unwrap(); resp.AccessGranted || !strings.Contains(resp.AccessReason, "not active") {
		t.Fatalf("revoked key: granted=%v reason=%q, want denial", resp.AccessGranted, resp.AccessReason)
	}
}
