//go:build !fips

package key_manager

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"strings"
	"testing"

	"github.com/cloudflare/circl/kem/kyber/kyber1024"
	"github.com/cloudflare/circl/kem/kyber/kyber512"
	"github.com/cloudflare/circl/kem/kyber/kyber768"
)

func TestSoftwareKeyProvider_KyberEncryptDecrypt(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name               string
		keyType            KeyType
		ciphertextSizeHint int
	}{
		{name: "Kyber512", keyType: KeyType_KEY_TYPE_KYBER_512, ciphertextSizeHint: kyber512.Scheme().CiphertextSize()},
		{name: "Kyber768", keyType: KeyType_KEY_TYPE_KYBER_768, ciphertextSizeHint: kyber768.Scheme().CiphertextSize()},
		{name: "Kyber1024", keyType: KeyType_KEY_TYPE_KYBER_1024, ciphertextSizeHint: kyber1024.Scheme().CiphertextSize()},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			ctx := context.Background()
			keyStore := NewInMemoryKeyStore()
			provider := NewSoftwareKeyProvider(nil)
			provider.SetKeyStore(keyStore)

			keyID := "test-" + tt.name
			keyPair, err := provider.GenerateKeyPair(ctx, tt.keyType, keyID, nil)
			if err != nil {
				t.Fatalf("GenerateKeyPair() error = %v", err)
			}
			if err := keyStore.StoreKeyPair(ctx, keyPair); err != nil {
				t.Fatalf("StoreKeyPair() error = %v", err)
			}

			plaintext := []byte("this-is-a-test-dek")

			ciphertext, err := provider.Encrypt(ctx, keyID, plaintext)
			if err != nil {
				t.Fatalf("Encrypt() error = %v", err)
			}

			if len(ciphertext) <= tt.ciphertextSizeHint {
				t.Fatalf("Encrypt() ciphertext too short: got %d, want > %d", len(ciphertext), tt.ciphertextSizeHint)
			}

			decrypted, err := provider.Decrypt(ctx, keyID, ciphertext)
			if err != nil {
				t.Fatalf("Decrypt() error = %v", err)
			}

			if !bytes.Equal(decrypted, plaintext) {
				t.Fatalf("Decrypt() mismatch: got %x, want %x", decrypted, plaintext)
			}
		})
	}
}

func TestSoftwareProvider_PublicKeyToPEM_Ed25519(t *testing.T) {
	provider := &SoftwareKeyProvider{}
	_, edPub, _ := ed25519.GenerateKey(rand.Reader)
	_, err := provider.publicKeyToPEM(edPub)
	if err == nil {
		t.Fatal("expected error for ed25519 key type")
	}
	if !strings.Contains(err.Error(), "unsupported public key type") {
		t.Errorf("expected unsupported key type error, got: %v", err)
	}
}

func TestSoftwareProvider_Decrypt_KeyNotFound(t *testing.T) {
	provider := &SoftwareKeyProvider{
		keyStore: NewInMemoryKeyStore(),
	}
	_, err := provider.Decrypt(context.Background(), "nonexistent-key", []byte("data"))
	if err == nil {
		t.Fatal("expected error for nonexistent key")
	}
}

func TestSoftwareProvider_Encrypt_KeyNotFound(t *testing.T) {
	provider := &SoftwareKeyProvider{
		keyStore: NewInMemoryKeyStore(),
	}
	_, err := provider.Encrypt(context.Background(), "nonexistent-key", []byte("data"))
	if err == nil {
		t.Fatal("expected error for nonexistent key")
	}
}

func TestSoftwareProvider_RotateKey_UnsupportedType(t *testing.T) {
	store := NewInMemoryKeyStore()
	ctx := context.Background()

	// Seed a key with unspecified type
	kp := &KeyPair{
		KeyID:   "unspecified-key",
		KeyType: KeyType_KEY_TYPE_UNSPECIFIED,
	}
	_ = store.StoreKeyPair(ctx, kp)

	provider := &SoftwareKeyProvider{keyStore: store}
	_, err := provider.RotateKey(ctx, "unspecified-key")
	if err == nil {
		t.Fatal("expected error rotating unsupported key type")
	}
}

func TestSoftwareProvider_RotateKey_KeyNotFound(t *testing.T) {
	provider := &SoftwareKeyProvider{
		keyStore: NewInMemoryKeyStore(),
	}
	_, err := provider.RotateKey(context.Background(), "missing-key")
	if err == nil {
		t.Fatal("expected error for nonexistent key in RotateKey")
	}
}
