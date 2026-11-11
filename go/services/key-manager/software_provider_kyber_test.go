//go:build !fips

package key_manager

import (
	"context"
	"crypto/rand"
	"testing"

	"github.com/cloudflare/circl/kem/kyber/kyber1024"
	"github.com/cloudflare/circl/kem/kyber/kyber512"
	"github.com/cloudflare/circl/kem/kyber/kyber768"
)

// TestDecryptWithKyber_UnknownPrivateKeyType covers the default (false) branch.
func TestDecryptWithKyber_UnknownPrivateKeyType(t *testing.T) {
	provider := NewSoftwareKeyProvider(nil)
	type notAKyberKey struct{}
	plaintext, handled, err := provider.decryptWithKyber(&notAKyberKey{}, []byte("data"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if handled {
		t.Fatal("expected handled=false for unknown private key type")
	}
	if plaintext != nil {
		t.Fatal("expected nil plaintext for unhandled type")
	}
}

// TestEncryptWithKyber_UnknownPublicKeyType covers the default (false) branch.
func TestEncryptWithKyber_UnknownPublicKeyType(t *testing.T) {
	provider := NewSoftwareKeyProvider(nil)
	type notAKyberKey struct{}
	ct, handled, err := provider.encryptWithKyber(&notAKyberKey{}, []byte("data"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if handled {
		t.Fatal("expected handled=false for unknown public key type")
	}
	if ct != nil {
		t.Fatal("expected nil ciphertext for unhandled type")
	}
}

// TestGenerateKyberKeyPair_Default exercises the default error branch.
func TestGenerateKyberKeyPair_Default(t *testing.T) {
	provider := NewSoftwareKeyProvider(nil)
	_, _, err := provider.generateKyberKeyPair(KeyType_KEY_TYPE_UNSPECIFIED)
	if err == nil {
		t.Fatal("expected error for unsupported Kyber key type")
	}
}

// TestGenerateKyberKeyPair_All verifies all three Kyber variants generate without error.
func TestGenerateKyberKeyPair_All(t *testing.T) {
	provider := NewSoftwareKeyProvider(nil)
	for _, kt := range []KeyType{
		KeyType_KEY_TYPE_KYBER_512,
		KeyType_KEY_TYPE_KYBER_768,
		KeyType_KEY_TYPE_KYBER_1024,
	} {
		pub, priv, err := provider.generateKyberKeyPair(kt)
		if err != nil {
			t.Fatalf("generateKyberKeyPair(%v) error = %v", kt, err)
		}
		if pub == nil || priv == nil {
			t.Fatalf("generateKyberKeyPair(%v) returned nil key(s)", kt)
		}
	}
}

// TestDecryptWithKyber512_ShortCiphertext covers the too-short ciphertext branch.
func TestDecryptWithKyber512_ShortCiphertext(t *testing.T) {
	provider := NewSoftwareKeyProvider(nil)
	_, priv, _ := kyber512.GenerateKeyPair(rand.Reader)
	_, err := provider.decryptWithKyber512(priv, []byte("too-short"))
	if err == nil {
		t.Fatal("expected error for too-short ciphertext")
	}
}

// TestDecryptWithKyber768_ShortCiphertext covers the too-short ciphertext branch.
func TestDecryptWithKyber768_ShortCiphertext(t *testing.T) {
	provider := NewSoftwareKeyProvider(nil)
	_, priv, _ := kyber768.GenerateKeyPair(rand.Reader)
	_, err := provider.decryptWithKyber768(priv, []byte("too-short"))
	if err == nil {
		t.Fatal("expected error for too-short ciphertext")
	}
}

// TestDecryptWithKyber1024_ShortCiphertext covers the too-short ciphertext branch.
func TestDecryptWithKyber1024_ShortCiphertext(t *testing.T) {
	provider := NewSoftwareKeyProvider(nil)
	_, priv, _ := kyber1024.GenerateKeyPair(rand.Reader)
	_, err := provider.decryptWithKyber1024(priv, []byte("too-short"))
	if err == nil {
		t.Fatal("expected error for too-short ciphertext")
	}
}

func TestKyber512EncryptDecryptRoundtrip(t *testing.T) {
	ctx := context.Background()
	keyStore := NewInMemoryKeyStore()
	provider := NewSoftwareKeyProvider(nil)
	provider.SetKeyStore(keyStore)

	kp, err := provider.GenerateKeyPair(ctx, KeyType_KEY_TYPE_KYBER_512, "ky512-test", nil)
	if err != nil {
		t.Fatalf("GenerateKeyPair KYBER_512 error = %v", err)
	}
	// Store so Decrypt can find the key pair
	if err := keyStore.StoreKeyPair(ctx, kp); err != nil {
		t.Fatalf("StoreKeyPair: %v", err)
	}

	plaintext := []byte("hello kyber-512")
	ct, err := provider.Encrypt(ctx, kp.KeyID, plaintext)
	if err != nil {
		t.Fatalf("Encrypt KYBER_512 error = %v", err)
	}

	pt, err := provider.Decrypt(ctx, kp.KeyID, ct)
	if err != nil {
		t.Fatalf("Decrypt KYBER_512 error = %v", err)
	}
	if string(pt) != string(plaintext) {
		t.Fatalf("round-trip mismatch: got %q want %q", pt, plaintext)
	}
}

func TestKyber768EncryptDecryptRoundtrip(t *testing.T) {
	ctx := context.Background()
	keyStore := NewInMemoryKeyStore()
	provider := NewSoftwareKeyProvider(nil)
	provider.SetKeyStore(keyStore)

	kp, err := provider.GenerateKeyPair(ctx, KeyType_KEY_TYPE_KYBER_768, "ky768-test", nil)
	if err != nil {
		t.Fatalf("GenerateKeyPair KYBER_768 error = %v", err)
	}
	if err := keyStore.StoreKeyPair(ctx, kp); err != nil {
		t.Fatalf("StoreKeyPair: %v", err)
	}

	plaintext := []byte("hello kyber-768")
	ct, err := provider.Encrypt(ctx, kp.KeyID, plaintext)
	if err != nil {
		t.Fatalf("Encrypt KYBER_768 error = %v", err)
	}

	pt, err := provider.Decrypt(ctx, kp.KeyID, ct)
	if err != nil {
		t.Fatalf("Decrypt KYBER_768 error = %v", err)
	}
	if string(pt) != string(plaintext) {
		t.Fatalf("round-trip mismatch: got %q want %q", pt, plaintext)
	}
}

func TestKyber1024EncryptDecryptRoundtrip(t *testing.T) {
	ctx := context.Background()
	keyStore := NewInMemoryKeyStore()
	provider := NewSoftwareKeyProvider(nil)
	provider.SetKeyStore(keyStore)

	kp, err := provider.GenerateKeyPair(ctx, KeyType_KEY_TYPE_KYBER_1024, "ky1024-test", nil)
	if err != nil {
		t.Fatalf("GenerateKeyPair KYBER_1024 error = %v", err)
	}
	if err := keyStore.StoreKeyPair(ctx, kp); err != nil {
		t.Fatalf("StoreKeyPair: %v", err)
	}

	plaintext := []byte("hello kyber-1024")
	ct, err := provider.Encrypt(ctx, kp.KeyID, plaintext)
	if err != nil {
		t.Fatalf("Encrypt KYBER_1024 error = %v", err)
	}

	pt, err := provider.Decrypt(ctx, kp.KeyID, ct)
	if err != nil {
		t.Fatalf("Decrypt KYBER_1024 error = %v", err)
	}
	if string(pt) != string(plaintext) {
		t.Fatalf("round-trip mismatch: got %q want %q", pt, plaintext)
	}
}
