package key_manager

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"testing"
)

func TestSoftwareKeyProvider_PublicKeyToPEM_ECCP384(t *testing.T) {
	provider := NewSoftwareKeyProvider(nil)
	key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey P384: %v", err)
	}

	pemStr, err := provider.publicKeyToPEM(&key.PublicKey)
	if err != nil {
		t.Fatalf("publicKeyToPEM P384 error = %v", err)
	}
	if pemStr == "" {
		t.Error("expected non-empty PEM string for P384")
	}
}

func TestSoftwareKeyProvider_PublicKeyToPEM_ECCP521(t *testing.T) {
	provider := NewSoftwareKeyProvider(nil)
	key, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey P521: %v", err)
	}

	pemStr, err := provider.publicKeyToPEM(&key.PublicKey)
	if err != nil {
		t.Fatalf("publicKeyToPEM P521 error = %v", err)
	}
	if pemStr == "" {
		t.Error("expected non-empty PEM string for P521")
	}
}
