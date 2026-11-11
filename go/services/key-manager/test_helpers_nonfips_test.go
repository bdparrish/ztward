//go:build !fips

package key_manager

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"testing"

	"github.com/bdparrish/ztward/go/pkg/auth"
)

// newFIPSSmartCardProvider creates a mock SmartCardKeyProvider with FIPS enabled and initialized
func newFIPSSmartCardProvider(t *testing.T) *SmartCardKeyProvider {
	t.Helper()
	provider := NewSmartCardKeyProvider("mock", map[string]string{"pin": "1234"})
	err := provider.Configure(map[string]string{"fips_enabled": "true", "pin": "1234"})
	if err != nil {
		t.Fatalf("Configure FIPS: %v", err)
	}
	if !provider.IsAvailable() {
		t.Fatal("SmartCard provider should be available after Configure")
	}
	return provider
}

// newInitializedSmartCardProvider creates a mock SmartCardKeyProvider that is initialized
func newInitializedSmartCardProvider(t *testing.T) *SmartCardKeyProvider {
	t.Helper()
	return NewSmartCardKeyProvider("mock", map[string]string{"pin": "1234"})
}

type failingProviderFactory struct{}

func (f *failingProviderFactory) CreateProvider(providerType KeyProviderType, config map[string]string) (KeyProviderInterface, error) {
	return nil, fmt.Errorf("no provider available")
}

func (f *failingProviderFactory) GetProvider(providerType KeyProviderType) (KeyProviderInterface, error) {
	return nil, fmt.Errorf("no provider available for %v", providerType)
}

func (f *failingProviderFactory) GetAvailableProviders() []KeyProviderType {
	return nil
}

func makeRSAPubKeyPEM(t *testing.T, bits int) string {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		t.Fatalf("GenerateKey(%d): %v", bits, err)
	}
	der, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		t.Fatalf("MarshalPKIXPublicKey: %v", err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
}

func makeECCPubKeyPEM(t *testing.T, curve elliptic.Curve) string {
	t.Helper()
	priv, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey ECC: %v", err)
	}
	der, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		t.Fatalf("MarshalPKIXPublicKey: %v", err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
}

func ctxWithSub(sub string) context.Context {
	return context.WithValue(context.Background(), "user_claims", &auth.UserClaims{Sub: sub})
}
