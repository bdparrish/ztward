//go:build !fips

package key_manager

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"strings"
	"testing"
)

func TestCoverageGaps2_InferKeyTypeFromPEM_Ed25519(t *testing.T) {
	edPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate Ed25519: %v", err)
	}
	derBytes, err := x509.MarshalPKIXPublicKey(edPub)
	if err != nil {
		t.Fatalf("marshal Ed25519: %v", err)
	}
	pemStr := string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: derBytes}))

	_, err = inferKeyTypeFromPEM(pemStr)
	if err == nil {
		t.Fatal("expected error for Ed25519 in inferKeyTypeFromPEM")
	}
	if !strings.Contains(err.Error(), "unsupported key type") {
		t.Errorf("expected 'unsupported key type' error, got: %v", err)
	}
}

func TestCoverageGaps2_InferKeyTypeFromPEM_RSA1024(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatalf("generate RSA-1024: %v", err)
	}
	derBytes, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		t.Fatalf("marshal RSA-1024: %v", err)
	}
	pemStr := string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: derBytes}))

	_, err = inferKeyTypeFromPEM(pemStr)
	if err == nil {
		t.Fatal("expected error for RSA-1024 in inferKeyTypeFromPEM")
	}
	if !strings.Contains(err.Error(), "unsupported RSA key size") {
		t.Errorf("expected 'unsupported RSA key size' error, got: %v", err)
	}
}

func TestCoverageGaps2_InferKeyTypeFromPEM_ECCP224(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P224(), rand.Reader)
	if err != nil {
		t.Fatalf("generate P-224: %v", err)
	}
	derBytes, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		t.Fatalf("marshal P-224: %v", err)
	}
	pemStr := string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: derBytes}))

	_, err = inferKeyTypeFromPEM(pemStr)
	if err == nil {
		t.Fatal("expected error for P-224 in inferKeyTypeFromPEM")
	}
	if !strings.Contains(err.Error(), "unsupported ECC curve") {
		t.Errorf("expected 'unsupported ECC curve' error, got: %v", err)
	}
}

func TestCoverageGaps2_InferKeyTypeFromPEM_BadDER(t *testing.T) {
	pemStr := string(pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: []byte("garbage-not-valid-asn1"),
	}))
	_, err := inferKeyTypeFromPEM(pemStr)
	if err == nil {
		t.Fatal("expected error for bad DER in inferKeyTypeFromPEM")
	}
	if !strings.Contains(err.Error(), "failed to parse public key") {
		t.Errorf("expected 'failed to parse public key' error, got: %v", err)
	}
}

// TestInferKeyTypeFromPEM_UnsupportedKeyType covers the default "unsupported key type" branch
// by constructing a fake DER payload that parses but isn't RSA/ECC.
// We can't easily inject a custom key type, so we verify the existing branches are reachable
// by testing a bad parse scenario (already tested) and a direct unsupported key type error.
func TestInferKeyTypeFromPEM_ParseError(t *testing.T) {
	// Valid PEM block header but garbage DER bytes
	badDER := []byte("garbage bytes that are not valid DER")
	pemStr := string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: badDER}))

	_, err := inferKeyTypeFromPEM(pemStr)
	if err == nil {
		t.Fatal("expected error for invalid DER content")
	}
}
