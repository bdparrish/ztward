//go:build !fips

package key_manager

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"strings"
	"testing"

	"github.com/cloudflare/circl/kem/kyber/kyber1024"
	"github.com/cloudflare/circl/kem/kyber/kyber512"
	"github.com/cloudflare/circl/kem/kyber/kyber768"
)

func TestConvertPrivateKeyToPEM_ECCWrongType(t *testing.T) {
	// Pass an RSA key but claim it's ECC type
	rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	_, err := ConvertPrivateKeyToPEM(rsaKey, KeyType_KEY_TYPE_ECC_P256)
	if err == nil {
		t.Fatal("expected error for RSA key with ECC type")
	}
	if !strings.Contains(err.Error(), "expected *ecdsa.PrivateKey") {
		t.Errorf("expected type mismatch error, got: %v", err)
	}
}

func TestConvertPrivateKeyToPEM_KyberNonKyberKey(t *testing.T) {
	rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	_, err := ConvertPrivateKeyToPEM(rsaKey, KeyType_KEY_TYPE_KYBER_512)
	if err == nil {
		t.Fatal("expected error for RSA key with Kyber type")
	}
}

// TestConvertPrivateKeyToPEM_CompletelyUnsupportedKeyType covers the final unsupported branch.
func TestConvertPrivateKeyToPEM_CompletelyUnsupportedKeyType(t *testing.T) {
	type weirdKey struct{}
	_, err := ConvertPrivateKeyToPEM(&weirdKey{}, KeyType_KEY_TYPE_UNSPECIFIED)
	if err == nil {
		t.Fatal("expected error for unsupported key type in ConvertPrivateKeyToPEM")
	}
}

// TestConvertPrivateKeyToPEM_KyberDisabledPath covers the Kyber "disabled" fallback.
// Passing a non-Kyber concrete type to ConvertPrivateKeyToPEM with a Kyber key type causes
// convertKyberPrivateKeyToPEM to return handled=false, hitting the "disabled" branch.
func TestConvertPrivateKeyToPEM_KyberDisabledPath(t *testing.T) {
	type fakeKyberKey struct{}
	_, err := ConvertPrivateKeyToPEM(&fakeKyberKey{}, KeyType_KEY_TYPE_KYBER_512)
	if err == nil {
		t.Fatal("expected error for fake Kyber key type in ConvertPrivateKeyToPEM")
	}
}

// TestDeserializePrivateKey_RSAParseError covers the RSA "parse fails" branch.
func TestDeserializePrivateKey_RSAParseError(t *testing.T) {
	_, err := deserializePrivateKey([]byte("garbage-not-a-key"), KeyType_KEY_TYPE_RSA_2048)
	if err == nil {
		t.Fatal("expected error for invalid RSA private key bytes")
	}
}

// TestDeserializePrivateKey_ECCParseError covers the ECC "parse fails" branch.
func TestDeserializePrivateKey_ECCParseError(t *testing.T) {
	_, err := deserializePrivateKey([]byte("garbage-not-a-key"), KeyType_KEY_TYPE_ECC_P256)
	if err == nil {
		t.Fatal("expected error for invalid ECC private key bytes")
	}
}

// TestDeserializePrivateKey_RSAWrongKeyType covers the case where PKCS8 parses
// but the resulting key is not RSA (contains an ECC key instead).
func TestDeserializePrivateKey_RSAWrongKeyType(t *testing.T) {
	ecKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	der, err := x509.MarshalPKCS8PrivateKey(ecKey)
	if err != nil {
		t.Fatalf("MarshalPKCS8PrivateKey: %v", err)
	}

	_, err = deserializePrivateKey(der, KeyType_KEY_TYPE_RSA_2048)
	if err == nil {
		t.Fatal("expected error when ECC bytes are parsed as RSA key type")
	}
}

// TestDeserializePrivateKey_ECCWrongKeyType covers the case where PKCS8 parses
// but the resulting key is not ECC (contains an RSA key instead).
func TestDeserializePrivateKey_ECCWrongKeyType(t *testing.T) {
	rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	der, err := x509.MarshalPKCS8PrivateKey(rsaKey)
	if err != nil {
		t.Fatalf("MarshalPKCS8PrivateKey: %v", err)
	}

	_, err = deserializePrivateKey(der, KeyType_KEY_TYPE_ECC_P256)
	if err == nil {
		t.Fatal("expected error when RSA bytes are parsed as ECC key type")
	}
}

func TestEncryptPrivateKeyPEM_RoundTripLong(t *testing.T) {
	adminKey := make([]byte, 32)
	_, _ = rand.Read(adminKey)
	ke, err := NewKeyEncryption(adminKey)
	if err != nil {
		t.Fatalf("NewKeyEncryption: %v", err)
	}

	// Use a longer PEM to exercise all code paths
	pemData := string(pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: make([]byte, 256),
	}))

	enc, err := ke.EncryptPrivateKeyPEM(pemData)
	if err != nil {
		t.Fatalf("EncryptPrivateKeyPEM error = %v", err)
	}

	dec, err := ke.DecryptPrivateKeyPEM(enc)
	if err != nil {
		t.Fatalf("DecryptPrivateKeyPEM error = %v", err)
	}
	if dec != pemData {
		t.Fatal("round-trip PEM mismatch")
	}
}

// TestDeserializePrivateKey_KyberDisabledBranch exercises the isKyberKeyType branch.
// In the !fips build, serializeKyberPrivateKey returns (nil, false, nil) for an
// unknown concrete type, so serializePrivateKey falls through to the
// "kyber key serialization is disabled" error — not triggered in !fips for real Kyber keys.
// We trigger it by passing a struct that satisfies none of the Kyber type-switch cases.
func TestSerializePrivateKey_KyberUnknownType(t *testing.T) {
	adminKey := make([]byte, 32)
	_, _ = rand.Read(adminKey)
	ke, _ := NewKeyEncryption(adminKey)

	type fakeKyberKey struct{}

	// Kyber type but unsupported concrete value — handled=false means we fall to disabled error
	_, err := ke.EncryptPrivateKey(&fakeKyberKey{}, KeyType_KEY_TYPE_KYBER_512)
	if err == nil {
		t.Fatal("expected error for unsupported Kyber concrete type")
	}
}

// TestDeserializePrivateKey_KyberPath exercises the Kyber deserialize path via Encrypt+Decrypt.
func TestKeyEncryption_Kyber512RoundTrip(t *testing.T) {
	pub512, priv512, err := kyber512.GenerateKeyPair(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKeyPair kyber512: %v", err)
	}
	_ = pub512

	adminKey := make([]byte, 32)
	_, _ = rand.Read(adminKey)
	ke, _ := NewKeyEncryption(adminKey)

	enc, err := ke.EncryptPrivateKey(priv512, KeyType_KEY_TYPE_KYBER_512)
	if err != nil {
		t.Fatalf("EncryptPrivateKey Kyber512 error = %v", err)
	}

	dec, err := ke.DecryptPrivateKey(enc, KeyType_KEY_TYPE_KYBER_512)
	if err != nil {
		t.Fatalf("DecryptPrivateKey Kyber512 error = %v", err)
	}
	if _, ok := dec.(*kyber512.PrivateKey); !ok {
		t.Fatalf("expected *kyber512.PrivateKey, got %T", dec)
	}
}

func TestKeyEncryption_Kyber768RoundTrip(t *testing.T) {
	_, priv768, err := kyber768.GenerateKeyPair(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKeyPair kyber768: %v", err)
	}

	adminKey := make([]byte, 32)
	_, _ = rand.Read(adminKey)
	ke, _ := NewKeyEncryption(adminKey)

	enc, err := ke.EncryptPrivateKey(priv768, KeyType_KEY_TYPE_KYBER_768)
	if err != nil {
		t.Fatalf("EncryptPrivateKey Kyber768 error = %v", err)
	}

	dec, err := ke.DecryptPrivateKey(enc, KeyType_KEY_TYPE_KYBER_768)
	if err != nil {
		t.Fatalf("DecryptPrivateKey Kyber768 error = %v", err)
	}
	if _, ok := dec.(*kyber768.PrivateKey); !ok {
		t.Fatalf("expected *kyber768.PrivateKey, got %T", dec)
	}
}

func TestKeyEncryption_Kyber1024RoundTrip(t *testing.T) {
	_, priv1024, err := kyber1024.GenerateKeyPair(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKeyPair kyber1024: %v", err)
	}

	adminKey := make([]byte, 32)
	_, _ = rand.Read(adminKey)
	ke, _ := NewKeyEncryption(adminKey)

	enc, err := ke.EncryptPrivateKey(priv1024, KeyType_KEY_TYPE_KYBER_1024)
	if err != nil {
		t.Fatalf("EncryptPrivateKey Kyber1024 error = %v", err)
	}

	dec, err := ke.DecryptPrivateKey(enc, KeyType_KEY_TYPE_KYBER_1024)
	if err != nil {
		t.Fatalf("DecryptPrivateKey Kyber1024 error = %v", err)
	}
	if _, ok := dec.(*kyber1024.PrivateKey); !ok {
		t.Fatalf("expected *kyber1024.PrivateKey, got %T", dec)
	}
}
