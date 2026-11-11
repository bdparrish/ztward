//go:build !fips

package key_manager

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"testing"
)

// TestEncryptDEKWithECCPublicKey_P256RoundTrip covers a full P-256 encrypt/decrypt
// to ensure all internal paths (sharedX, hkdf.Key, GCM, output construction) run.
func TestEncryptDEKWithECCPublicKey_P256RoundTrip(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	plaintext := []byte("ecies roundtrip p256")

	ct, err := encryptDEKWithECCPublicKey(&key.PublicKey, plaintext)
	if err != nil {
		t.Fatalf("encryptDEKWithECCPublicKey error = %v", err)
	}

	pt, err := decryptDEKWithECCPrivateKey(key, ct)
	if err != nil {
		t.Fatalf("decryptDEKWithECCPrivateKey error = %v", err)
	}
	if string(pt) != string(plaintext) {
		t.Fatalf("mismatch: got %q want %q", pt, plaintext)
	}
}
