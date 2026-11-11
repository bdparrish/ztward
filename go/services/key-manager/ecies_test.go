package key_manager

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"testing"
)

func TestECCECIESRoundTrip(t *testing.T) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	plaintext := []byte("secret data for ecc")
	ciphertext, err := encryptDEKWithECCPublicKey(&privateKey.PublicKey, plaintext)
	if err != nil {
		t.Fatalf("encryptDEKWithECCPublicKey failed: %v", err)
	}

	decrypted, err := decryptDEKWithECCPrivateKey(privateKey, ciphertext)
	if err != nil {
		t.Fatalf("decryptDEKWithECCPrivateKey failed: %v", err)
	}

	if string(decrypted) != string(plaintext) {
		t.Fatalf("decrypted plaintext mismatch: got %s want %s", decrypted, plaintext)
	}
}

func TestECCECIESTamper(t *testing.T) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	ciphertext, err := encryptDEKWithECCPublicKey(&privateKey.PublicKey, []byte("data"))
	if err != nil {
		t.Fatalf("encrypt failed: %v", err)
	}

	// Tamper with ciphertext payload
	corrupted := make([]byte, len(ciphertext))
	copy(corrupted, ciphertext)
	corrupted[len(corrupted)-1] ^= 0xFF

	if _, err := decryptDEKWithECCPrivateKey(privateKey, corrupted); err == nil {
		t.Fatalf("expected error when decrypting tampered payload")
	}
}

func TestEncryptDEKWithECCPublicKey_NilKey(t *testing.T) {
	_, err := encryptDEKWithECCPublicKey(nil, []byte("data"))
	if err == nil {
		t.Fatal("expected error for nil public key")
	}
}

func TestEncryptDEKWithECCPublicKey_NilCurve(t *testing.T) {
	_, err := encryptDEKWithECCPublicKey(&ecdsa.PublicKey{Curve: nil}, []byte("data"))
	if err == nil {
		t.Fatal("expected error for nil curve")
	}
}

func TestDecryptDEKWithECCPrivateKey_NilKey(t *testing.T) {
	_, err := decryptDEKWithECCPrivateKey(nil, []byte("data"))
	if err == nil {
		t.Fatal("expected error for nil private key")
	}
}

func TestDecryptDEKWithECCPrivateKey_ShortCiphertext(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	// coordSize = 32, headerSize = 64 -- provide fewer bytes than headerSize
	_, err := decryptDEKWithECCPrivateKey(key, []byte("short"))
	if err == nil {
		t.Fatal("expected error for ciphertext shorter than header")
	}
}

func TestDecryptDEKWithECCPrivateKey_PointNotOnCurve(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	// coordSize for P256 = 32 bytes, header = 64 bytes
	// Build a payload where the ephemeral x,y are all zeros (not on curve)
	coordSize := 32
	badPayload := make([]byte, coordSize*2+16+1) // headerSize + nonceSize + 1 byte of payload
	_, err := decryptDEKWithECCPrivateKey(key, badPayload)
	if err == nil {
		t.Fatal("expected error for ephemeral key not on curve")
	}
}

func TestDecryptDEKWithECCPrivateKey_ShortPayloadAfterHeader(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	// coordSize for P384 = 48 bytes, so headerSize = 96
	// Provide exactly 96 bytes (header only, no nonce/ciphertext)
	// This is > headerSize but GCM nonce check will fail if point is valid-looking
	// Use the right length but all zeros - point won't be on curve
	coordSize := 48
	payload := make([]byte, coordSize*2+1) // just 1 extra byte (> headerSize but < headerSize + nonceSize)
	_, err := decryptDEKWithECCPrivateKey(key, payload)
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestECIESRoundTrip_P384(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey P384: %v", err)
	}
	plaintext := []byte("p384 ecies roundtrip")
	ct, err := encryptDEKWithECCPublicKey(&key.PublicKey, plaintext)
	if err != nil {
		t.Fatalf("encryptDEKWithECCPublicKey P384 failed: %v", err)
	}
	got, err := decryptDEKWithECCPrivateKey(key, ct)
	if err != nil {
		t.Fatalf("decryptDEKWithECCPrivateKey P384 failed: %v", err)
	}
	if string(got) != string(plaintext) {
		t.Fatalf("P384 roundtrip mismatch: got %q want %q", got, plaintext)
	}
}

func TestECIESRoundTrip_P521(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey P521: %v", err)
	}
	plaintext := []byte("p521 ecies roundtrip")
	ct, err := encryptDEKWithECCPublicKey(&key.PublicKey, plaintext)
	if err != nil {
		t.Fatalf("encryptDEKWithECCPublicKey P521 failed: %v", err)
	}
	got, err := decryptDEKWithECCPrivateKey(key, ct)
	if err != nil {
		t.Fatalf("decryptDEKWithECCPrivateKey P521 failed: %v", err)
	}
	if string(got) != string(plaintext) {
		t.Fatalf("P521 roundtrip mismatch: got %q want %q", got, plaintext)
	}
}
