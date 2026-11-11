package key_manager

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"testing"
)

func TestSerializePrivateKey_RSAKeyWrongType(t *testing.T) {
	adminKey := make([]byte, 32)
	_, _ = rand.Read(adminKey)
	ke, _ := NewKeyEncryption(adminKey)

	// Pass an ECC key but claim RSA type — serializePrivateKey should fail
	eccKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	_, err := ke.EncryptPrivateKey(eccKey, KeyType_KEY_TYPE_RSA_2048)
	if err == nil {
		t.Fatal("EncryptPrivateKey should fail when passing ECC key as RSA type")
	}
}

func TestSerializePrivateKey_ECCKeyWrongType(t *testing.T) {
	adminKey := make([]byte, 32)
	_, _ = rand.Read(adminKey)
	ke, _ := NewKeyEncryption(adminKey)

	// Pass an RSA key but claim ECC type — serializePrivateKey should fail
	rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	_, err := ke.EncryptPrivateKey(rsaKey, KeyType_KEY_TYPE_ECC_P256)
	if err == nil {
		t.Fatal("EncryptPrivateKey should fail when passing RSA key as ECC type")
	}
}

func TestEncryptPrivateKeyPEM_Success(t *testing.T) {
	adminKey := make([]byte, 32)
	_, _ = rand.Read(adminKey)
	ke, _ := NewKeyEncryption(adminKey)

	pemData := "-----BEGIN RSA PRIVATE KEY-----\nfakekey\n-----END RSA PRIVATE KEY-----"
	enc, err := ke.EncryptPrivateKeyPEM(pemData)
	if err != nil {
		t.Fatalf("EncryptPrivateKeyPEM error = %v", err)
	}
	if enc == nil || len(enc.EncryptedData) == 0 {
		t.Fatal("expected non-empty encrypted data")
	}

	// Decrypt and verify roundtrip
	decrypted, err := ke.DecryptPrivateKeyPEM(enc)
	if err != nil {
		t.Fatalf("DecryptPrivateKeyPEM error = %v", err)
	}
	if decrypted != pemData {
		t.Errorf("PEM roundtrip mismatch: got %q want %q", decrypted, pemData)
	}
}

func TestDecryptPrivateKeyPEM_UnsupportedAlgo(t *testing.T) {
	adminKey := make([]byte, 32)
	_, _ = rand.Read(adminKey)
	ke, _ := NewKeyEncryption(adminKey)

	enc := &EncryptedKeyData{
		Algorithm:     "NOT-SUPPORTED",
		EncryptedData: []byte("data"),
		Nonce:         []byte("nonce"),
	}
	_, err := ke.DecryptPrivateKeyPEM(enc)
	if err == nil {
		t.Fatal("DecryptPrivateKeyPEM should fail for unsupported algorithm")
	}
}

func TestDecryptPrivateKey_UnsupportedAlgo(t *testing.T) {
	adminKey := make([]byte, 32)
	_, _ = rand.Read(adminKey)
	ke, _ := NewKeyEncryption(adminKey)

	enc := &EncryptedKeyData{
		Algorithm:     "CHACHA",
		EncryptedData: []byte("data"),
		Nonce:         []byte("nonce"),
	}
	_, err := ke.DecryptPrivateKey(enc, KeyType_KEY_TYPE_RSA_2048)
	if err == nil {
		t.Fatal("DecryptPrivateKey should fail for unsupported algorithm")
	}
}

func TestConvertPrivateKeyToPEM_RSA3072(t *testing.T) {
	rsaKey, _ := rsa.GenerateKey(rand.Reader, 3072)
	pemStr, err := ConvertPrivateKeyToPEM(rsaKey, KeyType_KEY_TYPE_RSA_3072)
	if err != nil {
		t.Fatalf("ConvertPrivateKeyToPEM RSA3072 error = %v", err)
	}
	if pemStr == "" {
		t.Error("expected non-empty PEM string")
	}
}
