package key_manager

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"testing"

	"github.com/bdparrish/ztward/go/pkg/security/encryption"

	"google.golang.org/protobuf/types/known/timestamppb"
)

// browserDecrypt mirrors the browser SDK (sdk/js/src/browser/dek-decryption.js):
// a fixed-length ECDH shared secret, HKDF-SHA256, then AES-256-GCM.
func browserDecrypt(t *testing.T, priv *ecdh.PrivateKey, data []byte) ([]byte, error) {
	t.Helper()
	peer, err := ecdh.P256().NewPublicKey(append([]byte{0x04}, data[:64]...))
	if err != nil {
		return nil, err
	}
	z, err := priv.ECDH(peer)
	if err != nil {
		return nil, err
	}
	key, err := hkdf.Key(sha256.New, z, nil, "key-manager-ecc-dek", 32)
	if err != nil {
		return nil, err
	}
	block, _ := aes.NewCipher(key)
	gcm, _ := cipher.NewGCM(block)
	rest := data[64:]
	return gcm.Open(nil, rest[:gcm.NonceSize()], rest[gcm.NonceSize():], nil)
}

func p256ClientKey(t *testing.T) (*ecdh.PrivateKey, *ecdsa.PublicKey, string) {
	t.Helper()
	priv, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(priv.PublicKey())
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		t.Fatal(err)
	}
	return priv, parsed.(*ecdsa.PublicKey), string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
}

// The shared secret must be the fixed-length X coordinate (SP 800-56A). A
// minimal big-endian encoding drops leading zero bytes for ~1/256 keys and
// silently breaks browser decryption.
func TestECCWrap_InteroperatesWithBrowserDerivation(t *testing.T) {
	priv, pub, _ := p256ClientKey(t)
	for i := 0; i < 1500; i++ {
		dek := make([]byte, 32)
		_, _ = rand.Read(dek)
		wrapped, err := encryptDEKWithECCPublicKey(pub, dek)
		if err != nil {
			t.Fatalf("wrap %d: %v", i, err)
		}
		got, err := browserDecrypt(t, priv, wrapped)
		if err != nil || string(got) != string(dek) {
			t.Fatalf("iteration %d: browser-style decryption failed: %v", i, err)
		}
	}
}

func TestRegisterClientKey_FIPSAllowsApprovedECCClientKeys(t *testing.T) {
	srv := newTestKeyManagerServerWithFIPS(t, encryption.RSA2048, true)
	_, _, pemStr := p256ClientKey(t)

	resp, err := srv.RegisterClientKey(ctxWithUser("alice"), &RegisterClientKeyRequest{
		ClientId:     "browser",
		PublicKeyPem: pemStr,
		KeyType:      KeyType_KEY_TYPE_ECC_P256,
	})
	if err != nil || !resp.GetSuccess() {
		t.Fatalf("ECC P-256 client key rejected in FIPS mode: %v %s", err, resp.GetErrorMessage())
	}

	// The server infers the type from the PEM; a key it cannot infer keeps the
	// requested (non-approved) type and must be refused.
	edPub, _, _ := ed25519.GenerateKey(rand.Reader)
	edDER, _ := x509.MarshalPKIXPublicKey(edPub)
	resp, err = srv.RegisterClientKey(ctxWithUser("alice"), &RegisterClientKeyRequest{
		ClientId:     "browser",
		PublicKeyPem: string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: edDER})),
		KeyType:      KeyType_KEY_TYPE_KYBER_768,
	})
	if err == nil && resp.GetSuccess() {
		t.Fatal("non-approved client key type accepted in FIPS mode")
	}
}

func TestUnwrapDEK_FIPSDeliversDEKToECCClientKey(t *testing.T) {
	ctx := context.Background()
	srv := newTestKeyManagerServerWithFIPS(t, encryption.RSA2048, true)

	created, err := srv.CreateKey(ctx, &CreateKeyRequest{
		Name:         "fips-service-key",
		KeyType:      KeyType_KEY_TYPE_RSA_2048,
		ProviderType: KeyProviderType_KEY_PROVIDER_TYPE_SOFTWARE,
	})
	if err != nil {
		t.Fatalf("CreateKey: %v", err)
	}
	provider, _ := srv.providerFactory.GetProvider(KeyProviderType_KEY_PROVIDER_TYPE_SOFTWARE)
	dek := []byte("test-dek-32-bytes-padding-xyz123")
	encryptedDEK, err := provider.Encrypt(ctx, created.Key.KeyId, dek)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	priv, _, pemStr := p256ClientKey(t)
	if err := srv.clientKeyStore.RegisterKey(ctx, &Key{
		KeyId: "browser-key", ClientId: "alice", PublicKeyPem: pemStr,
		KeyType: KeyType_KEY_TYPE_ECC_P256, Status: KeyStatus_KEY_STATUS_ACTIVE,
		CreatedAt: timestamppb.Now(), Metadata: map[string]string{},
	}); err != nil {
		t.Fatalf("RegisterKey: %v", err)
	}

	resp, err := srv.dekService.UnwrapDEK(ctx, &UnwrapDEKRequest{
		Subject: "alice", Resource: "r1", KeyId: created.Key.KeyId,
		ClientKeyId: "browser-key", EncryptedDek: encryptedDEK,
	})
	if err != nil || !resp.AccessGranted {
		t.Fatalf("UnwrapDEK for ECC client in FIPS mode: %v %s", err, resp.GetAccessReason())
	}
	got, err := browserDecrypt(t, priv, resp.EncryptedDekForSubject)
	if err != nil || string(got) != string(dek) {
		t.Fatalf("client could not recover the DEK: %v", err)
	}
}
