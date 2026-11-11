package key_manager

import (
	"context"
	"testing"

	"github.com/bdparrish/ztward/go/pkg/security/fipsbuild"
)

func TestUseHardwareCardReaderConfig(t *testing.T) {
	if !useHardwareCardReaderConfig(map[string]string{"pkcs11_library": "/tmp/lib.so"}) {
		t.Fatalf("expected hardware reader config to be detected")
	}
	if !useHardwareCardReaderConfig(map[string]string{"reader_backend": "yubikey"}) {
		t.Fatalf("expected reader_backend=yubikey to enable hardware mode")
	}
	if useHardwareCardReaderConfig(map[string]string{"device_id": "mock-device-1", "pin": "1234"}) {
		t.Fatalf("device_id+pin alone should keep mock reader behavior")
	}
}

func TestSmartCardKeyProvider_ConfigureGenerateLookup(t *testing.T) {
	provider := NewSmartCardKeyProvider("smartcard", nil)

	if err := provider.Configure(map[string]string{
		"device_id": "mock-device-1",
		"pin":       "1234",
	}); err != nil {
		t.Fatalf("Configure() failed: %v", err)
	}

	if !provider.IsAvailable() {
		t.Fatalf("provider should be available after configure")
	}

	keyPair, err := provider.GenerateKeyPair(context.Background(), KeyType_KEY_TYPE_RSA_2048, "mock-key-1", map[string]string{})
	if err != nil {
		t.Fatalf("GenerateKeyPair() failed: %v", err)
	}
	if keyPair.PublicKeyPEM == "" {
		t.Fatalf("expected public key PEM to be populated")
	}

	loaded, err := provider.GetKeyPair(context.Background(), "mock-key-1")
	if err != nil {
		t.Fatalf("GetKeyPair() failed: %v", err)
	}
	if loaded.KeyID != "mock-key-1" {
		t.Fatalf("unexpected key id %q", loaded.KeyID)
	}
}

func TestSmartCardKeyProvider_EncryptDecryptRoundTrip(t *testing.T) {
	provider := NewSmartCardKeyProvider("smartcard", nil)
	if err := provider.Configure(map[string]string{
		"device_id": "mock-device-1",
		"pin":       "1234",
	}); err != nil {
		t.Fatalf("Configure() failed: %v", err)
	}

	const keyID = "mock-key-2"
	if _, err := provider.GenerateKeyPair(context.Background(), KeyType_KEY_TYPE_RSA_2048, keyID, map[string]string{}); err != nil {
		t.Fatalf("GenerateKeyPair() failed: %v", err)
	}

	plaintext := []byte("smartcard provider roundtrip")
	ciphertext, err := provider.Encrypt(context.Background(), keyID, plaintext)
	if err != nil {
		t.Fatalf("Encrypt() failed: %v", err)
	}

	decrypted, err := provider.Decrypt(context.Background(), keyID, ciphertext)
	if err != nil {
		t.Fatalf("Decrypt() failed: %v", err)
	}

	if string(decrypted) != string(plaintext) {
		t.Fatalf("decrypted text mismatch: got %q want %q", string(decrypted), string(plaintext))
	}
}

func TestSmartCardKeyProvider_RotateKey(t *testing.T) {
	provider := NewSmartCardKeyProvider("smartcard", nil)
	if err := provider.Configure(map[string]string{
		"device_id": "mock-device-1",
		"pin":       "1234",
	}); err != nil {
		t.Fatalf("Configure() failed: %v", err)
	}

	const keyID = "mock-key-rotate"
	if _, err := provider.GenerateKeyPair(context.Background(), KeyType_KEY_TYPE_RSA_2048, keyID, map[string]string{}); err != nil {
		t.Fatalf("GenerateKeyPair() failed: %v", err)
	}

	rotated, err := provider.RotateKey(context.Background(), keyID)
	if err != nil {
		t.Fatalf("RotateKey() failed: %v", err)
	}
	if rotated.LastRotated == nil {
		t.Fatalf("expected rotated key to have LastRotated set")
	}
}

func TestSmartCardKeyProvider_GetSupportedKeyTypes_FIPSConfig(t *testing.T) {
	provider := NewSmartCardKeyProvider("smartcard", nil)

	if err := provider.Configure(map[string]string{
		"device_id":    "mock-device-1",
		"pin":          "1234",
		"fips_enabled": "true",
	}); err != nil {
		t.Fatalf("Configure() failed: %v", err)
	}

	got := provider.GetSupportedKeyTypes()
	if len(got) != 1 || got[0] != KeyType_KEY_TYPE_RSA_2048 {
		t.Fatalf("unexpected supported key types in FIPS mode: %v", got)
	}
}

func TestSmartCardKeyProvider_GenerateKeyPair_BlocksECCInFIPS(t *testing.T) {
	provider := NewSmartCardKeyProvider("smartcard", nil)

	if err := provider.Configure(map[string]string{
		"device_id":    "mock-device-1",
		"pin":          "1234",
		"fips_enabled": "true",
	}); err != nil {
		t.Fatalf("Configure() failed: %v", err)
	}

	if _, err := provider.GenerateKeyPair(context.Background(), KeyType_KEY_TYPE_ECC_P256, "mock-key-ecc-fips", map[string]string{}); err == nil {
		t.Fatalf("expected ECC key generation to be rejected in FIPS mode")
	}
}

func TestSmartCardKeyProvider_Sign_BlocksNonFIPSKeyInFIPS(t *testing.T) {
	if fipsbuild.Enabled {
		t.Skip("this scenario requires creating ECC key before enabling FIPS at runtime")
	}

	provider := NewSmartCardKeyProvider("smartcard", nil)
	if err := provider.Configure(map[string]string{
		"device_id": "mock-device-1",
		"pin":       "1234",
	}); err != nil {
		t.Fatalf("Configure() failed: %v", err)
	}

	const keyID = "mock-key-ecc-sign"
	if _, err := provider.GenerateKeyPair(context.Background(), KeyType_KEY_TYPE_ECC_P256, keyID, map[string]string{}); err != nil {
		t.Fatalf("GenerateKeyPair() failed: %v", err)
	}

	if err := provider.Configure(map[string]string{"fips_enabled": "true"}); err != nil {
		t.Fatalf("Configure() failed: %v", err)
	}

	if _, err := provider.Sign(context.Background(), keyID, []byte("payload")); err == nil {
		t.Fatalf("expected sign to be rejected for non-FIPS key in FIPS mode")
	}
}

func TestNewSmartCardKeyProvider_WithConfig_NoHardware(t *testing.T) {
	// config without hardware trigger fields - uses mock reader
	provider := NewSmartCardKeyProvider("usb_token", map[string]string{
		"device_id": "mock-device-1",
	})
	if provider == nil {
		t.Fatal("expected non-nil provider")
	}
	if provider.GetProviderType() != KeyProviderType_KEY_PROVIDER_TYPE_USB_TOKEN {
		t.Errorf("expected USB_TOKEN type, got %v", provider.GetProviderType())
	}
}

func TestNewSmartCardKeyProvider_USBTokenName(t *testing.T) {
	provider := NewSmartCardKeyProvider("usb_token", nil)
	if provider.GetProviderName() != "USB Token Key Provider" {
		t.Errorf("unexpected provider name: %q", provider.GetProviderName())
	}
}

func TestSmartCardKeyProvider_ValidateFIPSKeyByIDLocked_KeyInMetadata(t *testing.T) {
	provider := NewSmartCardKeyProvider("smartcard", nil)
	if err := provider.Configure(map[string]string{
		"device_id":    "mock-device-1",
		"pin":          "1234",
		"fips_enabled": "true",
	}); err != nil {
		t.Fatalf("Configure() failed: %v", err)
	}

	// Generate an RSA-2048 key (FIPS allowed) and populate metadata
	const keyID = "fips-meta-key"
	if _, err := provider.GenerateKeyPair(context.Background(), KeyType_KEY_TYPE_RSA_2048, keyID, map[string]string{}); err != nil {
		t.Fatalf("GenerateKeyPair() failed: %v", err)
	}

	// Sign should succeed - RSA-2048 is FIPS allowed
	provider.mu.Lock()
	err := provider.validateFIPSKeyByIDLocked(keyID)
	provider.mu.Unlock()
	if err != nil {
		t.Fatalf("validateFIPSKeyByIDLocked for RSA-2048 should succeed: %v", err)
	}
}

func TestSmartCardKeyProvider_ValidateFIPSKeyByIDLocked_KeyNotInMetadata(t *testing.T) {
	provider := NewSmartCardKeyProvider("smartcard", nil)
	if err := provider.Configure(map[string]string{
		"device_id": "mock-device-1",
		"pin":       "1234",
	}); err != nil {
		t.Fatalf("Configure() failed: %v", err)
	}

	provider.mu.Lock()
	err := provider.validateFIPSKeyByIDLocked("nonexistent-key")
	provider.mu.Unlock()
	if fipsbuild.Enabled {
		// FIPS mode can't be turned off in a FIPS build, and an unknown key fails closed.
		if err == nil {
			t.Fatal("validateFIPSKeyByIDLocked should reject an unknown key in a FIPS build")
		}
		return
	}
	// Without FIPS mode, the validation should return nil regardless
	if err != nil {
		t.Fatalf("validateFIPSKeyByIDLocked without FIPS should be nil, got: %v", err)
	}
}

func TestSmartCardKeyProvider_GetConfiguration(t *testing.T) {
	provider := NewSmartCardKeyProvider("smartcard", nil)
	if err := provider.Configure(map[string]string{
		"device_id": "mock-device-1",
		"pin":       "1234",
		"custom":    "value",
	}); err != nil {
		t.Fatalf("Configure() failed: %v", err)
	}

	cfg := provider.GetConfiguration()
	// PIN should be excluded
	if _, exists := cfg["pin"]; exists {
		t.Error("GetConfiguration should exclude 'pin' field")
	}
	if cfg["custom"] != "value" {
		t.Errorf("expected custom=value, got %q", cfg["custom"])
	}
}
