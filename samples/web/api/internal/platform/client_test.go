package platform

import (
	"path/filepath"
	"testing"
)

func TestTransportCredentials(t *testing.T) {
	t.Run("TLS by default", func(t *testing.T) {
		t.Setenv("PLATFORM_INSECURE", "")
		t.Setenv("ZTWARD_GRPC_CA_FILE", "")
		creds, err := transportCredentials()
		if err != nil || creds.Info().SecurityProtocol != "tls" {
			t.Fatalf("got %v, %v; want TLS credentials", creds, err)
		}
	})
	t.Run("explicit insecure opt-out", func(t *testing.T) {
		t.Setenv("PLATFORM_INSECURE", "true")
		creds, err := transportCredentials()
		if err != nil || creds.Info().SecurityProtocol != "insecure" {
			t.Fatalf("got %v, %v; want insecure credentials", creds, err)
		}
	})
	t.Run("unreadable CA is an error, not a downgrade", func(t *testing.T) {
		t.Setenv("PLATFORM_INSECURE", "")
		t.Setenv("ZTWARD_GRPC_CA_FILE", filepath.Join(t.TempDir(), "missing.pem"))
		if _, err := transportCredentials(); err == nil {
			t.Fatal("expected error for unreadable CA file")
		}
	})
}
