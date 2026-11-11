package ztdf

import (
	"path/filepath"
	"testing"
)

// With TLS requested, a CA that cannot be loaded must fail the dial setup
// rather than silently downgrading to plaintext.
func TestDialCredentialsTLSFailureIsAnError(t *testing.T) {
	t.Setenv("ZTWARD_GRPC_CA_FILE", filepath.Join(t.TempDir(), "missing-ca.pem"))

	for _, fips := range []bool{false, true} {
		if _, err := dialCredentials("localhost:50053", true, fips); err == nil {
			t.Errorf("dialCredentials(useTLS=true, fips=%v) = nil error, want error for unreadable CA", fips)
		}
	}
}

func TestDialCredentialsTLSWithDefaultRoots(t *testing.T) {
	t.Setenv("ZTWARD_GRPC_CA_FILE", "")
	t.Setenv("GRPC_DEFAULT_SSL_ROOTS_FILE_PATH", "")
	t.Setenv("SSL_CERT_FILE", "")

	if _, err := dialCredentials("localhost:50053", true, false); err != nil {
		t.Fatalf("dialCredentials(useTLS=true) with system roots: %v", err)
	}
}
