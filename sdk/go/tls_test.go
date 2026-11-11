package ztward

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/health"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
)

// startTLSHealthServer serves the gRPC health service over TLS with a cert
// signed by a throwaway CA. It returns the address and the CA PEM path.
func startTLSHealthServer(t *testing.T) (string, string) {
	t.Helper()

	caKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test-ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("create CA: %v", err)
	}
	caCert, _ := x509.ParseCertificate(caDER)

	srvKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	srvTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "localhost"},
		DNSNames:     []string{"localhost"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	srvDER, err := x509.CreateCertificate(rand.Reader, srvTmpl, caCert, &srvKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("create server cert: %v", err)
	}

	caPath := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(caPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}), 0o600); err != nil {
		t.Fatalf("write CA: %v", err)
	}

	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	srv := grpc.NewServer(grpc.Creds(credentials.NewServerTLSFromCert(&tls.Certificate{
		Certificate: [][]byte{srvDER},
		PrivateKey:  srvKey,
	})))
	healthpb.RegisterHealthServer(srv, health.NewServer())
	go func() { _ = srv.Serve(lis) }()
	t.Cleanup(srv.Stop)

	return lis.Addr().String(), caPath
}

func checkHealth(t *testing.T, cfg *Config, addr string) error {
	t.Helper()
	opts, err := cfg.dialOptions()
	if err != nil {
		return err
	}
	conn, err := grpc.NewClient(addr, opts...)
	if err != nil {
		return err
	}
	defer conn.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	_, err = healthpb.NewHealthClient(conn).Check(ctx, &healthpb.HealthCheckRequest{})
	return err
}

func TestDialOptionsTLS(t *testing.T) {
	t.Setenv("ZTWARD_GRPC_CA_FILE", "")
	addr, caPath := startTLSHealthServer(t)

	t.Run("trusted CA file connects", func(t *testing.T) {
		if err := checkHealth(t, &Config{UseTLS: true, CAFile: caPath}, addr); err != nil {
			t.Fatalf("expected TLS call to succeed, got %v", err)
		}
	})

	t.Run("CA from ZTWARD_GRPC_CA_FILE connects", func(t *testing.T) {
		t.Setenv("ZTWARD_GRPC_CA_FILE", caPath)
		if err := checkHealth(t, &Config{UseTLS: true}, addr); err != nil {
			t.Fatalf("expected TLS call to succeed, got %v", err)
		}
	})

	t.Run("untrusted server cert is rejected", func(t *testing.T) {
		err := checkHealth(t, &Config{UseTLS: true}, addr)
		if err == nil || !strings.Contains(err.Error(), "certificate") {
			t.Fatalf("expected certificate verification failure, got %v", err)
		}
	})

	t.Run("plaintext client cannot talk to TLS server", func(t *testing.T) {
		if err := checkHealth(t, &Config{UseTLS: false}, addr); err == nil {
			t.Fatal("expected plaintext call to a TLS server to fail")
		}
	})

	t.Run("unreadable CA file is a config error, not a fallback", func(t *testing.T) {
		_, err := (&Config{UseTLS: true, CAFile: filepath.Join(t.TempDir(), "missing.pem")}).dialOptions()
		if err == nil {
			t.Fatal("expected error for missing CA file")
		}
	})
}
