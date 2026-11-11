// Package ztward provides a Golang SDK for integrating with the Ztward platform.
//
// The SDK provides easy-to-use clients for:
//   - Key Manager: Register keys, encrypt/decrypt data
//   - Platform: Make authorization decisions
//   - PAP: Manage policies and entitlements
//   - Key Access: Request data encryption keys
//
// Example usage:
//
//	config := &ztward.Config{
//	    PlatformAddress:   "platform.example.com:50051",
//	    KeyManagerAddress: "key-manager.example.com:50052",
//	    KeyAccessAddress:  "key-access.example.com:50053",
//	    PAPAddress:        "pap.example.com:8090",
//	    OIDC: &ztward.OIDCConfig{
//	        IssuerURL:    "https://keycloak.example.com/realms/ztward",
//	        ClientID:     "my-app",
//	        ClientSecret: "secret",
//	    },
//	}
//
//	client, err := ztward.NewClient(config)
//	if err != nil {
//	    log.Fatal(err)
//	}
//	defer client.Close()
package ztward

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/bdparrish/ztward/sdk/go/internal/fipsruntime"
	"go.opentelemetry.io/contrib/instrumentation/google.golang.org/grpc/otelgrpc"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
)

// Config holds the configuration for the Ztward SDK client.
type Config struct {
	// Service Addresses
	PlatformAddress   string // Platform service gRPC address (e.g., "platform.example.com:50051")
	KeyManagerAddress string // Key Manager service gRPC address (e.g., "key-manager.example.com:50052")
	KeyAccessAddress  string // Key Access service gRPC address (e.g., "key-access.example.com:50053")
	PAPAddress        string // PAP service HTTP address (e.g., "http://pap.example.com:8090")

	// Authentication
	OIDC *OIDCConfig // OIDC configuration for authentication
	// BearerToken allows callers to provide a pre-fetched token instead of using OIDC flows.
	BearerToken string

	// Connection options
	Timeout       time.Duration // Default timeout for requests (default: 30s)
	RetryAttempts int           // Number of retry attempts on failure (default: 3)
	UseTLS        bool          // Use TLS for gRPC connections (default: false)
	// CAFile is a PEM bundle used to verify service certificates when UseTLS is set.
	// Falls back to ZTWARD_GRPC_CA_FILE, then the system roots.
	CAFile string

	// Advanced options
	DialOptions []grpc.DialOption // Additional gRPC dial options

	// Telemetry
	Telemetry *TelemetryConfig

	// FIPS controls FIPS 140-3 enforcement for SDK crypto paths.
	FIPS *FIPSConfig
}

// TelemetryConfig controls SDK OpenTelemetry exporters.
type TelemetryConfig struct {
	Enabled     bool              // Enable telemetry exporters
	Endpoint    string            // OTLP gRPC endpoint (host:port)
	Insecure    bool              // Use insecure transport for OTLP
	ServiceName string            // Service identity reported to the collector
	Headers     map[string]string // Additional OTLP headers
}

// OIDCConfig holds OIDC authentication configuration.
type OIDCConfig struct {
	IssuerURL    string   // OIDC issuer URL (e.g., "https://keycloak.example.com/realms/ztward")
	ClientID     string   // OIDC client ID
	ClientSecret string   // OIDC client secret
	Username     string   // Username to use with password grant
	Password     string   // Password to use with password grant
	Scopes       []string // OIDC scopes (default: ["openid", "profile", "email"])
	RedirectURL  string   // OIDC redirect url (e.g., https://localhost:8080/callback)
}

// FIPSConfig controls FIPS 140-3 enforcement for SDK crypto.
type FIPSConfig struct {
	Enabled  bool   // Enable FIPS enforcement for SDK crypto paths
	GoModule string // Required GOFIPS140 module version (e.g., v1.0.0)
}

// Validate checks if the configuration is valid.
func (c *Config) Validate() error {
	if c.PlatformAddress == "" && c.KeyManagerAddress == "" && c.KeyAccessAddress == "" && c.PAPAddress == "" {
		return fmt.Errorf("at least one service address must be configured")
	}

	if c.OIDC != nil {
		if c.OIDC.IssuerURL == "" {
			return fmt.Errorf("OIDC issuer URL is required")
		}
		if c.OIDC.ClientID == "" {
			return fmt.Errorf("OIDC client ID is required")
		}
		if c.OIDC.ClientSecret == "" {
			return fmt.Errorf("OIDC client secret is required")
		}
	}

	if c.Telemetry != nil && c.Telemetry.Enabled {
		if strings.TrimSpace(c.Telemetry.Endpoint) == "" {
			return fmt.Errorf("telemetry endpoint is required when telemetry is enabled")
		}
		if c.Telemetry.ServiceName == "" {
			c.Telemetry.ServiceName = "ztward-sdk"
		}
	}

	if c.FIPS != nil && c.FIPS.Enabled {
		if strings.TrimSpace(c.FIPS.GoModule) == "" {
			return fmt.Errorf("fips.go_module is required when FIPS mode is enabled")
		}
		buildSetting, ok := fipsruntime.GoFIPSBuildSetting()
		if !ok {
			return fmt.Errorf("FIPS mode requires GOFIPS140 build setting %q", c.FIPS.GoModule)
		}
		if !fipsruntime.MatchesGoModule(c.FIPS.GoModule, buildSetting) {
			return fmt.Errorf("fips.go_module %q does not match build setting %q", c.FIPS.GoModule, buildSetting)
		}
		if value, ok := fipsruntime.GoDebugSetting("fips140"); ok && value == "off" {
			return fmt.Errorf("GODEBUG fips140=off disables FIPS mode")
		}
	}

	return nil
}

// SetDefaults sets default values for unspecified configuration options.
func (c *Config) SetDefaults() {
	if c.Timeout == 0 {
		c.Timeout = DefaultTimeout
	}
	if c.RetryAttempts == 0 {
		c.RetryAttempts = DefaultRetryAttempts
	}
	if c.OIDC != nil && len(c.OIDC.Scopes) == 0 {
		c.OIDC.Scopes = DefaultOIDCScopes
	}
	if c.Telemetry != nil {
		if c.Telemetry.ServiceName == "" {
			c.Telemetry.ServiceName = "ztward-sdk"
		}
		if c.Telemetry.Endpoint == "" {
			c.Telemetry.Endpoint = "localhost:4317"
		}
	}
	if c.FIPS != nil && c.FIPS.GoModule == "" {
		c.FIPS.GoModule = "v1.0.0"
	}
}

// IsFIPSMode returns true when FIPS enforcement is enabled.
func (c *Config) IsFIPSMode() bool {
	return c.FIPS != nil && c.FIPS.Enabled
}

// dialOptions returns the gRPC dial options based on configuration.
func (c *Config) dialOptions() ([]grpc.DialOption, error) {
	creds := insecure.NewCredentials()
	if c.UseTLS {
		tlsCfg, err := c.tlsConfig()
		if err != nil {
			return nil, err
		}
		creds = credentials.NewTLS(tlsCfg)
	}
	opts := []grpc.DialOption{grpc.WithTransportCredentials(creds)}

	// Add telemetry interceptors when enabled
	if c.Telemetry != nil && c.Telemetry.Enabled {
		opts = append(opts, grpc.WithStatsHandler(otelgrpc.NewClientHandler()))
	}

	// Add custom dial options
	opts = append(opts, c.DialOptions...)

	return opts, nil
}

// tlsConfig builds the client TLS config. A CA file that cannot be loaded is an
// error rather than a silent fallback, so a misconfiguration never downgrades
// to an unverified connection.
func (c *Config) tlsConfig() (*tls.Config, error) {
	cfg := &tls.Config{MinVersion: tls.VersionTLS12}
	caFile := strings.TrimSpace(c.CAFile)
	if caFile == "" {
		caFile = strings.TrimSpace(os.Getenv("ZTWARD_GRPC_CA_FILE"))
	}
	if caFile == "" {
		return cfg, nil
	}
	pem, err := os.ReadFile(caFile)
	if err != nil {
		return nil, fmt.Errorf("read CA file %s: %w", caFile, err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		return nil, fmt.Errorf("no certificates found in CA file %s", caFile)
	}
	cfg.RootCAs = pool
	return cfg, nil
}

// contextWithTimeout creates a context with the configured timeout.
func (c *Config) contextWithTimeout(ctx context.Context) (context.Context, context.CancelFunc) {
	if c.Timeout > 0 {
		return context.WithTimeout(ctx, c.Timeout)
	}
	return ctx, func() {}
}

// contextWithAuth adds authentication metadata to the context.
func contextWithAuth(ctx context.Context, token string) context.Context {
	if token == "" {
		return ctx
	}
	return metadata.AppendToOutgoingContext(ctx, "authorization", AuthHeaderPrefix+token)
}
