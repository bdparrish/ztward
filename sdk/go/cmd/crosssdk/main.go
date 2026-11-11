package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	ztward "github.com/bdparrish/ztward/sdk/go"
	"github.com/bdparrish/ztward/sdk/go/gen/models"
	"github.com/bdparrish/ztward/sdk/go/ztdf"
	"google.golang.org/protobuf/encoding/protojson"
)

type request struct {
	Plaintext    string `json:"plaintext,omitempty"`
	Ztdf         string `json:"ztdf,omitempty"`
	Filename     string `json:"filename,omitempty"`
	ContentType  string `json:"contentType,omitempty"`
	Resource     string `json:"resource,omitempty"`
	PolicyBase64 string `json:"policyBase64,omitempty"`
}

type response struct {
	Ztdf      string `json:"ztdf,omitempty"`
	Plaintext string `json:"plaintext,omitempty"`
}

type envConfig struct {
	useTLS             bool
	platformAddr       string
	keyManagerAddr     string
	keyAccessAddr      string
	oidcIssuer         string
	bearerToken        string
	clientID           string
	clientSecret       string
	username           string
	password           string
	scopes             []string
	keyDir             string
	defaultPolicy      string
	defaultResource    string
	defaultFilename    string
	defaultContentType string
	subjectID          string
	resourceAttributes map[string]string
}

type clientContext struct {
	cfg          envConfig
	ztwardClient *ztward.Client
	ztdfClient   *ztdf.Client
	keyInfo      *keyMetadata
}

type keyMetadata struct {
	KeyID          string `json:"keyId"`
	PrivateKeyPath string `json:"privateKeyPath"`
}

func main() {
	flag.Parse()
	if flag.NArg() < 1 {
		fail("usage: crosssdk <encrypt|decrypt>")
	}
	mode := flag.Arg(0)

	payload, err := io.ReadAll(os.Stdin)
	if err != nil {
		fail("failed to read input: %v", err)
	}
	payload = bytesTrimSpace(payload)
	if len(payload) == 0 {
		fail("missing JSON payload on stdin")
	}

	var req request
	if err := json.Unmarshal(payload, &req); err != nil {
		fail("failed to parse JSON request: %v", err)
	}

	cfg, err := loadEnvConfig()
	if err != nil {
		fail("misconfiguration: %v", err)
	}

	ctx := context.Background()
	clientCtx, err := newClientContext(ctx, cfg)
	if err != nil {
		fail("failed to initialize Ztward client: %v", err)
	}
	defer clientCtx.Close()

	switch mode {
	case "encrypt":
		resp, err := clientCtx.handleEncrypt(ctx, req)
		if err != nil {
			fail("encrypt failed: %v", err)
		}
		writeResponse(resp)
	case "decrypt":
		resp, err := clientCtx.handleDecrypt(ctx, req)
		if err != nil {
			fail("decrypt failed: %v", err)
		}
		writeResponse(resp)
	default:
		fail("unknown mode %q (expected encrypt or decrypt)", mode)
	}
}

func (c *clientContext) handleEncrypt(ctx context.Context, req request) (response, error) {
	plaintext, err := decodeBase64Field(req.Plaintext, "plaintext")
	if err != nil {
		return response{}, err
	}

	policyBase64 := firstNonEmpty(req.PolicyBase64, c.cfg.defaultPolicy)
	if policyBase64 == "" {
		return response{}, fmt.Errorf("policyBase64 must be provided either in request or ZTWARD_POLICY_BASE64")
	}
	policy, err := parsePolicy(policyBase64)
	if err != nil {
		return response{}, fmt.Errorf("invalid policy: %w", err)
	}

	resource := firstNonEmpty(req.Resource, c.cfg.defaultResource)
	if resource == "" {
		return response{}, fmt.Errorf("resource must be provided")
	}

	options := &ztdf.WrapOptions{
		Resource:             resource,
		ClientKeyID:          c.keyInfo.KeyID,
		ClientPrivateKeyPath: c.keyInfo.PrivateKeyPath,
		IntegrityCheck:       true,
		Policy:               policy,
		ResourceAttributes:   c.cfg.resourceAttributes,
	}

	tdo, err := c.ztdfClient.Wrap(ctx, plaintext, options)
	if err != nil {
		return response{}, fmt.Errorf("wrap failed: %w", err)
	}

	ztdfBytes, err := ztdf.SaveToBytes(tdo)
	if err != nil {
		return response{}, fmt.Errorf("failed to serialize ZTDF: %w", err)
	}

	return response{Ztdf: base64.StdEncoding.EncodeToString(ztdfBytes)}, nil
}

func (c *clientContext) handleDecrypt(ctx context.Context, req request) (response, error) {
	ztdfBytes, err := decodeBase64Field(req.Ztdf, "ztdf")
	if err != nil {
		return response{}, err
	}

	tdo, err := ztdf.LoadFromBytes(ztdfBytes)
	if err != nil {
		return response{}, fmt.Errorf("failed to parse ZTDF: %w", err)
	}

	resource := firstNonEmpty(req.Resource, c.cfg.defaultResource)
	if resource == "" {
		return response{}, fmt.Errorf("resource must be provided")
	}

	options := &ztdf.UnwrapOptions{
		Resource:             resource,
		ClientKeyID:          c.keyInfo.KeyID,
		ClientPrivateKeyPath: c.keyInfo.PrivateKeyPath,
		VerifyIntegrity:      true,
		VerifyPolicy:         true,
	}

	plaintext, err := c.ztdfClient.Unwrap(ctx, tdo, options)
	if err != nil {
		return response{}, fmt.Errorf("unwrap failed: %w", err)
	}

	return response{Plaintext: base64.StdEncoding.EncodeToString(plaintext)}, nil
}

func (c *clientContext) Close() {
	if c.ztwardClient != nil {
		_ = c.ztwardClient.Close()
	}
}

func newClientContext(ctx context.Context, cfg envConfig) (*clientContext, error) {
	ztwardConfig := &ztward.Config{
		PlatformAddress:   cfg.platformAddr,
		KeyManagerAddress: cfg.keyManagerAddr,
		KeyAccessAddress:  cfg.keyAccessAddr,
		Timeout:           30 * time.Second,
		RetryAttempts:     3,
		BearerToken:       cfg.bearerToken,
		UseTLS:            cfg.useTLS,
	}
	if cfg.bearerToken == "" {
		ztwardConfig.OIDC = &ztward.OIDCConfig{
			IssuerURL:    cfg.oidcIssuer,
			ClientID:     cfg.clientID,
			ClientSecret: cfg.clientSecret,
			Username:     cfg.username,
			Password:     cfg.password,
			Scopes:       cfg.scopes,
		}
	}

	client, err := ztward.NewClient(ztwardConfig)
	if err != nil {
		return nil, err
	}

	keyInfo, err := ensureClientKey(ctx, client, cfg)
	if err != nil {
		client.Close()
		return nil, err
	}

	return &clientContext{
		cfg:          cfg,
		ztwardClient: client,
		ztdfClient:   ztdf.NewClient(client),
		keyInfo:      keyInfo,
	}, nil
}

func ensureClientKey(ctx context.Context, client *ztward.Client, cfg envConfig) (*keyMetadata, error) {
	if cfg.keyDir == "" {
		return nil, fmt.Errorf("ZTWARD_GO_KEY_DIR must be set")
	}
	metaPath := filepath.Join(cfg.keyDir, "key-info.json")

	ownerID := cfg.subjectID
	if ownerID == "" {
		ownerID = cfg.clientID
	}
	if ownerID == "" {
		return nil, fmt.Errorf("ZTWARD_SUBJECT_ID or ZTWARD_CLIENT_ID must be set")
	}

	if info, err := loadKeyMetadata(metaPath); err == nil {
		if _, err := os.Stat(info.PrivateKeyPath); err == nil {
			// Reuse the stored key only if Key Manager still has it for this caller.
			usable, err := client.KeyManager.IsKeyUsable(ctx, ownerID, info.KeyID)
			if err != nil {
				return nil, fmt.Errorf("failed to verify stored client key %s: %w", info.KeyID, err)
			}
			if usable {
				return info, nil
			}
		}
	}

	if err := os.MkdirAll(cfg.keyDir, 0o700); err != nil {
		return nil, fmt.Errorf("failed to create key dir: %w", err)
	}

	privateKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return nil, fmt.Errorf("failed to generate key pair: %w", err)
	}

	privateKeyPath := filepath.Join(cfg.keyDir, "client.key")
	if err := savePrivateKey(privateKeyPath, privateKey); err != nil {
		return nil, err
	}

	publicPEM, err := marshalPublicKeyPEM(&privateKey.PublicKey)
	if err != nil {
		return nil, err
	}

	clientKey, err := client.KeyManager.RegisterKey(ctx, &ztward.RegisterKeyRequest{
		ClientID:     ownerID,
		PublicKeyPEM: publicPEM,
		KeyType:      ztward.KeyTypeRSA4096,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to register client key: %w", err)
	}

	info := &keyMetadata{
		KeyID:          clientKey.KeyID,
		PrivateKeyPath: privateKeyPath,
	}
	if err := saveKeyMetadata(metaPath, info); err != nil {
		return nil, err
	}
	return info, nil
}

func savePrivateKey(path string, key *rsa.PrivateKey) error {
	keyBytes := x509.MarshalPKCS1PrivateKey(key)
	block := &pem.Block{Type: "RSA PRIVATE KEY", Bytes: keyBytes}
	return os.WriteFile(path, pem.EncodeToMemory(block), 0o600)
}

func marshalPublicKeyPEM(pub *rsa.PublicKey) (string, error) {
	bytes, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return "", fmt.Errorf("failed to marshal public key: %w", err)
	}
	block := &pem.Block{Type: "PUBLIC KEY", Bytes: bytes}
	return string(pem.EncodeToMemory(block)), nil
}

func loadKeyMetadata(path string) (*keyMetadata, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var meta keyMetadata
	if err := json.Unmarshal(data, &meta); err != nil {
		return nil, err
	}
	return &meta, nil
}

func saveKeyMetadata(path string, meta *keyMetadata) error {
	data, err := json.MarshalIndent(meta, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o600)
}

func loadEnvConfig() (envConfig, error) {
	cfg := envConfig{
		platformAddr:       firstNonEmpty(os.Getenv("ZTWARD_PLATFORM_ADDR"), os.Getenv("ZTWARD_PLATFORM_URL")),
		keyManagerAddr:     firstNonEmpty(os.Getenv("ZTWARD_KEY_MANAGER_ADDR"), os.Getenv("ZTWARD_KEY_MANAGER_URL"), os.Getenv("ZTWARD_KEY_MANAGER_URI")),
		keyAccessAddr:      firstNonEmpty(os.Getenv("ZTWARD_KEY_ACCESS_ADDR"), os.Getenv("ZTWARD_KEY_ACCESS_URL"), os.Getenv("ZTWARD_KEY_ACCESS_URI")),
		oidcIssuer:         os.Getenv("ZTWARD_OIDC_ISSUER"),
		bearerToken:        strings.TrimSpace(os.Getenv("ZTWARD_BEARER_TOKEN")),
		clientID:           os.Getenv("ZTWARD_CLIENT_ID"),
		clientSecret:       os.Getenv("ZTWARD_CLIENT_SECRET"),
		username:           os.Getenv("ZTWARD_USERNAME"),
		password:           os.Getenv("ZTWARD_PASSWORD"),
		defaultPolicy:      os.Getenv("ZTWARD_POLICY_BASE64"),
		defaultResource:    os.Getenv("ZTWARD_RESOURCE"),
		defaultFilename:    os.Getenv("ZTWARD_FILENAME"),
		defaultContentType: os.Getenv("ZTWARD_CONTENT_TYPE"),
		keyDir:             os.Getenv("ZTWARD_GO_KEY_DIR"),
		subjectID:          strings.TrimSpace(os.Getenv("ZTWARD_SUBJECT_ID")),
	}
	cfg.resourceAttributes = parseAttributes(os.Getenv("ZTWARD_RESOURCE_ATTRIBUTES"))
	// Match the Java/JS helpers: an https:// service URI means TLS.
	cfg.useTLS = strings.EqualFold(os.Getenv("ZTWARD_USE_TLS"), "true") ||
		strings.HasPrefix(os.Getenv("ZTWARD_KEY_ACCESS_URI"), "https://") ||
		strings.HasPrefix(os.Getenv("ZTWARD_KEY_MANAGER_URI"), "https://")
	if cfg.keyAccessAddr == "" || cfg.keyManagerAddr == "" {
		return cfg, fmt.Errorf("ZTWARD_KEY_ACCESS_ADDR/URL and ZTWARD_KEY_MANAGER_ADDR/URL are required")
	}
	if cfg.bearerToken == "" {
		if cfg.clientID == "" {
			return cfg, fmt.Errorf("ZTWARD_CLIENT_ID is required when ZTWARD_BEARER_TOKEN is not set")
		}
		if cfg.clientSecret == "" {
			return cfg, fmt.Errorf("ZTWARD_CLIENT_SECRET is required when ZTWARD_BEARER_TOKEN is not set")
		}
	}
	if cfg.oidcIssuer == "" && cfg.bearerToken == "" {
		keycloakURL := os.Getenv("ZTWARD_KEYCLOAK_URL")
		realm := os.Getenv("ZTWARD_KEYCLOAK_REALM")
		if keycloakURL != "" && realm != "" {
			cfg.oidcIssuer = strings.TrimRight(keycloakURL, "/") + "/realms/" + realm
		} else {
			return cfg, fmt.Errorf("ZTWARD_OIDC_ISSUER or ZTWARD_KEYCLOAK_URL/ZTWARD_KEYCLOAK_REALM must be set")
		}
	}
	if cfg.defaultResource == "" {
		cfg.defaultResource = "integration-resource"
	}
	if cfg.defaultFilename == "" {
		cfg.defaultFilename = "interop.txt"
	}
	if cfg.defaultContentType == "" {
		cfg.defaultContentType = "text/plain"
	}

	scopeStr := os.Getenv("ZTWARD_OIDC_SCOPES")
	if scopeStr == "" {
		scopeStr = os.Getenv("ZTWARD_OIDC_SCOPE")
	}
	if scopeStr == "" {
		scopeStr = "openid profile email"
	}
	cfg.scopes = strings.Fields(scopeStr)
	if cfg.subjectID == "" && cfg.clientID == "" {
		return cfg, fmt.Errorf("ZTWARD_SUBJECT_ID or ZTWARD_CLIENT_ID must be set")
	}
	return cfg, nil
}

func parsePolicy(policyBase64 string) (*models.ZtdfPolicy, error) {
	data, err := base64.StdEncoding.DecodeString(policyBase64)
	if err != nil {
		return nil, err
	}
	policy := &models.ZtdfPolicy{}
	if err := protojson.Unmarshal(data, policy); err != nil {
		return nil, err
	}
	return policy, nil
}

func decodeBase64Field(value, name string) ([]byte, error) {
	if value == "" {
		return nil, fmt.Errorf("missing %s field", name)
	}
	data, err := base64.StdEncoding.DecodeString(value)
	if err != nil {
		return nil, fmt.Errorf("invalid base64 in %s: %w", name, err)
	}
	return data, nil
}

func writeResponse(resp response) {
	enc := json.NewEncoder(os.Stdout)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(resp); err != nil {
		fail("failed to encode response: %v", err)
	}
}

func fail(format string, args ...any) {
	msg := fmt.Sprintf(format, args...)
	if !strings.HasSuffix(msg, "\n") {
		msg += "\n"
	}
	_, _ = os.Stderr.WriteString(msg)
	os.Exit(1)
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}

func bytesTrimSpace(b []byte) []byte {
	return []byte(strings.TrimSpace(string(b)))
}

func parseAttributes(raw string) map[string]string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil
	}
	result := make(map[string]string)
	pairs := strings.Split(raw, ",")
	for _, pair := range pairs {
		pair = strings.TrimSpace(pair)
		if pair == "" {
			continue
		}
		parts := strings.SplitN(pair, "=", 2)
		if len(parts) != 2 {
			continue
		}
		key := strings.TrimSpace(parts[0])
		value := strings.TrimSpace(parts[1])
		if key == "" {
			continue
		}
		result[key] = value
	}
	if len(result) == 0 {
		return nil
	}
	return result
}
