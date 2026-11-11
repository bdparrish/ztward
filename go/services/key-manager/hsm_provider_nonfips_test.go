//go:build !fips

package key_manager

import (
	"testing"
)

// TestNewHSMKeyProvider_WithConfig exercises the `if config != nil` branch.
func TestNewHSMKeyProvider_WithConfig(t *testing.T) {
	p := NewHSMKeyProvider(map[string]string{
		"hsm_endpoint": "mock",
	})
	if p == nil {
		t.Fatal("NewHSMKeyProvider returned nil")
	}
	if !p.IsAvailable() {
		t.Fatal("expected provider to be available when config is supplied")
	}
	cfg := p.GetConfiguration()
	if cfg["hsm_endpoint"] != "mock" {
		t.Errorf("expected hsm_endpoint=mock in config, got %v", cfg)
	}
}
