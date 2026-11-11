//go:build !fips

package key_manager

import (
	"context"
	"testing"
)

// TestCompositeAdminKeyProvider_GetAdminKey_WrongLengthNoError covers the branch
// where every provider succeeds (err==nil) but returns a key of the wrong length,
// so lastErr stays nil and we hit the "no admin key provider succeeded" return.
func TestCompositeAdminKeyProvider_GetAdminKey_WrongLengthNoError(t *testing.T) {
	provider1 := NewMockAdminKeyProvider()
	provider1.getAdminKeyFunc = func(ctx context.Context) ([]byte, error) {
		return make([]byte, 16), nil // wrong length, no error
	}

	composite := NewCompositeAdminKeyProvider(provider1)
	_, err := composite.GetAdminKey(context.Background())
	if err == nil {
		t.Fatal("expected error for wrong-length key with no provider error")
	}
}
