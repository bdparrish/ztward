package auth

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"
)

func unsignedJWT(t *testing.T, username string) string {
	t.Helper()
	enc := base64.RawURLEncoding
	claims, _ := json.Marshal(map[string]any{"sub": "sub-" + username, "preferred_username": username})
	return enc.EncodeToString([]byte(`{"alg":"none"}`)) + "." + enc.EncodeToString(claims) + ".sig"
}

// newCachedProvider returns a provider for `username` whose token file already
// holds a valid token for `cachedUser`, plus a counter of token-endpoint calls.
func newCachedProvider(t *testing.T, username, cachedUser string) (*KeycloakAuthProvider, *int32) {
	t.Helper()
	var calls int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&calls, 1)
		_ = r.ParseForm()
		fmt.Fprintf(w, `{"access_token":"at","id_token":%q,"refresh_token":"rt","expires_in":300}`,
			unsignedJWT(t, r.PostForm.Get("username")))
	}))
	t.Cleanup(srv.Close)

	p, err := NewKeycloakAuthProvider(&AuthConfig{
		IssuerURL: srv.URL,
		ClientID:  "test-client",
		Username:  username,
		Password:  "pw",
		TokenFile: filepath.Join(t.TempDir(), "token.json"),
	})
	if err != nil {
		t.Fatalf("NewKeycloakAuthProvider: %v", err)
	}
	k := p.(*KeycloakAuthProvider)
	k.tokenStore = &tokenStore{
		AccessToken: "cached-at",
		IDToken:     unsignedJWT(t, cachedUser),
		ExpiresAt:   time.Now().Add(time.Hour),
		Issuer:      srv.URL,
	}
	if err := k.saveToken(); err != nil {
		t.Fatalf("saveToken: %v", err)
	}
	k.tokenStore = nil
	return k, &calls
}

func TestAuthenticate_CachedTokenForDifferentUserIsNotReused(t *testing.T) {
	k, calls := newCachedProvider(t, "service-account-1", "user123")

	if _, err := k.Authenticate(context.Background()); err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	claims, err := k.GetUserClaims()
	if err != nil {
		t.Fatalf("GetUserClaims: %v", err)
	}
	if claims.PreferredUsername != "service-account-1" {
		t.Errorf("authenticated as %q, want service-account-1", claims.PreferredUsername)
	}
	if atomic.LoadInt32(calls) != 1 {
		t.Errorf("token endpoint called %d times, want 1 (fresh login)", *calls)
	}
}

func TestAuthenticate_CachedTokenForSameUserIsReused(t *testing.T) {
	k, calls := newCachedProvider(t, "user123", "user123")

	if _, err := k.Authenticate(context.Background()); err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	if atomic.LoadInt32(calls) != 0 {
		t.Errorf("token endpoint called %d times, want 0 (cache hit)", *calls)
	}
}
