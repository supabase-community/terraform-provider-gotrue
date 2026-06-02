package adminclient

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

func newTestServer(t *testing.T, handler http.HandlerFunc) (*httptest.Server, Client) {
	t.Helper()
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)

	u, err := url.ParseRequestURI(srv.URL)
	if err != nil {
		t.Fatalf("parsing test server URL: %v", err)
	}

	c, err := New(WithBaseURL(*u))
	if err != nil {
		t.Fatalf("creating client: %v", err)
	}
	return srv, c
}

func providerJSON(identifier string) []byte {
	p := CustomOAuthProviderResponse{
		Identifier:   identifier,
		ProviderType: "oidc",
		Name:         "Test",
		ClientID:     "cid",
		CreatedAt:    time.Now(),
		UpdatedAt:    time.Now(),
	}
	b, _ := json.Marshal(p)
	return b
}

// TestCustomOAuthProviderPathEscaping verifies that an identifier containing "/"
// is percent-encoded in the request path so it is treated as a single path
// segment rather than splitting the URL into extra segments.
func TestCustomOAuthProviderPathEscaping(t *testing.T) {
	const identifier = "custom:my/provider"
	// url.PathEscape encodes "/" → "%2F" but leaves ":" unencoded (safe in segments).
	escaped := url.PathEscape(identifier) // "custom:my%2Fprovider"

	assertEscapedPath := func(t *testing.T, r *http.Request) {
		t.Helper()
		// The raw wire URI must contain the encoded form, not the bare "/".
		if !strings.HasSuffix(r.RequestURI, escaped) {
			t.Errorf("expected request URI to end with %q, got %q", escaped, r.RequestURI)
		}
	}

	t.Run("GetCustomOAuthProvider", func(t *testing.T) {
		_, c := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
			assertEscapedPath(t, r)
			w.WriteHeader(http.StatusOK)
			w.Write(providerJSON(identifier))
		})
		c.GetCustomOAuthProvider(context.Background(), identifier) //nolint:errcheck
	})

	t.Run("UpdateCustomOAuthProvider", func(t *testing.T) {
		_, c := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
			if r.Method == http.MethodPut {
				assertEscapedPath(t, r)
			}
			w.WriteHeader(http.StatusOK)
			w.Write(providerJSON(identifier))
		})
		c.UpdateCustomOAuthProvider(context.Background(), identifier, &CustomOAuthProviderRequest{}) //nolint:errcheck
	})

	t.Run("DeleteCustomOAuthProvider", func(t *testing.T) {
		_, c := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
			assertEscapedPath(t, r)
			w.WriteHeader(http.StatusOK)
		})
		c.DeleteCustomOAuthProvider(context.Background(), identifier) //nolint:errcheck
	})
}
