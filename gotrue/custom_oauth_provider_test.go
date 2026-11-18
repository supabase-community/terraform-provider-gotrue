package gotrue

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/terraform"

	"github.com/supabase-community/terraform-provider-gotrue/adminclient"
)

func baseOIDCConfig() map[string]interface{} {
	return map[string]interface{}{
		"provider_type": "oidc",
		"identifier":    "custom:acme",
		"name":          "Acme",
		"client_id":     "cid",
		"issuer":        "https://idp.example.com",
	}
}

func with(base map[string]interface{}, kv map[string]interface{}) map[string]interface{} {
	out := map[string]interface{}{}
	for k, v := range base {
		out[k] = v
	}
	for k, v := range kv {
		out[k] = v
	}
	return out
}

func TestCustomOAuthProviderClientAuthValidation(t *testing.T) {
	tests := []struct {
		name    string
		config  map[string]interface{}
		wantErr string
	}{
		{
			name:   "client_secret default with secret",
			config: with(baseOIDCConfig(), map[string]interface{}{"client_secret": "s"}),
		},
		{
			name:    "client_secret default without secret",
			config:  baseOIDCConfig(),
			wantErr: "client_secret is required",
		},
		{
			name: "client_secret with audience",
			config: with(baseOIDCConfig(), map[string]interface{}{
				"client_secret":             "s",
				"client_assertion_audience": "https://aud",
			}),
			wantErr: "client_assertion_audience is only supported",
		},
		{
			name: "private_key_jwt with audience",
			config: with(baseOIDCConfig(), map[string]interface{}{
				"client_auth_method":        "private_key_jwt",
				"client_assertion_audience": "https://aud",
			}),
		},
		{
			name: "private_key_jwt with secret",
			config: with(baseOIDCConfig(), map[string]interface{}{
				"client_auth_method": "private_key_jwt",
				"client_secret":      "s",
			}),
			wantErr: "client_secret must not be set",
		},
		{
			name: "private_key_jwt on oauth2",
			config: with(baseOIDCConfig(), map[string]interface{}{
				"provider_type":      "oauth2",
				"client_auth_method": "private_key_jwt",
			}),
			wantErr: "only supported for OIDC providers",
		},
		{
			name: "unknown method",
			config: with(baseOIDCConfig(), map[string]interface{}{
				"client_auth_method": "basic",
				"client_secret":      "s",
			}),
			wantErr: "expected client_auth_method to be one of",
		},
	}

	r := resourceCustomOAuthProvider()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := terraform.NewResourceConfigRaw(tt.config)

			var errs []string
			for _, d := range r.Validate(cfg) {
				errs = append(errs, d.Summary)
			}
			if len(errs) == 0 {
				if _, err := r.Diff(context.Background(), nil, cfg, nil); err != nil {
					errs = append(errs, err.Error())
				}
			}

			got := strings.Join(errs, "; ")
			switch {
			case tt.wantErr == "" && got != "":
				t.Fatalf("unexpected error: %s", got)
			case tt.wantErr != "" && !strings.Contains(got, tt.wantErr):
				t.Fatalf("expected error containing %q, got %q", tt.wantErr, got)
			}
		})
	}
}

// recordingServer returns a client whose requests are decoded into the
// returned map, and which responds with resp.
func recordingServer(t *testing.T, resp adminclient.CustomOAuthProviderResponse) (adminclient.Client, *map[string]interface{}) {
	t.Helper()
	body := map[string]interface{}{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost || r.Method == http.MethodPut {
			raw, _ := io.ReadAll(r.Body)
			body = map[string]interface{}{}
			if err := json.Unmarshal(raw, &body); err != nil {
				t.Errorf("decoding request body: %v", err)
			}
		}
		w.Header().Set("Content-Type", "application/json")
		if r.Method == http.MethodPost {
			w.WriteHeader(http.StatusCreated)
		}
		_ = json.NewEncoder(w).Encode(resp)
	}))
	t.Cleanup(srv.Close)

	u, _ := url.ParseRequestURI(srv.URL)
	c, err := adminclient.New(adminclient.WithBaseURL(*u))
	if err != nil {
		t.Fatal(err)
	}
	return c, &body
}

func strPtr(s string) *string { return &s }

func TestCustomOAuthProviderCreateClientAuth(t *testing.T) {
	t.Run("default method is omitted", func(t *testing.T) {
		c, body := recordingServer(t, adminclient.CustomOAuthProviderResponse{
			Identifier: "custom:acme", ProviderType: "oidc", ClientAuthMethod: "client_secret",
		})
		r := resourceCustomOAuthProvider()
		cfg := terraform.NewResourceConfigRaw(with(baseOIDCConfig(), map[string]interface{}{"client_secret": "s"}))
		state, diags := r.Apply(context.Background(), nil, mustDiff(t, r, nil, cfg), c)
		if diags.HasError() {
			t.Fatalf("apply: %v", diags)
		}
		if _, ok := (*body)["client_auth_method"]; ok {
			t.Errorf("client_auth_method should be omitted for the default, got %v", (*body)["client_auth_method"])
		}
		if _, ok := (*body)["client_assertion_audience"]; ok {
			t.Errorf("client_assertion_audience should be omitted")
		}
		if (*body)["client_secret"] != "s" {
			t.Errorf("client_secret not sent")
		}
		if got := state.Attributes["client_auth_method"]; got != "client_secret" {
			t.Errorf("state client_auth_method = %q", got)
		}
	})

	t.Run("private_key_jwt with audience", func(t *testing.T) {
		c, body := recordingServer(t, adminclient.CustomOAuthProviderResponse{
			Identifier: "custom:acme", ProviderType: "oidc",
			ClientAuthMethod: "private_key_jwt", ClientAssertionAudience: strPtr("https://aud"),
		})
		r := resourceCustomOAuthProvider()
		cfg := terraform.NewResourceConfigRaw(with(baseOIDCConfig(), map[string]interface{}{
			"client_auth_method":        "private_key_jwt",
			"client_assertion_audience": "https://aud",
		}))
		state, diags := r.Apply(context.Background(), nil, mustDiff(t, r, nil, cfg), c)
		if diags.HasError() {
			t.Fatalf("apply: %v", diags)
		}
		if (*body)["client_auth_method"] != "private_key_jwt" {
			t.Errorf("client_auth_method = %v", (*body)["client_auth_method"])
		}
		if (*body)["client_assertion_audience"] != "https://aud" {
			t.Errorf("client_assertion_audience = %v", (*body)["client_assertion_audience"])
		}
		if _, ok := (*body)["client_secret"]; ok {
			t.Errorf("client_secret must not be sent")
		}
		if got := state.Attributes["client_assertion_audience"]; got != "https://aud" {
			t.Errorf("state client_assertion_audience = %q", got)
		}
	})
}

func TestCustomOAuthProviderUpdateClientAuth(t *testing.T) {
	pkjwtState := &terraform.InstanceState{
		ID: "custom:acme",
		Attributes: map[string]string{
			"id":                        "custom:acme",
			"provider_type":             "oidc",
			"identifier":                "custom:acme",
			"name":                      "Acme",
			"client_id":                 "cid",
			"issuer":                    "https://idp.example.com",
			"client_auth_method":        "private_key_jwt",
			"client_assertion_audience": "https://aud",
		},
	}
	secretState := &terraform.InstanceState{
		ID: "custom:acme",
		Attributes: with2(pkjwtState.Attributes, map[string]string{
			"client_auth_method":        "client_secret",
			"client_assertion_audience": "",
			"client_secret":             "old",
		}),
	}

	tests := []struct {
		name   string
		state  *terraform.InstanceState
		config map[string]interface{}
		want   map[string]interface{} // nil value means the key must be absent
	}{
		{
			name:  "switch to client_secret sends secret but no audience",
			state: pkjwtState,
			config: with(baseOIDCConfig(), map[string]interface{}{
				"client_secret": "new",
			}),
			want: map[string]interface{}{
				"client_auth_method":        "client_secret",
				"client_secret":             "new",
				"client_assertion_audience": nil,
			},
		},
		{
			name:  "switch to private_key_jwt sends no secret",
			state: secretState,
			config: with(baseOIDCConfig(), map[string]interface{}{
				"client_auth_method": "private_key_jwt",
			}),
			want: map[string]interface{}{
				"client_auth_method":        "private_key_jwt",
				"client_secret":             nil,
				"client_assertion_audience": nil,
			},
		},
		{
			name:  "removing audience sends empty string",
			state: pkjwtState,
			config: with(baseOIDCConfig(), map[string]interface{}{
				"client_auth_method": "private_key_jwt",
			}),
			want: map[string]interface{}{
				"client_auth_method":        nil,
				"client_assertion_audience": "",
			},
		},
		{
			name:  "changing audience",
			state: pkjwtState,
			config: with(baseOIDCConfig(), map[string]interface{}{
				"client_auth_method":        "private_key_jwt",
				"client_assertion_audience": "https://other",
			}),
			want: map[string]interface{}{
				"client_auth_method":        nil,
				"client_assertion_audience": "https://other",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c, body := recordingServer(t, adminclient.CustomOAuthProviderResponse{
				Identifier: "custom:acme", ProviderType: "oidc",
			})
			r := resourceCustomOAuthProvider()
			cfg := terraform.NewResourceConfigRaw(tt.config)
			if _, diags := r.Apply(context.Background(), tt.state, mustDiff(t, r, tt.state, cfg), c); diags.HasError() {
				t.Fatalf("apply: %v", diags)
			}
			for k, want := range tt.want {
				got, ok := (*body)[k]
				if want == nil {
					if ok {
						t.Errorf("%s should be absent, got %v", k, got)
					}
					continue
				}
				if got != want {
					t.Errorf("%s = %v, want %v", k, got, want)
				}
			}
		})
	}
}

func TestCustomOAuthProviderReadDefaultsMethod(t *testing.T) {
	// Servers that predate client_auth_method don't return it.
	c, _ := recordingServer(t, adminclient.CustomOAuthProviderResponse{
		Identifier: "custom:acme", ProviderType: "oidc",
	})
	r := resourceCustomOAuthProvider()
	state, diags := r.RefreshWithoutUpgrade(context.Background(), &terraform.InstanceState{
		ID: "custom:acme", Attributes: map[string]string{"id": "custom:acme"},
	}, c)
	if diags.HasError() {
		t.Fatalf("refresh: %v", diags)
	}
	if got := state.Attributes["client_auth_method"]; got != "client_secret" {
		t.Errorf("client_auth_method = %q, want client_secret", got)
	}
}

func mustDiff(t *testing.T, r interface {
	Diff(context.Context, *terraform.InstanceState, *terraform.ResourceConfig, interface{}) (*terraform.InstanceDiff, error)
}, state *terraform.InstanceState, cfg *terraform.ResourceConfig) *terraform.InstanceDiff {
	t.Helper()
	d, err := r.Diff(context.Background(), state, cfg, nil)
	if err != nil {
		t.Fatalf("diff: %v", err)
	}
	return d
}

func with2(base, kv map[string]string) map[string]string {
	out := map[string]string{}
	for k, v := range base {
		out[k] = v
	}
	for k, v := range kv {
		out[k] = v
	}
	return out
}
