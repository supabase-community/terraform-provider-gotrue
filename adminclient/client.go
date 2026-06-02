package adminclient

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type Client interface {
	GetIdentityProvider(ctx context.Context, id string) (*IdentityProviderResponse, error)
	CreateIdentityProvider(ctx context.Context, template *IdentityProviderRequest) (*IdentityProviderResponse, error)
	UpdateIdentityProvider(ctx context.Context, id string, template *IdentityProviderRequest) (*IdentityProviderResponse, error)
	DeleteIdentityProvider(ctx context.Context, id string) error

	GetCustomOAuthProvider(ctx context.Context, identifier string) (*CustomOAuthProviderResponse, error)
	CreateCustomOAuthProvider(ctx context.Context, req *CustomOAuthProviderRequest) (*CustomOAuthProviderResponse, error)
	UpdateCustomOAuthProvider(ctx context.Context, identifier string, req *CustomOAuthProviderRequest) (*CustomOAuthProviderResponse, error)
	DeleteCustomOAuthProvider(ctx context.Context, identifier string) error
}

type HTTPClient interface {
	Do(r *http.Request) (*http.Response, error)
}

type client struct {
	HTTPClient HTTPClient
	BaseURL    url.URL
	Headers    http.Header
}

type Option = func(*client)

func New(options ...Option) (Client, error) {
	c := &client{}

	for _, option := range options {
		option(c)
	}

	if c.HTTPClient == nil {
		c.HTTPClient = http.DefaultClient
	}

	if c.Headers == nil {
		c.Headers = make(http.Header)
	}

	return c, nil
}

func WithHTTPClient(httpClient HTTPClient) Option {
	return func(c *client) {
		c.HTTPClient = httpClient
	}
}

func WithBaseURL(url url.URL) Option {
	return func(c *client) {
		c.BaseURL = url
		c.BaseURL.Path = strings.TrimSuffix(c.BaseURL.Path, "/")
	}
}

func WithHeaders(headers http.Header) Option {
	return func(c *client) {
		c.Headers = headers.Clone()
	}
}

type Attribute struct {
	Name    string      `json:"name,omitempty"`
	Names   []string    `json:"names,omitempty"`
	Default interface{} `json:"default,omitempty"`
}

type AttributeMapping struct {
	Keys map[string]Attribute `json:"keys,omitempty"`
}

type IdentityProviderRequest struct {
	ID         string `json:"id,omitempty"`
	ResourceID string `json:"resource_id,omitempty"`

	Type string `json:"type,omitempty"`

	Domains          *[]string        `json:"domains,omitempty"`
	MetadataXML      string           `json:"metadata_xml,omitempty"`
	MetadataURL      string           `json:"metadata_url,omitempty"`
	AttributeMapping AttributeMapping `json:"attribute_mapping,omitempty"`

	CreatedAt time.Time `json:"created_at,omitempty"`
	UpdatedAt time.Time `json:"updated_at,omitempty"`
}

type IdentityProviderResponse struct {
	ID         string `json:"id,omitempty"`
	ResourceID string `json:"resource_id,omitempty"`

	Domains []Domain `json:"domains,omitempty"`

	SAML SAML `json:"saml,omitempty"`

	CreatedAt time.Time `json:"created_at,omitempty"`
	UpdatedAt time.Time `json:"updated_at,omitempty"`
}

type SAML struct {
	MetadataXML      string           `json:"metadata_xml"`
	MetadataURL      string           `json:"metadata_url"`
	AttributeMapping AttributeMapping `json:"attribute_mapping,omitempty"`
}

type Domain struct {
	Domain string `json:"domain,omitempty"`
}

func (c *client) GetIdentityProvider(ctx context.Context, id string) (*IdentityProviderResponse, error) {
	url := c.BaseURL
	url.Path += "/admin/sso/providers/" + id

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url.String(), nil)
	if err != nil {
		return nil, err
	}

	req.Header = c.Headers.Clone()

	res, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, err
	}

	defer res.Body.Close()

	if res.StatusCode != http.StatusOK {
		return nil, parseError(res, http.StatusOK, fmt.Sprintf("fetching identity provider with id %q", id))
	}

	provider := &IdentityProviderResponse{}

	if err := json.NewDecoder(res.Body).Decode(provider); err != nil {
		return nil, err
	}

	return provider, nil
}

func (c *client) CreateIdentityProvider(ctx context.Context, template *IdentityProviderRequest) (*IdentityProviderResponse, error) {
	url := c.BaseURL
	url.Path += "/admin/sso/providers"

	buffer := bytes.NewBuffer(make([]byte, 0))
	if err := json.NewEncoder(buffer).Encode(template); err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url.String(), buffer)
	if err != nil {
		return nil, err
	}

	req.Header = c.Headers.Clone()
	req.Header.Add("Content-Type", "application/json")

	res, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, err
	}

	defer res.Body.Close()

	if res.StatusCode != http.StatusCreated {
		return nil, parseError(res, http.StatusCreated, "creating new identity provider")
	}

	provider := &IdentityProviderResponse{}

	if err := json.NewDecoder(res.Body).Decode(provider); err != nil {
		return nil, err
	}

	return provider, nil
}

func (c *client) UpdateIdentityProvider(ctx context.Context, id string, template *IdentityProviderRequest) (*IdentityProviderResponse, error) {
	url := c.BaseURL
	url.Path += "/admin/sso/providers/" + id

	buffer := bytes.NewBuffer(make([]byte, 0))
	if err := json.NewEncoder(buffer).Encode(template); err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPut, url.String(), buffer)
	if err != nil {
		return nil, err
	}

	req.Header = c.Headers.Clone()
	req.Header.Add("Content-Type", "application/json")

	res, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, err
	}

	defer res.Body.Close()

	if res.StatusCode != http.StatusOK {
		return nil, parseError(res, http.StatusOK, fmt.Sprintf("updating identity provider with ID %q", id))
	}

	provider := &IdentityProviderResponse{}

	if err := json.NewDecoder(res.Body).Decode(provider); err != nil {
		return nil, err
	}

	return provider, nil
}

func (c *client) DeleteIdentityProvider(ctx context.Context, id string) error {
	url := c.BaseURL
	url.Path += "/admin/sso/providers/" + id

	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, url.String(), nil)
	if err != nil {
		return err
	}

	req.Header = c.Headers.Clone()

	res, err := c.HTTPClient.Do(req)
	if err != nil {
		return err
	}

	defer res.Body.Close()

	if res.StatusCode != http.StatusOK {
		return parseError(res, http.StatusOK, fmt.Sprintf("deleting identity provider with ID %q", id))
	}

	return nil
}

type CustomOAuthProviderRequest struct {
	ProviderType        string                 `json:"provider_type,omitempty"`
	Identifier          string                 `json:"identifier,omitempty"`
	Name                string                 `json:"name,omitempty"`
	ClientID            string                 `json:"client_id,omitempty"`
	ClientSecret        string                 `json:"client_secret,omitempty"`
	AcceptableClientIDs []string               `json:"acceptable_client_ids,omitempty"`
	Scopes              []string               `json:"scopes,omitempty"`
	PKCEEnabled         *bool                  `json:"pkce_enabled,omitempty"`
	AttributeMapping    map[string]interface{} `json:"attribute_mapping,omitempty"`
	AuthorizationParams map[string]interface{} `json:"authorization_params,omitempty"`
	Enabled             *bool                  `json:"enabled,omitempty"`
	EmailOptional       *bool                  `json:"email_optional,omitempty"`
	Issuer              string                 `json:"issuer,omitempty"`
	DiscoveryURL        *string                `json:"discovery_url,omitempty"`
	SkipNonceCheck      *bool                  `json:"skip_nonce_check,omitempty"`
	AuthorizationURL    string                 `json:"authorization_url,omitempty"`
	TokenURL            string                 `json:"token_url,omitempty"`
	UserinfoURL         string                 `json:"userinfo_url,omitempty"`
	JwksURI             *string                `json:"jwks_uri,omitempty"`
}

type CustomOAuthProviderResponse struct {
	ID                  string                 `json:"id,omitempty"`
	ProviderType        string                 `json:"provider_type,omitempty"`
	Identifier          string                 `json:"identifier,omitempty"`
	Name                string                 `json:"name,omitempty"`
	ClientID            string                 `json:"client_id,omitempty"`
	AcceptableClientIDs []string               `json:"acceptable_client_ids,omitempty"`
	Scopes              []string               `json:"scopes,omitempty"`
	PKCEEnabled         *bool                  `json:"pkce_enabled,omitempty"`
	AttributeMapping    map[string]interface{} `json:"attribute_mapping,omitempty"`
	AuthorizationParams map[string]interface{} `json:"authorization_params,omitempty"`
	Enabled             *bool                  `json:"enabled,omitempty"`
	EmailOptional       *bool                  `json:"email_optional,omitempty"`
	Issuer              string                 `json:"issuer,omitempty"`
	DiscoveryURL        *string                `json:"discovery_url,omitempty"`
	SkipNonceCheck      *bool                  `json:"skip_nonce_check,omitempty"`
	AuthorizationURL    string                 `json:"authorization_url,omitempty"`
	TokenURL            string                 `json:"token_url,omitempty"`
	UserinfoURL         string                 `json:"userinfo_url,omitempty"`
	JwksURI             *string                `json:"jwks_uri,omitempty"`
	DiscoveryDocument   json.RawMessage        `json:"discovery_document,omitempty"`
	CreatedAt           time.Time              `json:"created_at,omitempty"`
	UpdatedAt           time.Time              `json:"updated_at,omitempty"`
}

func (c *client) GetCustomOAuthProvider(ctx context.Context, identifier string) (*CustomOAuthProviderResponse, error) {
	rawURL := c.BaseURL.String() + "/admin/custom-providers/" + url.PathEscape(identifier)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, err
	}

	req.Header = c.Headers.Clone()

	res, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, err
	}

	defer res.Body.Close()

	if res.StatusCode != http.StatusOK {
		return nil, parseError(res, http.StatusOK, fmt.Sprintf("fetching custom OAuth provider with identifier %q", identifier))
	}

	provider := &CustomOAuthProviderResponse{}

	if err := json.NewDecoder(res.Body).Decode(provider); err != nil {
		return nil, err
	}

	return provider, nil
}

func (c *client) CreateCustomOAuthProvider(ctx context.Context, template *CustomOAuthProviderRequest) (*CustomOAuthProviderResponse, error) {
	url := c.BaseURL
	url.Path += "/admin/custom-providers"

	buffer := bytes.NewBuffer(make([]byte, 0))
	if err := json.NewEncoder(buffer).Encode(template); err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url.String(), buffer)
	if err != nil {
		return nil, err
	}

	req.Header = c.Headers.Clone()
	req.Header.Add("Content-Type", "application/json")

	res, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, err
	}

	defer res.Body.Close()

	if res.StatusCode != http.StatusCreated {
		return nil, parseError(res, http.StatusCreated, "creating new custom OAuth provider")
	}

	provider := &CustomOAuthProviderResponse{}

	if err := json.NewDecoder(res.Body).Decode(provider); err != nil {
		return nil, err
	}

	return provider, nil
}

func (c *client) UpdateCustomOAuthProvider(ctx context.Context, identifier string, template *CustomOAuthProviderRequest) (*CustomOAuthProviderResponse, error) {
	rawURL := c.BaseURL.String() + "/admin/custom-providers/" + url.PathEscape(identifier)

	buffer := bytes.NewBuffer(make([]byte, 0))
	if err := json.NewEncoder(buffer).Encode(template); err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPut, rawURL, buffer)
	if err != nil {
		return nil, err
	}

	req.Header = c.Headers.Clone()
	req.Header.Add("Content-Type", "application/json")

	res, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, err
	}

	defer res.Body.Close()

	if res.StatusCode != http.StatusOK {
		return nil, parseError(res, http.StatusOK, fmt.Sprintf("updating custom OAuth provider with identifier %q", identifier))
	}

	provider := &CustomOAuthProviderResponse{}

	if err := json.NewDecoder(res.Body).Decode(provider); err != nil {
		return nil, err
	}

	return provider, nil
}

func (c *client) DeleteCustomOAuthProvider(ctx context.Context, identifier string) error {
	rawURL := c.BaseURL.String() + "/admin/custom-providers/" + url.PathEscape(identifier)

	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, rawURL, nil)
	if err != nil {
		return err
	}

	req.Header = c.Headers.Clone()

	res, err := c.HTTPClient.Do(req)
	if err != nil {
		return err
	}

	defer res.Body.Close()

	if res.StatusCode != http.StatusOK {
		return parseError(res, http.StatusOK, fmt.Sprintf("deleting custom OAuth provider with identifier %q", identifier))
	}

	return nil
}

type Error struct {
	Op       string `json:"-"`
	Expected int    `json:"-"`

	Code    int    `json:"code,omitempty"`
	Message string `json:"msg,omitempty"`
	ErrorID string `json:"error_id,omitempty"`
}

func (e *Error) Error() string {
	return fmt.Sprintf("adminclient: expected HTTP %v when %s, got HTTP %v: %s", e.Expected, e.Op, e.Code, e.Message)
}

func parseError(res *http.Response, expected int, op string) error {
	body, err := io.ReadAll(res.Body)
	if err != nil {
		return err
	}

	var errorObject Error
	errorObject.Op = op
	errorObject.Expected = expected
	errorObject.Code = res.StatusCode

	if err := json.Unmarshal(body, &errorObject); err != nil {
		errorObject.Message = string(body)
	}

	return &errorObject
}
