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
