package gotrue

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"time"

	"github.com/hashicorp/go-cty/cty"
	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"

	"github.com/supabase-community/terraform-provider-gotrue/adminclient"
)

func resourceIdentityProviderSet(provider *adminclient.IdentityProviderResponse, d *schema.ResourceData) diag.Diagnostics {
	d.SetId(provider.ID)

	if provider.SAML.MetadataURL != "" {
		if err := d.Set("metadata_url", provider.SAML.MetadataURL); err != nil {
			return diag.FromErr(err)
		}
	} else if provider.SAML.MetadataXML != "" {
		if err := d.Set("metadata_xml", provider.SAML.MetadataXML); err != nil {
			return diag.FromErr(err)
		}
	}

	if err := d.Set("created_at", provider.CreatedAt.UTC().Format(time.RFC3339)); err != nil {
		return diag.FromErr(err)
	}

	if err := d.Set("updated_at", provider.UpdatedAt.UTC().Format(time.RFC3339)); err != nil {
		return diag.FromErr(err)
	}

	var domains []string

	for _, domain := range provider.Domains {
		domains = append(domains, domain.Domain)
	}

	sort.Strings(domains)

	domainsSet := schema.NewSet(schema.HashString, nil)
	for _, domain := range domains {
		domainsSet.Add(domain)
	}

	if err := d.Set("domains", domainsSet); err != nil {
		return diag.FromErr(err)
	}

	keys, err := json.Marshal(provider.SAML.AttributeMapping)
	if err != nil {
		return diag.FromErr(err)
	}

	if err := d.Set("attribute_mapping", string(keys)); err != nil {
		return diag.FromErr(err)
	}

	return nil
}

func resourceIdentityProviderRead(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	client := m.(adminclient.Client)

	provider, err := client.GetIdentityProvider(ctx, d.Id())
	if err != nil {
		return diag.FromErr(err)
	}

	return resourceIdentityProviderSet(provider, d)
}

func resourceIdentityProviderUpdate(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	client := m.(adminclient.Client)

	template := &adminclient.IdentityProviderRequest{}

	if d.HasChange("metadata_url") {
		template.MetadataURL = d.Get("metadata_url").(string)
	} else if d.HasChange("metadata_xml") {
		template.MetadataXML = d.Get("metadata_xml").(string)
	}

	if d.HasChange("domains") {
		domains := make([]string, 0, 10)

		for _, domain := range d.Get("domains").(*schema.Set).List() {
			domains = append(domains, domain.(string))
		}

		template.Domains = &domains
	}

	if d.HasChange("attribute_mapping") {
		if keys, ok := d.GetOk("attribute_mapping"); ok && keys.(string) != "" {
			if err := json.Unmarshal([]byte(keys.(string)), &template.AttributeMapping); err != nil {
				return diag.FromErr(err)
			}
		}
	}

	provider, err := client.UpdateIdentityProvider(ctx, d.Id(), template)
	if err != nil {
		return diag.FromErr(err)
	}

	return resourceIdentityProviderSet(provider, d)
}

func resourceIdentityProviderDelete(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	client := m.(adminclient.Client)

	if err := client.DeleteIdentityProvider(ctx, d.Id()); err != nil {
		return diag.FromErr(err)
	}

	d.SetId("")

	return nil
}

func resourceIdentityProviderCreate(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	client := m.(adminclient.Client)

	template := &adminclient.IdentityProviderRequest{
		Type: "saml",
	}

	if metadataURL, ok := d.GetOk("metadata_url"); ok && metadataURL.(string) != "" {
		template.MetadataURL = metadataURL.(string)
	} else if metadataXML, ok := d.GetOk("metadata_xml"); ok && metadataXML.(string) != "" {
		template.MetadataXML = metadataXML.(string)
	}

	if domainsSet, ok := d.GetOk("domains"); ok {
		var domains []string

		for _, domain := range domainsSet.(*schema.Set).List() {
			domains = append(domains, domain.(string))
		}

		template.Domains = &domains
	}

	if keys, ok := d.GetOk("attribute_mapping"); ok && keys.(string) != "" {
		if err := json.Unmarshal([]byte(keys.(string)), &template.AttributeMapping); err != nil {
			return diag.FromErr(err)
		}
	}

	provider, err := client.CreateIdentityProvider(ctx, template)
	if err != nil {
		return diag.FromErr(err)
	}

	return resourceIdentityProviderSet(provider, d)
}

var (
	domainPattern      = regexp.MustCompile("^[a-z0-9-]+(.[a-z0-9-]+)*$")
	customIdentPattern = regexp.MustCompile("^custom:")
)

func resourceCustomOAuthProviderSet(provider *adminclient.CustomOAuthProviderResponse, d *schema.ResourceData) diag.Diagnostics {
	d.SetId(provider.Identifier)

	discoveryURL := ""
	if provider.DiscoveryURL != nil {
		discoveryURL = *provider.DiscoveryURL
	}

	jwksURI := ""
	if provider.JwksURI != nil {
		jwksURI = *provider.JwksURI
	}

	pkceEnabled := false
	if provider.PKCEEnabled != nil {
		pkceEnabled = *provider.PKCEEnabled
	}

	enabled := false
	if provider.Enabled != nil {
		enabled = *provider.Enabled
	}

	emailOptional := false
	if provider.EmailOptional != nil {
		emailOptional = *provider.EmailOptional
	}

	skipNonceCheck := false
	if provider.SkipNonceCheck != nil {
		skipNonceCheck = *provider.SkipNonceCheck
	}

	fields := map[string]interface{}{
		"provider_type":     provider.ProviderType,
		"identifier":        provider.Identifier,
		"name":              provider.Name,
		"client_id":         provider.ClientID,
		"issuer":            provider.Issuer,
		"discovery_url":     discoveryURL,
		"authorization_url": provider.AuthorizationURL,
		"token_url":         provider.TokenURL,
		"userinfo_url":      provider.UserinfoURL,
		"jwks_uri":          jwksURI,
		"pkce_enabled":      pkceEnabled,
		"enabled":           enabled,
		"email_optional":    emailOptional,
		"skip_nonce_check":  skipNonceCheck,
	}

	for k, v := range fields {
		if err := d.Set(k, v); err != nil {
			return diag.FromErr(err)
		}
	}

	if err := d.Set("scopes", provider.Scopes); err != nil {
		return diag.FromErr(err)
	}

	if err := d.Set("acceptable_client_ids", provider.AcceptableClientIDs); err != nil {
		return diag.FromErr(err)
	}

	authorizationParams := ""
	if len(provider.AuthorizationParams) > 0 {
		raw, err := json.Marshal(provider.AuthorizationParams)
		if err != nil {
			return diag.FromErr(err)
		}
		authorizationParams = string(raw)
	}
	if err := d.Set("authorization_params", authorizationParams); err != nil {
		return diag.FromErr(err)
	}

	discoveryDocument := ""
	if len(provider.DiscoveryDocument) > 0 {
		discoveryDocument = string(provider.DiscoveryDocument)
	}
	if err := d.Set("discovery_document", discoveryDocument); err != nil {
		return diag.FromErr(err)
	}

	return nil
}

func resourceCustomOAuthProviderRead(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	client := m.(adminclient.Client)

	provider, err := client.GetCustomOAuthProvider(ctx, d.Id())
	if err != nil {
		return diag.FromErr(err)
	}

	return resourceCustomOAuthProviderSet(provider, d)
}

func resourceCustomOAuthProviderCreate(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	client := m.(adminclient.Client)

	template := &adminclient.CustomOAuthProviderRequest{
		ProviderType: d.Get("provider_type").(string),
		Identifier:   d.Get("identifier").(string),
		Name:         d.Get("name").(string),
		ClientID:     d.Get("client_id").(string),
		ClientSecret: d.Get("client_secret").(string),
	}

	if v, ok := d.GetOk("issuer"); ok {
		template.Issuer = v.(string)
	}
	if v, ok := d.GetOk("discovery_url"); ok {
		s := v.(string)
		template.DiscoveryURL = &s
	}
	if v, ok := d.GetOk("authorization_url"); ok {
		template.AuthorizationURL = v.(string)
	}
	if v, ok := d.GetOk("token_url"); ok {
		template.TokenURL = v.(string)
	}
	if v, ok := d.GetOk("userinfo_url"); ok {
		template.UserinfoURL = v.(string)
	}
	if v, ok := d.GetOk("jwks_uri"); ok {
		s := v.(string)
		template.JwksURI = &s
	}
	b := d.Get("pkce_enabled").(bool)
	template.PKCEEnabled = &b

	b = d.Get("enabled").(bool)
	template.Enabled = &b

	b = d.Get("email_optional").(bool)
	template.EmailOptional = &b

	b = d.Get("skip_nonce_check").(bool)
	template.SkipNonceCheck = &b

	if v, ok := d.GetOk("scopes"); ok {
		raw := v.([]interface{})
		scopes := make([]string, len(raw))
		for i, s := range raw {
			scopes[i] = s.(string)
		}
		template.Scopes = scopes
	}

	if v, ok := d.GetOk("acceptable_client_ids"); ok {
		raw := v.([]interface{})
		ids := make([]string, len(raw))
		for i, s := range raw {
			ids[i] = s.(string)
		}
		template.AcceptableClientIDs = ids
	}

	if v, ok := d.GetOk("authorization_params"); ok && v.(string) != "" {
		var params map[string]interface{}
		if err := json.Unmarshal([]byte(v.(string)), &params); err != nil {
			return diag.FromErr(err)
		}
		template.AuthorizationParams = params
	}

	provider, err := client.CreateCustomOAuthProvider(ctx, template)
	if err != nil {
		return diag.FromErr(err)
	}

	return resourceCustomOAuthProviderSet(provider, d)
}

func resourceCustomOAuthProviderUpdate(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	client := m.(adminclient.Client)

	template := &adminclient.CustomOAuthProviderRequest{}

	if d.HasChange("name") {
		template.Name = d.Get("name").(string)
	}
	if d.HasChange("client_id") {
		template.ClientID = d.Get("client_id").(string)
	}
	if d.HasChange("client_secret") {
		if v := d.Get("client_secret").(string); v != "" {
			template.ClientSecret = v
		}
	}
	if d.HasChange("issuer") {
		template.Issuer = d.Get("issuer").(string)
	}
	if d.HasChange("discovery_url") {
		s := d.Get("discovery_url").(string)
		template.DiscoveryURL = &s
	}
	if d.HasChange("authorization_url") {
		template.AuthorizationURL = d.Get("authorization_url").(string)
	}
	if d.HasChange("token_url") {
		template.TokenURL = d.Get("token_url").(string)
	}
	if d.HasChange("userinfo_url") {
		template.UserinfoURL = d.Get("userinfo_url").(string)
	}
	if d.HasChange("jwks_uri") {
		s := d.Get("jwks_uri").(string)
		template.JwksURI = &s
	}
	if d.HasChange("pkce_enabled") {
		b := d.Get("pkce_enabled").(bool)
		template.PKCEEnabled = &b
	}
	if d.HasChange("enabled") {
		b := d.Get("enabled").(bool)
		template.Enabled = &b
	}
	if d.HasChange("email_optional") {
		b := d.Get("email_optional").(bool)
		template.EmailOptional = &b
	}
	if d.HasChange("skip_nonce_check") {
		b := d.Get("skip_nonce_check").(bool)
		template.SkipNonceCheck = &b
	}
	if d.HasChange("scopes") {
		raw := d.Get("scopes").([]interface{})
		scopes := make([]string, len(raw))
		for i, s := range raw {
			scopes[i] = s.(string)
		}
		template.Scopes = scopes
	}
	if d.HasChange("acceptable_client_ids") {
		raw := d.Get("acceptable_client_ids").([]interface{})
		ids := make([]string, len(raw))
		for i, s := range raw {
			ids[i] = s.(string)
		}
		template.AcceptableClientIDs = ids
	}
	if d.HasChange("authorization_params") {
		if v, ok := d.GetOk("authorization_params"); ok && v.(string) != "" {
			var params map[string]interface{}
			if err := json.Unmarshal([]byte(v.(string)), &params); err != nil {
				return diag.FromErr(err)
			}
			template.AuthorizationParams = params
		}
	}

	provider, err := client.UpdateCustomOAuthProvider(ctx, d.Id(), template)
	if err != nil {
		return diag.FromErr(err)
	}

	return resourceCustomOAuthProviderSet(provider, d)
}

func resourceCustomOAuthProviderDelete(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	client := m.(adminclient.Client)

	if err := client.DeleteCustomOAuthProvider(ctx, d.Id()); err != nil {
		return diag.FromErr(err)
	}

	d.SetId("")

	return nil
}

func resourceCustomOAuthProvider() *schema.Resource {
	validateJSON := func(value interface{}, path cty.Path) diag.Diagnostics {
		var diags diag.Diagnostics
		var out map[string]interface{}
		if err := json.Unmarshal([]byte(value.(string)), &out); err != nil {
			diags = append(diags, diag.Diagnostic{
				Severity: diag.Error,
				Summary:  "Value must be valid JSON",
				Detail:   fmt.Sprintf("JSON parsing failed: %v", err.Error()),
			})
		}
		return diags
	}

	return &schema.Resource{
		CreateContext: resourceCustomOAuthProviderCreate,
		ReadContext:   resourceCustomOAuthProviderRead,
		UpdateContext: resourceCustomOAuthProviderUpdate,
		DeleteContext: resourceCustomOAuthProviderDelete,
		Importer: &schema.ResourceImporter{
			StateContext: schema.ImportStatePassthroughContext,
		},
		Schema: map[string]*schema.Schema{
			"provider_type": {
				Type:     schema.TypeString,
				Required: true,
				ForceNew: true,
				ValidateDiagFunc: func(value interface{}, path cty.Path) diag.Diagnostics {
					var diags diag.Diagnostics
					v := value.(string)
					if v != "oauth2" && v != "oidc" {
						diags = append(diags, diag.Diagnostic{
							Severity: diag.Error,
							Summary:  fmt.Sprintf("provider_type must be \"oauth2\" or \"oidc\", got %q", v),
						})
					}
					return diags
				},
			},
			"identifier": {
				Type:     schema.TypeString,
				Required: true,
				ForceNew: true,
				ValidateDiagFunc: func(value interface{}, path cty.Path) diag.Diagnostics {
					var diags diag.Diagnostics
					if !customIdentPattern.MatchString(value.(string)) {
						diags = append(diags, diag.Diagnostic{
							Severity: diag.Error,
							Summary:  fmt.Sprintf("identifier must start with \"custom:\", got %q", value.(string)),
						})
					}
					return diags
				},
			},
			"name": {
				Type:     schema.TypeString,
				Required: true,
			},
			"client_id": {
				Type:     schema.TypeString,
				Required: true,
			},
			"client_secret": {
				Type:      schema.TypeString,
				Required:  true,
				Sensitive: true,
			},
			"acceptable_client_ids": {
				Type:     schema.TypeList,
				Optional: true,
				Elem:     &schema.Schema{Type: schema.TypeString},
			},
			"scopes": {
				Type:     schema.TypeList,
				Optional: true,
				Computed: true,
				Elem:     &schema.Schema{Type: schema.TypeString},
			},
			"pkce_enabled": {
				Type:     schema.TypeBool,
				Optional: true,
				Computed: true,
			},
			"authorization_params": {
				Type:             schema.TypeString,
				Optional:         true,
				ValidateDiagFunc: validateJSON,
			},
			"enabled": {
				Type:     schema.TypeBool,
				Optional: true,
				Computed: true,
			},
			"email_optional": {
				Type:     schema.TypeBool,
				Optional: true,
				Computed: true,
			},
			"issuer": {
				Type:     schema.TypeString,
				Optional: true,
			},
			"discovery_url": {
				Type:     schema.TypeString,
				Optional: true,
			},
			"skip_nonce_check": {
				Type:     schema.TypeBool,
				Optional: true,
				Computed: true,
			},
			"authorization_url": {
				Type:     schema.TypeString,
				Optional: true,
			},
			"token_url": {
				Type:     schema.TypeString,
				Optional: true,
			},
			"userinfo_url": {
				Type:     schema.TypeString,
				Optional: true,
			},
			"jwks_uri": {
				Type:     schema.TypeString,
				Optional: true,
			},
			"id": {
				Type:     schema.TypeString,
				Computed: true,
			},
			"discovery_document": {
				Type:     schema.TypeString,
				Computed: true,
			},
		},
	}
}

func resourceIdentityProvider() *schema.Resource {
	return &schema.Resource{
		CreateContext: resourceIdentityProviderCreate,
		ReadContext:   resourceIdentityProviderRead,
		UpdateContext: resourceIdentityProviderUpdate,
		DeleteContext: resourceIdentityProviderDelete,
		Schema: map[string]*schema.Schema{
			"domains": {
				Type:     schema.TypeSet,
				Optional: true,
				Elem: &schema.Schema{
					Type: schema.TypeString,
					ValidateDiagFunc: func(value interface{}, path cty.Path) diag.Diagnostics {
						var diags diag.Diagnostics

						if !domainPattern.MatchString(value.(string)) {
							diags = append(diags, diag.Diagnostic{
								Severity: diag.Error,
								Summary:  fmt.Sprintf("Value %q is not a valid domain", value.(string)),
							})
						}

						return diags
					},
				},
			},
			"metadata_url": {
				Type:     schema.TypeString,
				Optional: true,
			},
			"metadata_xml": {
				Type:     schema.TypeString,
				Optional: true,
			},
			"attribute_mapping": {
				Type:     schema.TypeString,
				Optional: true,
				ValidateDiagFunc: func(value interface{}, path cty.Path) diag.Diagnostics {
					var diags diag.Diagnostics

					var mapping adminclient.AttributeMapping

					if err := json.Unmarshal([]byte(value.(string)), &mapping); err != nil {
						diags = append(diags, diag.Diagnostic{
							Severity: diag.Error,
							Summary:  "attribute_mapping must be valid JSON",
							Detail:   fmt.Sprintf("JSON parsing failed: %v", err.Error()),
						})

						return diags
					}

					for key, value := range mapping.Keys {
						if value.Name == "" && len(value.Names) == 0 && value.Default == nil {
							diags = append(diags, diag.Diagnostic{
								Severity: diag.Error,
								Summary:  fmt.Sprintf("Attribute mapping key %q must have at least one property set: name, names or default", key),
							})
						} else if len(value.Names) > 0 {
							for i, name := range value.Names {
								if name == "" {
									diags = append(diags, diag.Diagnostic{
										Severity: diag.Error,
										Summary:  fmt.Sprintf("Attribute mapping name under %q.names at position %v is empty", key, i),
									})
								}
							}
						}
					}

					return diags
				},
			},
			"created_at": {
				Type:     schema.TypeString,
				Computed: true,
			},
			"updated_at": {
				Type:     schema.TypeString,
				Computed: true,
			},
		},
	}
}

func Provider() *schema.Provider {
	provider := &schema.Provider{
		Schema: map[string]*schema.Schema{
			"url": {
				Type:        schema.TypeString,
				Required:    true,
				DefaultFunc: schema.EnvDefaultFunc("GOTRUE_URL", nil),
				ValidateDiagFunc: func(value interface{}, path cty.Path) diag.Diagnostics {
					var diags diag.Diagnostics

					rawURL := value.(string)

					if rawURL == "" {
						diags = append(diags, diag.Diagnostic{
							Severity: diag.Error,
							Summary:  "GoTrue URL is empty",
						})

						return diags
					}

					parsedURL, err := url.ParseRequestURI(rawURL)
					if err != nil {
						diags = append(diags, diag.Diagnostic{
							Severity: diag.Error,
							Summary:  "GoTrue URL is not valid",
							Detail:   fmt.Sprintf("Unable to parse URL: %s", err.Error()),
						})
					}

					if parsedURL.Scheme != "http" && parsedURL.Scheme != "https" {
						diags = append(diags, diag.Diagnostic{
							Severity: diag.Error,
							Summary:  fmt.Sprintf("GoTrue URL is not HTTP(S): %q", parsedURL.Scheme),
						})
					}

					islocalhost, err := regexp.MatchString("^(localhost|127(.[0-9]{1,3}){3})(:[0-9]+)?$", parsedURL.Host)
					if err != nil {
						panic(err)
					}

					if !islocalhost {
						if parsedURL.Scheme == "http" {
							diags = append(diags, diag.Diagnostic{
								Severity: diag.Warning,
								Summary:  "GoTrue URL does not use HTTPS",
								Detail:   "Communication with GoTrue should occur over HTTPS whenever possible",
							})
						}
					}

					return diags
				},
			},
			"headers": {
				Type:     schema.TypeMap,
				Optional: true,
				Elem: &schema.Schema{
					Type:      schema.TypeString,
					Required:  true,
					Sensitive: true,
				},
				//DefaultFunc: schema.EnvDefaultFunc("GOTRUE_HEADERS", nil),
			},
		},
		ResourcesMap: map[string]*schema.Resource{
			"gotrue_saml_identity_provider": resourceIdentityProvider(),
			"gotrue_custom_oauth_provider":  resourceCustomOAuthProvider(),
		},
	}

	provider.ConfigureContextFunc = func(ctx context.Context, d *schema.ResourceData) (interface{}, diag.Diagnostics) {
		return providerConfigure(ctx, d, provider)
	}

	return provider
}

func providerConfigure(ctx context.Context, d *schema.ResourceData, provider *schema.Provider) (interface{}, diag.Diagnostics) {
	var diags diag.Diagnostics

	parsedURL, err := url.ParseRequestURI(d.Get("url").(string))
	if err != nil {
		// validation should have caught this
		panic(err)
	}

	headers := make(http.Header)

	for h, v := range d.Get("headers").(map[string]interface{}) {
		headers.Add(h, v.(string))
	}

	headers.Add("User-Agent", provider.UserAgent("terraform-provider-gotrue", Version))

	if headers.Get("Authorization") == "" {
		diags = append(diags, diag.Diagnostic{
			Severity: diag.Warning,
			Summary:  "No Authorization header, requests may fail",
			Detail:   "There was no Authorization header configured, requests may fail (depending on setup)",
		})
	}

	var client adminclient.Client

	if parsedURL != nil {
		client, err = adminclient.New(
			adminclient.WithBaseURL(*parsedURL),
			adminclient.WithHeaders(headers),
		)

		if err != nil {
			diags = append(diags, diag.Diagnostic{
				Severity: diag.Error,
				Summary:  "Unable to create GoTrue Admin client",
				Detail:   "Unhandled error: " + err.Error(),
			})

			return nil, diags
		}
	}

	return client, diags
}
