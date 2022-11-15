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
		for _, domain := range d.Get("domains").(*schema.Set).List() {
			template.Domains = append(template.Domains, domain.(string))
		}
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

		template.Domains = domains
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
	domainPattern = regexp.MustCompile("^[a-z0-9-]+(.[a-z0-9-]+)*$")
)

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
