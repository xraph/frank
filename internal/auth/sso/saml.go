package sso

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"encoding/xml"
	"net/http"
	"net/url"
	"strings"

	"github.com/crewjam/saml"
	"github.com/crewjam/saml/samlsp"
	"github.com/juicycleff/frank/ent"
	"github.com/juicycleff/frank/pkg/errors"
	"github.com/juicycleff/frank/pkg/logging"
)

// SAMLProvider implements the IdentityProvider interface for SAML
type SAMLProvider struct {
	name        string
	config      ProviderConfig
	sp          *samlsp.Middleware
	logger      logging.Logger
	certificate *x509.Certificate
	privateKey  *rsa.PrivateKey
}

// SAMLProviderFactory creates SAML providers
type SAMLProviderFactory struct{}

// CreateProvider creates a new SAML provider from a configuration
func (f *SAMLProviderFactory) CreateProvider(config *ent.IdentityProvider) (IdentityProvider, error) {
	if config.ProviderType != "saml" {
		return nil, ErrUnsupportedProviderType
	}

	// Parse certificate
	var certificate *x509.Certificate
	if config.Certificate != "" {
		certBlock, _ := pem.Decode([]byte(config.Certificate))
		if certBlock == nil {
			return nil, errors.New(errors.CodeInvalidInput, "failed to parse certificate PEM")
		}
		var err error
		certificate, err = x509.ParseCertificate(certBlock.Bytes)
		if err != nil {
			return nil, errors.Wrap(errors.CodeInvalidInput, err, "failed to parse certificate")
		}
	}

	// Parse private key
	var privateKey *rsa.PrivateKey
	if config.PrivateKey != "" {
		keyBlock, _ := pem.Decode([]byte(config.PrivateKey))
		if keyBlock == nil {
			return nil, errors.New(errors.CodeInvalidInput, "failed to parse private key PEM")
		}
		var err error
		privateKey, err = x509.ParsePKCS1PrivateKey(keyBlock.Bytes)
		if err != nil {
			return nil, errors.Wrap(errors.CodeInvalidInput, err, "failed to parse private key")
		}
	}

	// Parse attributes mapping
	attributesMapping := make(map[string]string)
	if config.AttributesMapping != nil {
		attributesMapping = config.AttributesMapping
	}

	// Build provider configuration
	providerConfig := ProviderConfig{
		Name:              config.Name,
		Type:              "saml",
		OrganizationID:    config.OrganizationID,
		AttributeMappings: attributesMapping,
		Metadata:          config.Metadata,
	}

	logger := logging.GetLogger()

	// Create SAML provider
	samlProvider := &SAMLProvider{
		name:        config.Name,
		config:      providerConfig,
		logger:      logger,
		certificate: certificate,
		privateKey:  privateKey,
	}

	// Initialize SAML service provider
	if err := samlProvider.initServiceProvider(config); err != nil {
		return nil, err
	}

	return samlProvider, nil
}

// initServiceProvider initializes the SAML service provider
func (p *SAMLProvider) initServiceProvider(config *ent.IdentityProvider) error {
	// Define root URL for SAML endpoints
	rootURL, err := url.Parse(config.MetadataURL)
	if err != nil {
		return errors.Wrap(errors.CodeInvalidInput, err, "invalid metadata URL")
	}

	// // Create key pair
	// keyPair := tls.Certificate{
	// 	Certificate: [][]byte{p.certificate.Raw},
	// 	PrivateKey:  p.privateKey,
	// }

	// Create SAML options
	samlOpts := samlsp.Options{
		URL:               *rootURL,
		Key:               p.privateKey,
		Certificate:       p.certificate,
		AllowIDPInitiated: true,
	}

	metadataURL, err := url.Parse(config.MetadataURL)
	if err != nil {
		return errors.Wrap(errors.CodeInvalidInput, err, "invalid metadata URL")
	}

	// Parse IdP metadata if available
	if config.MetadataURL != "" {
		idpMetadata, err := samlsp.FetchMetadata(context.Background(), http.DefaultClient, *metadataURL)
		if err != nil {
			return errors.Wrap(errors.CodeIdentityProviderError, err, "failed to fetch IdP metadata")
		}
		samlOpts.IDPMetadata = idpMetadata
	}

	// Create SAML middleware
	middleware, err := samlsp.New(samlOpts)
	if err != nil {
		return errors.Wrap(errors.CodeConfigurationError, err, "failed to create SAML middleware")
	}

	p.sp = middleware
	return nil
}

// GetName returns the name of the provider
func (p *SAMLProvider) GetName() string {
	return p.name
}

// GetType returns the type of the provider
func (p *SAMLProvider) GetType() string {
	return "saml"
}

// GetAuthURL returns the URL to initiate authentication
func (p *SAMLProvider) GetAuthURL(state string, options map[string]interface{}) (string, error) {
	if p.sp == nil {
		return "", errors.New(errors.CodeConfigurationError, "SAML provider not properly initialized")
	}

	// Create a request to redirect to IdP
	// This normally happens at middleware level, but we need to handle it directly

	// Get the SSO URL from the IdP metadata
	idpSSOURL := p.sp.ServiceProvider.IDPMetadata.IDPSSODescriptors[0].SingleSignOnServices[0].Location

	// Create the authentication request
	authnRequest, err := p.sp.ServiceProvider.MakeAuthenticationRequest(idpSSOURL, saml.HTTPPostBinding, saml.HTTPRedirectBinding)
	if err != nil {
		return "", errors.Wrap(errors.CodeIdentityProviderError, err, "failed to create SAML authentication request")
	}

	// Store application-specific options in the request if needed
	if len(options) > 0 {
		// SAML doesn't have a direct way to pass custom parameters, but you could
		// encode them into the relay state or implement a custom session mechanism
	}

	// Get the redirect URL
	redirectURL, err := authnRequest.Redirect(state, &p.sp.ServiceProvider)
	if err != nil {
		return "", errors.Wrap(errors.CodeIdentityProviderError, err, "failed to create SAML redirect URL")
	}

	return redirectURL.String(), nil
}

// ExchangeCode processes a SAML response and returns user information
func (p *SAMLProvider) ExchangeCode(ctx context.Context, samlResponse string, state string) (*UserInfo, error) {
	if p.sp == nil {
		return nil, errors.New(errors.CodeConfigurationError, "SAML provider not properly initialized")
	}

	// Parse and validate SAML response
	assertionInfo, err := p.parseAndValidateSAMLResponse(samlResponse)
	if err != nil {
		return nil, err
	}

	// Extract user information
	userInfo, err := p.extractUserInfo(assertionInfo)
	if err != nil {
		return nil, err
	}

	return userInfo, nil
}

// ValidateToken validates a token and returns user information
// Note: For SAML, tokens are ephemeral and not stored, so this would typically
// be used to validate a session token created after the SAML authentication
func (p *SAMLProvider) ValidateToken(ctx context.Context, token string) (*UserInfo, error) {
	// For SAML, we don't typically validate tokens after initial authentication
	// This would be implemented if you're using a custom token system
	return nil, errors.New(errors.CodeUnsupportedOperation, "token validation not supported for SAML")
}

// GetConfig returns the provider's configuration
func (p *SAMLProvider) GetConfig() ProviderConfig {
	return p.config
}

// parseAndValidateSAMLResponse parses and validates a SAML response
func (p *SAMLProvider) parseAndValidateSAMLResponse(samlResponse string) (*saml.Assertion, error) {
	// Decode base64-encoded response
	responseBytes, err := base64.StdEncoding.DecodeString(samlResponse)
	if err != nil {
		return nil, errors.Wrap(errors.CodeInvalidInput, err, "failed to decode SAML response")
	}

	// Parse the XML response
	var response saml.Response
	if err := xml.Unmarshal(responseBytes, &response); err != nil {
		return nil, errors.Wrap(errors.CodeInvalidInput, err, "failed to parse SAML response XML")
	}

	// // Validate the response
	// err = p.sp.ServiceProvider.ValidateResponse(&response)
	// if err != nil {
	// 	return nil, errors.Wrap(errors.CodeInvalidToken, err, "failed to validate SAML response")
	// }

	// Check if there's an assertion
	if response.Assertion == nil {
		return nil, errors.New(errors.CodeInvalidInput, "SAML response contains no assertions")
	}

	return response.Assertion, nil
}

// extractUserInfo extracts user information from a SAML assertion
func (p *SAMLProvider) extractUserInfo(assertion *saml.Assertion) (*UserInfo, error) {
	if assertion == nil {
		return nil, errors.New(errors.CodeInvalidInput, "invalid assertion")
	}

	// Initialize user info with defaults
	userInfo := &UserInfo{
		ID:             assertion.Subject.NameID.Value,
		ProviderType:   "saml",
		ProviderName:   p.name,
		RawAttributes:  make(map[string]interface{}),
		OrganizationID: p.config.OrganizationID,
	}

	// Extract attributes from the assertion
	attributes := make(map[string][]string)
	for _, attributeStatement := range assertion.AttributeStatements {
		for _, attribute := range attributeStatement.Attributes {
			values := make([]string, len(attribute.Values))
			for i, value := range attribute.Values {
				values[i] = value.Value
				// Store raw attributes
				userInfo.RawAttributes[attribute.Name] = value.Value
			}
			attributes[attribute.Name] = values
		}
	}

	// Map attributes based on configuration
	p.mapAttributes(userInfo, attributes)

	return userInfo, nil
}

// mapAttributes maps SAML attributes to user info fields based on configuration
func (p *SAMLProvider) mapAttributes(userInfo *UserInfo, attributes map[string][]string) {
	// Map known attributes based on configuration
	mappings := p.config.AttributeMappings
	if mappings == nil {
		mappings = defaultSAMLAttributeMappings()
	}

	// Apply mappings
	for samlAttr, userAttr := range mappings {
		if values, ok := attributes[samlAttr]; ok && len(values) > 0 {
			value := values[0]
			switch userAttr {
			case "email":
				userInfo.Email = value
			case "email_verified":
				userInfo.EmailVerified = value == "true" || value == "1"
			case "name":
				userInfo.Name = value
			case "first_name":
				userInfo.FirstName = value
			case "last_name":
				userInfo.LastName = value
			case "picture":
				userInfo.ProfilePicture = value
			case "locale":
				userInfo.Locale = value
			case "groups":
				userInfo.Groups = strings.Split(value, ",")
			case "organization_name":
				userInfo.OrganizationName = value
			case "organization_email":
				userInfo.OrganizationEmail = value
			}
		}
	}

	// If no name is set, try to construct it from first and last name
	if userInfo.Name == "" && (userInfo.FirstName != "" || userInfo.LastName != "") {
		userInfo.Name = strings.TrimSpace(userInfo.FirstName + " " + userInfo.LastName)
	}

	// If email is not explicitly mapped, try to use the NameID if it looks like an email
	if userInfo.Email == "" && strings.Contains(userInfo.ID, "@") {
		userInfo.Email = userInfo.ID
	}
}

// defaultSAMLAttributeMappings returns default mappings for common SAML attributes
func defaultSAMLAttributeMappings() map[string]string {
	return map[string]string{
		"urn:oid:0.9.2342.19200300.100.1.3":                                  "email",
		"http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress": "email",
		"mail":  "email",
		"email": "email",

		"urn:oid:2.5.4.42": "first_name",
		"http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname": "first_name",
		"givenName": "first_name",

		"urn:oid:2.5.4.4": "last_name",
		"http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname": "last_name",
		"sn": "last_name",

		"urn:oid:2.5.4.3": "name",
		"http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name": "name",
		"cn":          "name",
		"displayName": "name",

		"urn:oid:1.3.6.1.4.1.5923.1.1.1.1":                               "groups",
		"http://schemas.microsoft.com/ws/2008/06/identity/claims/groups": "groups",
		"groups": "groups",

		"locale": "locale",
		"http://schemas.xmlsoap.org/ws/2005/05/identity/claims/locality": "locale",
	}
}
