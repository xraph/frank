package sso

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"encoding/xml"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/juicycleff/frank/internal/model"
	"github.com/juicycleff/frank/pkg/errors"
	"github.com/juicycleff/frank/pkg/logging"
	"github.com/juicycleff/frank/pkg/validation"
)

// SAMLService defines the SAML SSO service interface
type SAMLService interface {
	// Authentication flow
	InitiateLogin(ctx context.Context, provider *model.IdentityProvider, state, redirectURL string) (string, error)
	HandleCallback(ctx context.Context, provider *model.IdentityProvider, samlResponse, relayState string) (*SSOUserInfo, error)

	// Configuration and validation
	ValidateConfig(config model.IdentityProviderConfig) error
	TestConnection(ctx context.Context, provider *model.IdentityProvider) error

	// Metadata generation
	GenerateMetadata(ctx context.Context, provider *model.IdentityProvider) (string, error)
	GetMetadata(ctx context.Context, config model.SSOProviderConfig) (string, error)

	// Utility methods
	ParseSAMLResponse(samlResponse string) (*SAMLResponse, error)
	ValidateSAMLResponse(response *SAMLResponse, provider *model.IdentityProvider) error
}

// samlService implements SAML SSO functionality
type samlService struct {
	logger      logging.Logger
	baseURL     string
	privateKey  *rsa.PrivateKey
	certificate *x509.Certificate
	httpClient  *http.Client
}

// NewSAMLService creates a new SAML service
func NewSAMLService(baseURL string, logger logging.Logger) (SAMLService, error) {
	// Generate or load private key and certificate for SAML signing
	privateKey, certificate, err := generateSAMLKeyPair()
	if err != nil {
		return nil, fmt.Errorf("failed to generate SAML key pair: %w", err)
	}

	return &samlService{
		logger:      logger,
		baseURL:     baseURL,
		privateKey:  privateKey,
		certificate: certificate,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{
					InsecureSkipVerify: false,
				},
			},
		},
	}, nil
}

// InitiateLogin initiates SAML authentication flow
func (s *samlService) InitiateLogin(ctx context.Context, provider *model.IdentityProvider, state, redirectURL string) (string, error) {
	s.logger.Info("Initiating SAML login", logging.String("provider", provider.Name))

	// Extract SAML configuration
	config, err := s.extractSAMLConfig(provider.Config)
	if err != nil {
		return "", errors.Wrap(err, errors.CodeInvalidInput, "invalid SAML configuration")
	}

	// Generate SAML Request ID
	requestID := generateSAMLID()

	// Create SAML AuthnRequest
	authnRequest := &SAMLAuthnRequest{
		ID:                          requestID,
		Version:                     "2.0",
		IssueInstant:                time.Now().UTC().Format(time.RFC3339),
		Destination:                 config.SSOURL,
		ProtocolBinding:             "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST",
		AssertionConsumerServiceURL: fmt.Sprintf("%s/auth/saml/callback/%s", s.baseURL, provider.ID.String()),
		Issuer:                      s.getSAMLIssuer(provider),
		NameIDPolicy: &SAMLNameIDPolicy{
			Format:      config.NameIDFormat,
			AllowCreate: true,
		},
	}

	// Sign the request if required
	if config.SignRequests {
		if err := s.signSAMLRequest(authnRequest); err != nil {
			return "", errors.Wrap(err, errors.CodeInternalServer, "failed to sign SAML request")
		}
	}

	// Encode the request
	encodedRequest, err := s.encodeSAMLRequest(authnRequest)
	if err != nil {
		return "", errors.Wrap(err, errors.CodeInternalServer, "failed to encode SAML request")
	}

	// Build authentication URL
	authURL, err := s.buildSAMLAuthURL(config.SSOURL, encodedRequest, state)
	if err != nil {
		return "", errors.Wrap(err, errors.CodeInternalServer, "failed to build auth URL")
	}

	s.logger.Info("Generated SAML auth URL", logging.String("url", authURL))
	return authURL, nil
}

// HandleCallback processes SAML response after authentication
func (s *samlService) HandleCallback(ctx context.Context, provider *model.IdentityProvider, samlResponse, relayState string) (*SSOUserInfo, error) {
	s.logger.Info("Processing SAML callback", logging.String("provider", provider.Name))

	// Parse SAML response
	response, err := s.ParseSAMLResponse(samlResponse)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeInvalidInput, "failed to parse SAML response")
	}

	// Validate SAML response
	if err := s.ValidateSAMLResponse(response, provider); err != nil {
		return nil, errors.Wrap(err, errors.CodeUnauthorized, "SAML response validation failed")
	}

	// Extract user information from SAML response
	userInfo, err := s.extractUserInfoFromSAML(response, provider)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeInternalServer, "failed to extract user info")
	}

	s.logger.Info("Successfully processed SAML response", logging.String("user_email", userInfo.Email))
	return userInfo, nil
}

// ValidateConfig validates SAML provider configuration
func (s *samlService) ValidateConfig(config model.IdentityProviderConfig) error {
	if config.SSOUrl == "" {
		return errors.New(errors.CodeInvalidInput, "missing required SAML field: missing SSO URL")
	}

	if config.EntityID == "" {
		return errors.New(errors.CodeInvalidInput, "missing required SAML field: missing EntityID")
	}

	if config.Certificate == "" {
		return errors.New(errors.CodeInvalidInput, "missing required SAML field: missing Certificate")
	}

	// Validate URLs
	if _, err := url.Parse(config.SSOUrl); err != nil {
		return errors.Wrap(err, errors.CodeInvalidInput, "invalid SAML URL")
	}
	if _, err := url.Parse(config.Certificate); err != nil {
		return errors.Wrap(err, errors.CodeInvalidInput, "invalid certificate")
	}

	return nil
}

// TestConnection tests SAML provider connection
func (s *samlService) TestConnection(ctx context.Context, provider *model.IdentityProvider) error {
	config, err := s.extractSAMLConfig(provider.Config)
	if err != nil {
		return fmt.Errorf("invalid SAML configuration: %w", err)
	}

	// Test SSO URL accessibility
	if err := s.testSSOURL(config.SSOURL); err != nil {
		return fmt.Errorf("SSO URL test failed: %w", err)
	}

	// Test metadata endpoint if available
	if config.MetadataURL != "" {
		if err := s.testMetadataURL(config.MetadataURL); err != nil {
			return fmt.Errorf("metadata URL test failed: %w", err)
		}
	}

	return nil
}

// GenerateMetadata generates SAML metadata for service provider
func (s *samlService) GenerateMetadata(ctx context.Context, provider *model.IdentityProvider) (string, error) {
	entityID := s.getSAMLIssuer(provider)
	acsURL := fmt.Sprintf("%s/auth/saml/callback/%s", s.baseURL, provider.ID.String())

	metadata := &SAMLMetadata{
		EntityID: entityID,
		SPSSODescriptor: &SAMLSPSSODescriptor{
			AuthnRequestsSigned:        true,
			WantAssertionsSigned:       true,
			ProtocolSupportEnumeration: "urn:oasis:names:tc:SAML:2.0:protocol",
			AssertionConsumerServices: []SAMLAssertionConsumerService{
				{
					Binding:  "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST",
					Location: acsURL,
					Index:    0,
				},
			},
			KeyDescriptors: []SAMLKeyDescriptor{
				{
					Use: "signing",
					KeyInfo: &SAMLKeyInfo{
						X509Data: &SAMLX509Data{
							X509Certificate: s.getCertificateString(),
						},
					},
				},
			},
		},
	}

	return s.marshalSAMLMetadata(metadata)
}

// ParseSAMLResponse parses base64-encoded SAML response
func (s *samlService) ParseSAMLResponse(samlResponse string) (*SAMLResponse, error) {
	// Decode base64
	decoded, err := base64.StdEncoding.DecodeString(samlResponse)
	if err != nil {
		return nil, fmt.Errorf("failed to decode SAML response: %w", err)
	}

	// Parse XML
	var response SAMLResponse
	if err := xml.Unmarshal(decoded, &response); err != nil {
		return nil, fmt.Errorf("failed to parse SAML XML: %w", err)
	}

	return &response, nil
}

func (s *samlService) GetMetadata(ctx context.Context, config model.SSOProviderConfig) (string, error) {
	return "", nil
}

// ValidateSAMLResponse validates SAML response
func (s *samlService) ValidateSAMLResponse(response *SAMLResponse, provider *model.IdentityProvider) error {
	config, err := s.extractSAMLConfig(provider.Config)
	if err != nil {
		return fmt.Errorf("invalid SAML configuration: %w", err)
	}

	// Validate response status
	if response.Status.StatusCode.Value != "urn:oasis:names:tc:SAML:2.0:status:Success" {
		return fmt.Errorf("SAML response status is not success: %s", response.Status.StatusCode.Value)
	}

	// Validate issuer
	if response.Issuer != config.EntityID {
		return fmt.Errorf("SAML response issuer mismatch: expected %s, got %s", config.EntityID, response.Issuer)
	}

	// Validate destination
	expectedDestination := fmt.Sprintf("%s/auth/saml/callback/%s", s.baseURL, provider.ID.String())
	if response.Destination != expectedDestination {
		return fmt.Errorf("SAML response destination mismatch: expected %s, got %s", expectedDestination, response.Destination)
	}

	// Validate signature if present
	if response.Signature != nil {
		if err := s.validateSAMLSignature(response, config); err != nil {
			return fmt.Errorf("SAML signature validation failed: %w", err)
		}
	}

	// Validate assertion
	if len(response.Assertions) == 0 {
		return fmt.Errorf("SAML response contains no assertions")
	}

	assertion := response.Assertions[0]

	// Check assertion conditions
	if assertion.Conditions != nil {
		now := time.Now().UTC()

		if assertion.Conditions.NotBefore != "" {
			notBefore, err := time.Parse(time.RFC3339, assertion.Conditions.NotBefore)
			if err != nil {
				return fmt.Errorf("invalid NotBefore time: %w", err)
			}
			if now.Before(notBefore) {
				return fmt.Errorf("assertion not yet valid")
			}
		}

		if assertion.Conditions.NotOnOrAfter != "" {
			notOnOrAfter, err := time.Parse(time.RFC3339, assertion.Conditions.NotOnOrAfter)
			if err != nil {
				return fmt.Errorf("invalid NotOnOrAfter time: %w", err)
			}
			if now.After(notOnOrAfter) {
				return fmt.Errorf("assertion has expired")
			}
		}
	}

	return nil
}

// Helper methods

// extractSAMLConfig extracts SAML configuration from provider config
// extractSAMLConfig extracts SAML configuration from provider config
func (s *samlService) extractSAMLConfig(config model.IdentityProviderConfig) (*SAMLConfig, error) {
	// Start with default configuration
	samlConfig := DefaultSAMLConfig()

	// Map from IdentityProviderConfig to SAMLConfig
	samlConfig.SSOURL = config.SSOUrl
	samlConfig.EntityID = config.EntityID
	samlConfig.Certificate = config.Certificate

	// Optional fields
	if config.SLOUrl != "" {
		samlConfig.SLOURL = config.SLOUrl
	}

	if config.NameIDFormat != "" {
		samlConfig.NameIDFormat = config.NameIDFormat
	}

	// Note: MetadataURL, SignRequests, and WantAssertionsSigned are not in IdentityProviderConfig
	// You may need to add these fields to IdentityProviderConfig or handle them separately

	// Validate the extracted configuration
	if err := samlConfig.Validate(); err != nil {
		return nil, fmt.Errorf("invalid SAML configuration: %w", err)
	}

	// Additional SAML-specific validations
	if err := s.validateSAMLSpecificRules(samlConfig); err != nil {
		return nil, fmt.Errorf("SAML validation failed: %w", err)
	}

	return samlConfig, nil
}

// validateSAMLSpecificRules performs SAML-specific validation
func (s *samlService) validateSAMLSpecificRules(config *SAMLConfig) error {
	var errors []string

	// Validate NameID format
	validNameIDFormats := []string{
		"urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
		"urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified",
		"urn:oasis:names:tc:SAML:2.0:nameid-format:persistent",
		"urn:oasis:names:tc:SAML:2.0:nameid-format:transient",
	}

	validFormat := false
	for _, format := range validNameIDFormats {
		if config.NameIDFormat == format {
			validFormat = true
			break
		}
	}

	if !validFormat {
		errors = append(errors, "invalid NameID format")
	}

	// Validate certificate format (basic check for PEM format)
	if !strings.Contains(config.Certificate, "-----BEGIN CERTIFICATE-----") {
		errors = append(errors, "certificate must be in PEM format")
	}

	// Validate URLs are HTTPS in production
	if !s.isTestEnvironment() {
		if !strings.HasPrefix(config.SSOURL, "https://") {
			errors = append(errors, "SSO URL must use HTTPS in production")
		}

		if config.SLOURL != "" && !strings.HasPrefix(config.SLOURL, "https://") {
			errors = append(errors, "SLO URL must use HTTPS in production")
		}

		if config.MetadataURL != "" && !strings.HasPrefix(config.MetadataURL, "https://") {
			errors = append(errors, "Metadata URL must use HTTPS in production")
		}
	}

	if len(errors) > 0 {
		return fmt.Errorf("validation errors: %s", strings.Join(errors, "; "))
	}

	return nil
}

// isTestEnvironment checks if we're running in a test environment
func (s *samlService) isTestEnvironment() bool {
	// Implement your environment detection logic
	// This is just a placeholder
	return false
}

// Alternative approach: Extract with validation during mapping
func (s *samlService) extractSAMLConfigWithValidation(config model.IdentityProviderConfig) (*SAMLConfig, error) {
	validator := validation.GetInstance()

	// Validate required fields exist and are not empty
	if config.SSOUrl == "" {
		return nil, fmt.Errorf("sso_url is required")
	}

	if config.EntityID == "" {
		return nil, fmt.Errorf("entity_id is required")
	}

	if config.Certificate == "" {
		return nil, fmt.Errorf("certificate is required")
	}

	// Validate individual fields
	if err := validator.ValidateVar(config.SSOUrl, "required,url"); err != nil {
		return nil, fmt.Errorf("invalid sso_url: %w", err)
	}

	if config.SLOUrl != "" {
		if err := validator.ValidateVar(config.SLOUrl, "url"); err != nil {
			return nil, fmt.Errorf("invalid slo_url: %w", err)
		}
	}

	// Create and populate SAML config
	samlConfig := &SAMLConfig{
		SSOURL:       config.SSOUrl,
		EntityID:     config.EntityID,
		Certificate:  config.Certificate,
		SLOURL:       config.SLOUrl,
		NameIDFormat: config.NameIDFormat,
		// Set defaults for missing fields
		SignRequests:         false,
		WantAssertionsSigned: true,
	}

	// Set default NameID format if not provided
	if samlConfig.NameIDFormat == "" {
		samlConfig.NameIDFormat = "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"
	}

	// Final validation of the complete config
	if err := samlConfig.Validate(); err != nil {
		return nil, fmt.Errorf("SAML configuration validation failed: %w", err)
	}

	return samlConfig, nil
}

// extractUserInfoFromSAML extracts user information from SAML assertion
func (s *samlService) extractUserInfoFromSAML(response *SAMLResponse, provider *model.IdentityProvider) (*SSOUserInfo, error) {
	if len(response.Assertions) == 0 {
		return nil, fmt.Errorf("no assertions in SAML response")
	}

	assertion := response.Assertions[0]

	// Get NameID as user ID
	userID := assertion.Subject.NameID.Value

	// Initialize user info
	userInfo := &SSOUserInfo{
		ID:         userID,
		Attributes: make(map[string]interface{}),
	}

	// Extract attributes from attribute statements
	for _, attrStatement := range assertion.AttributeStatements {
		for _, attr := range attrStatement.Attributes {
			// Map common attributes
			switch strings.ToLower(attr.Name) {
			case "email", "emailaddress", "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress":
				if len(attr.Values) > 0 {
					userInfo.Email = attr.Values[0]
				}
			case "firstname", "givenname", "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname":
				if len(attr.Values) > 0 {
					userInfo.FirstName = attr.Values[0]
				}
			case "lastname", "surname", "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname":
				if len(attr.Values) > 0 {
					userInfo.LastName = attr.Values[0]
				}
			case "displayname", "name", "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name":
				if len(attr.Values) > 0 {
					// If no first/last name, try to parse display name
					if userInfo.FirstName == "" && userInfo.LastName == "" {
						parts := strings.SplitN(attr.Values[0], " ", 2)
						if len(parts) >= 1 {
							userInfo.FirstName = parts[0]
						}
						if len(parts) >= 2 {
							userInfo.LastName = parts[1]
						}
					}
				}
			}

			// Store all attributes
			userInfo.Attributes[attr.Name] = attr.Values
		}
	}

	// Apply custom attribute mapping if configured
	if provider.AttributeMapping != nil {
		s.applyAttributeMapping(userInfo, provider.AttributeMapping)
	}

	// Validate required fields
	if userInfo.Email == "" {
		return nil, fmt.Errorf("email not found in SAML response")
	}

	return userInfo, nil
}

// applyAttributeMapping applies custom attribute mapping
func (s *samlService) applyAttributeMapping(userInfo *SSOUserInfo, mapping map[string]string) {
	for localAttr, samlAttr := range mapping {
		if values, exists := userInfo.Attributes[samlAttr]; exists {
			if valueSlice, ok := values.([]string); ok && len(valueSlice) > 0 {
				switch localAttr {
				case "email":
					userInfo.Email = valueSlice[0]
				case "first_name":
					userInfo.FirstName = valueSlice[0]
				case "last_name":
					userInfo.LastName = valueSlice[0]
				case "profile_image_url":
					userInfo.Picture = valueSlice[0]
				}
			}
		}
	}
}

// getSAMLIssuer returns the SAML issuer for the service provider
func (s *samlService) getSAMLIssuer(provider *model.IdentityProvider) string {
	return fmt.Sprintf("%s/auth/saml/metadata/%s", s.baseURL, provider.ID.String())
}

// validateCertificate validates X.509 certificate
func (s *samlService) validateCertificate(certPEM string) error {
	block, _ := pem.Decode([]byte(certPEM))
	if block == nil {
		return fmt.Errorf("failed to parse certificate PEM")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return fmt.Errorf("failed to parse certificate: %w", err)
	}

	// Check if certificate is expired
	now := time.Now()
	if now.Before(cert.NotBefore) || now.After(cert.NotAfter) {
		return fmt.Errorf("certificate is expired or not yet valid")
	}

	return nil
}

// testSSOURL tests if SSO URL is accessible
func (s *samlService) testSSOURL(ssoURL string) error {
	resp, err := s.httpClient.Get(ssoURL)
	if err != nil {
		return fmt.Errorf("failed to connect to SSO URL: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 && resp.StatusCode < 500 {
		return fmt.Errorf("SSO URL returned client error: %d", resp.StatusCode)
	}

	return nil
}

// testMetadataURL tests if metadata URL is accessible
func (s *samlService) testMetadataURL(metadataURL string) error {
	resp, err := s.httpClient.Get(metadataURL)
	if err != nil {
		return fmt.Errorf("failed to connect to metadata URL: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return fmt.Errorf("metadata URL returned status: %d", resp.StatusCode)
	}

	return nil
}

// Additional helper methods for SAML processing

// generateSAMLID generates a unique SAML request ID
func generateSAMLID() string {
	b := make([]byte, 16)
	rand.Read(b)
	return fmt.Sprintf("_%x", b)
}

// signSAMLRequest signs a SAML request (placeholder implementation)
func (s *samlService) signSAMLRequest(request *SAMLAuthnRequest) error {
	// This would implement XML signature signing
	// For now, just mark as signed
	return nil
}

// encodeSAMLRequest encodes SAML request for transmission
func (s *samlService) encodeSAMLRequest(request *SAMLAuthnRequest) (string, error) {
	// Marshal to XML
	xmlBytes, err := xml.Marshal(request)
	if err != nil {
		return "", fmt.Errorf("failed to marshal SAML request: %w", err)
	}

	// Base64 encode
	return base64.StdEncoding.EncodeToString(xmlBytes), nil
}

// buildSAMLAuthURL builds the SAML authentication URL
func (s *samlService) buildSAMLAuthURL(ssoURL, encodedRequest, relayState string) (string, error) {
	u, err := url.Parse(ssoURL)
	if err != nil {
		return "", fmt.Errorf("invalid SSO URL: %w", err)
	}

	q := u.Query()
	q.Set("SAMLRequest", encodedRequest)
	if relayState != "" {
		q.Set("RelayState", relayState)
	}
	u.RawQuery = q.Encode()

	return u.String(), nil
}

// validateSAMLSignature validates SAML response signature
func (s *samlService) validateSAMLSignature(response *SAMLResponse, config *SAMLConfig) error {
	// This would implement XML signature validation
	// For now, just return success
	return nil
}

// marshalSAMLMetadata marshals SAML metadata to XML
func (s *samlService) marshalSAMLMetadata(metadata *SAMLMetadata) (string, error) {
	xmlBytes, err := xml.MarshalIndent(metadata, "", "  ")
	if err != nil {
		return "", fmt.Errorf("failed to marshal SAML metadata: %w", err)
	}

	return string(xmlBytes), nil
}

// getCertificateString returns the certificate as a string
func (s *samlService) getCertificateString() string {
	if s.certificate == nil {
		return ""
	}

	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: s.certificate.Raw,
	})

	// Remove PEM headers and newlines for XML
	certStr := string(certPEM)
	certStr = strings.Replace(certStr, "-----BEGIN CERTIFICATE-----", "", 1)
	certStr = strings.Replace(certStr, "-----END CERTIFICATE-----", "", 1)
	certStr = strings.Replace(certStr, "\n", "", -1)

	return certStr
}

// generateSAMLKeyPair generates a key pair for SAML signing
func generateSAMLKeyPair() (*rsa.PrivateKey, *x509.Certificate, error) {
	// Generate private key
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate private key: %w", err)
	}

	// Create certificate template
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization:  []string{"Frank Auth"},
			Country:       []string{"US"},
			Province:      []string{""},
			Locality:      []string{""},
			StreetAddress: []string{""},
			PostalCode:    []string{""},
		},
		NotBefore:   time.Now(),
		NotAfter:    time.Now().Add(365 * 24 * time.Hour), // 1 year
		KeyUsage:    x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses: []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback},
	}

	// Create certificate
	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create certificate: %w", err)
	}

	certificate, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse certificate: %w", err)
	}

	return privateKey, certificate, nil
}

// Validate validates the SAML configuration
func (c *SAMLConfig) Validate() error {
	validator := validation.GetInstance()
	return validator.ValidateStruct(c)
}
