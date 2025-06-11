package sso

import (
	"encoding/xml"
)

// SAML data structures

// SAMLConfig represents SAML provider configuration
type SAMLConfig struct {
	SSOURL               string `json:"sso_url"`
	SLOURL               string `json:"slo_url,omitempty"`
	EntityID             string `json:"entity_id"`
	Certificate          string `json:"certificate"`
	MetadataURL          string `json:"metadata_url,omitempty"`
	NameIDFormat         string `json:"name_id_format"`
	SignRequests         bool   `json:"sign_requests"`
	WantAssertionsSigned bool   `json:"want_assertions_signed"`
}

// DefaultSAMLConfig returns a SAMLConfig with default values
func DefaultSAMLConfig() *SAMLConfig {
	return &SAMLConfig{
		NameIDFormat:         "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
		SignRequests:         false,
		WantAssertionsSigned: true,
	}
}

// SAMLAuthnRequest represents a SAML authentication request
type SAMLAuthnRequest struct {
	XMLName                     xml.Name          `xml:"samlp:AuthnRequest"`
	Xmlns                       string            `xml:"xmlns:samlp,attr"`
	XmlnsSAML                   string            `xml:"xmlns:saml,attr"`
	ID                          string            `xml:"ID,attr"`
	Version                     string            `xml:"Version,attr"`
	IssueInstant                string            `xml:"IssueInstant,attr"`
	Destination                 string            `xml:"Destination,attr"`
	ProtocolBinding             string            `xml:"ProtocolBinding,attr"`
	AssertionConsumerServiceURL string            `xml:"AssertionConsumerServiceURL,attr"`
	Issuer                      string            `xml:"saml:Issuer"`
	NameIDPolicy                *SAMLNameIDPolicy `xml:"samlp:NameIDPolicy,omitempty"`
}

// SAMLNameIDPolicy represents SAML NameID policy
type SAMLNameIDPolicy struct {
	Format      string `xml:"Format,attr"`
	AllowCreate bool   `xml:"AllowCreate,attr"`
}

// SAMLResponse represents a SAML response
type SAMLResponse struct {
	XMLName      xml.Name        `xml:"Response"`
	ID           string          `xml:"ID,attr"`
	Version      string          `xml:"Version,attr"`
	IssueInstant string          `xml:"IssueInstant,attr"`
	Destination  string          `xml:"Destination,attr"`
	Issuer       string          `xml:"Issuer"`
	Status       SAMLStatus      `xml:"Status"`
	Assertions   []SAMLAssertion `xml:"Assertion"`
	Signature    *SAMLSignature  `xml:"Signature,omitempty"`
}

// SAMLStatus represents SAML status
type SAMLStatus struct {
	StatusCode SAMLStatusCode `xml:"StatusCode"`
}

// SAMLStatusCode represents SAML status code
type SAMLStatusCode struct {
	Value string `xml:"Value,attr"`
}

// SAMLAssertion represents a SAML assertion
type SAMLAssertion struct {
	ID                  string                   `xml:"ID,attr"`
	Version             string                   `xml:"Version,attr"`
	IssueInstant        string                   `xml:"IssueInstant,attr"`
	Issuer              string                   `xml:"Issuer"`
	Subject             SAMLSubject              `xml:"Subject"`
	Conditions          *SAMLConditions          `xml:"Conditions,omitempty"`
	AttributeStatements []SAMLAttributeStatement `xml:"AttributeStatement"`
}

// SAMLSubject represents SAML subject
type SAMLSubject struct {
	NameID SAMLNameID `xml:"NameID"`
}

// SAMLNameID represents SAML NameID
type SAMLNameID struct {
	Format string `xml:"Format,attr"`
	Value  string `xml:",chardata"`
}

// SAMLConditions represents SAML conditions
type SAMLConditions struct {
	NotBefore    string `xml:"NotBefore,attr"`
	NotOnOrAfter string `xml:"NotOnOrAfter,attr"`
}

// SAMLAttributeStatement represents SAML attribute statement
type SAMLAttributeStatement struct {
	Attributes []SAMLAttribute `xml:"Attribute"`
}

// SAMLAttribute represents a SAML attribute
type SAMLAttribute struct {
	Name   string   `xml:"Name,attr"`
	Values []string `xml:"AttributeValue"`
}

// SAMLSignature represents SAML signature
type SAMLSignature struct {
	// Signature elements would be defined here
}

// SAMLMetadata represents SAML metadata
type SAMLMetadata struct {
	XMLName         xml.Name             `xml:"md:EntityDescriptor"`
	Xmlns           string               `xml:"xmlns:md,attr"`
	EntityID        string               `xml:"entityID,attr"`
	SPSSODescriptor *SAMLSPSSODescriptor `xml:"md:SPSSODescriptor"`
}

// SAMLSPSSODescriptor represents SAML SP SSO descriptor
type SAMLSPSSODescriptor struct {
	AuthnRequestsSigned        bool                           `xml:"AuthnRequestsSigned,attr"`
	WantAssertionsSigned       bool                           `xml:"WantAssertionsSigned,attr"`
	ProtocolSupportEnumeration string                         `xml:"protocolSupportEnumeration,attr"`
	KeyDescriptors             []SAMLKeyDescriptor            `xml:"md:KeyDescriptor"`
	AssertionConsumerServices  []SAMLAssertionConsumerService `xml:"md:AssertionConsumerService"`
}

// SAMLKeyDescriptor represents SAML key descriptor
type SAMLKeyDescriptor struct {
	Use     string       `xml:"use,attr"`
	KeyInfo *SAMLKeyInfo `xml:"ds:KeyInfo"`
}

// SAMLKeyInfo represents SAML key info
type SAMLKeyInfo struct {
	Xmlns    string        `xml:"xmlns:ds,attr"`
	X509Data *SAMLX509Data `xml:"ds:X509Data"`
}

// SAMLX509Data represents SAML X509 data
type SAMLX509Data struct {
	X509Certificate string `xml:"ds:X509Certificate"`
}

// SAMLAssertionConsumerService represents SAML assertion consumer service
type SAMLAssertionConsumerService struct {
	Binding  string `xml:"Binding,attr"`
	Location string `xml:"Location,attr"`
	Index    int    `xml:"index,attr"`
}
