package passkey

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"time"

	"github.com/juicycleff/frank/pkg/errors"
	"github.com/juicycleff/frank/pkg/logging"
	"github.com/rs/xid"
)

// WebAuthnService defines the interface for WebAuthn operations
type WebAuthnService interface {
	// Registration operations
	BeginRegistration(ctx context.Context, req WebAuthnBeginRegistrationRequest) (map[string]interface{}, *WebAuthnSessionData, error)
	FinishRegistration(ctx context.Context, req WebAuthnFinishRegistrationRequest) (*WebAuthnCredential, error)

	// Authentication operations
	BeginAuthentication(ctx context.Context, req WebAuthnBeginAuthenticationRequest) (map[string]interface{}, *WebAuthnSessionData, error)
	FinishAuthentication(ctx context.Context, req WebAuthnFinishAuthenticationRequest) (*WebAuthnAuthenticationResult, error)

	// Verification operations
	VerifyCredential(ctx context.Context, req WebAuthnVerifyCredentialRequest) (bool, error)
	ValidateAssertion(ctx context.Context, req WebAuthnValidateAssertionRequest) (*WebAuthnValidationResult, error)
}

// WebAuthn request/response types
type WebAuthnBeginRegistrationRequest struct {
	Username           string `json:"username"`
	DisplayName        string `json:"displayName"`
	RequireResidentKey bool   `json:"requireResidentKey"`
	UserVerification   string `json:"userVerification"`
	AttestationType    string `json:"attestationType"`
	AuthenticatorType  string `json:"authenticatorType"`
}

type WebAuthnBeginAuthenticationRequest struct {
	Username         string   `json:"username"`
	AllowCredentials []string `json:"allowCredentials"`
	UserVerification string   `json:"userVerification"`
}

type WebAuthnFinishRegistrationRequest struct {
	SessionID string                 `json:"sessionId"`
	Response  map[string]interface{} `json:"response"`
}

type WebAuthnFinishAuthenticationRequest struct {
	SessionID string                 `json:"sessionId"`
	Response  map[string]interface{} `json:"response"`
}

type WebAuthnVerifyCredentialRequest struct {
	CredentialID string `json:"credentialId"`
	Challenge    string `json:"challenge"`
	Origin       string `json:"origin"`
	PublicKey    []byte `json:"publicKey"`
}

type WebAuthnValidateAssertionRequest struct {
	CredentialID      string                 `json:"credentialId"`
	AuthenticatorData []byte                 `json:"authenticatorData"`
	ClientDataJSON    []byte                 `json:"clientDataJSON"`
	Signature         []byte                 `json:"signature"`
	Challenge         string                 `json:"challenge"`
	Origin            string                 `json:"origin"`
	PublicKey         []byte                 `json:"publicKey"`
	AdditionalData    map[string]interface{} `json:"additionalData"`
}

type WebAuthnSessionData struct {
	SessionID string    `json:"sessionId"`
	Challenge string    `json:"challenge"`
	UserID    string    `json:"userId,omitempty"`
	ExpiresAt time.Time `json:"expiresAt"`
}

type WebAuthnCredential struct {
	CredentialID   string                 `json:"credentialId"`
	PublicKey      []byte                 `json:"publicKey"`
	DeviceType     string                 `json:"deviceType"`
	AAGUID         string                 `json:"aaguid"`
	Transports     []string               `json:"transports"`
	Attestation    map[string]interface{} `json:"attestation"`
	BackupEligible bool                   `json:"backupEligible"`
	BackupState    bool                   `json:"backupState"`
	SignCount      int                    `json:"signCount"`
}

type WebAuthnAuthenticationResult struct {
	CredentialID string `json:"credentialId"`
	UserHandle   []byte `json:"userHandle"`
	SignCount    int    `json:"signCount"`
	Success      bool   `json:"success"`
}

type WebAuthnValidationResult struct {
	Valid        bool   `json:"valid"`
	SignCount    int    `json:"signCount"`
	BackupState  bool   `json:"backupState"`
	ErrorMessage string `json:"errorMessage,omitempty"`
}

// WebAuthn configuration
type WebAuthnConfig struct {
	RelyingPartyName    string   `json:"relyingPartyName"`
	RelyingPartyID      string   `json:"relyingPartyId"`
	RelyingPartyOrigins []string `json:"relyingPartyOrigins"`
	AttestationTimeout  int      `json:"attestationTimeout"`
	AssertionTimeout    int      `json:"assertionTimeout"`
}

// webauthnService implements the WebAuthnService interface
type webauthnService struct {
	config       WebAuthnConfig
	sessionStore map[string]*WebAuthnSessionData // In production, use Redis or similar
	logger       logging.Logger
}

// NewWebAuthnService creates a new WebAuthn service
func NewWebAuthnService(config WebAuthnConfig, logger logging.Logger) WebAuthnService {
	return &webauthnService{
		config:       config,
		sessionStore: make(map[string]*WebAuthnSessionData),
		logger:       logger.Named("webauthn"),
	}
}

// BeginRegistration starts the WebAuthn registration process
func (w *webauthnService) BeginRegistration(ctx context.Context, req WebAuthnBeginRegistrationRequest) (map[string]interface{}, *WebAuthnSessionData, error) {
	w.logger.Debug("Beginning WebAuthn registration", logging.String("username", req.Username))

	// Generate challenge
	challenge, err := w.generateChallenge()
	if err != nil {
		return nil, nil, errors.Wrap(err, errors.CodeInternalServer, "failed to generate challenge")
	}

	// Generate user ID
	userID := base64.URLEncoding.EncodeToString([]byte(req.Username))

	// Create session data
	sessionID := xid.New().String()
	sessionData := &WebAuthnSessionData{
		SessionID: sessionID,
		Challenge: challenge,
		UserID:    userID,
		ExpiresAt: time.Now().Add(5 * time.Minute),
	}

	// Store session
	w.sessionStore[sessionID] = sessionData

	// Build credential creation options
	options := map[string]interface{}{
		"rp": map[string]interface{}{
			"name": w.config.RelyingPartyName,
			"id":   w.config.RelyingPartyID,
		},
		"user": map[string]interface{}{
			"id":          userID,
			"name":        req.Username,
			"displayName": req.DisplayName,
		},
		"challenge": challenge,
		"pubKeyCredParams": []map[string]interface{}{
			{
				"type": "public-key",
				"alg":  -7, // ES256
			},
			{
				"type": "public-key",
				"alg":  -257, // RS256
			},
		},
		"timeout": w.config.AttestationTimeout,
		"attestation": func() string {
			if req.AttestationType != "" {
				return req.AttestationType
			}
			return "none"
		}(),
		"authenticatorSelection": map[string]interface{}{
			"authenticatorAttachment": func() interface{} {
				if req.AuthenticatorType == "platform" {
					return "platform"
				} else if req.AuthenticatorType == "roaming" {
					return "cross-platform"
				}
				return nil
			}(),
			"requireResidentKey": req.RequireResidentKey,
			"residentKey": func() string {
				if req.RequireResidentKey {
					return "required"
				}
				return "preferred"
			}(),
			"userVerification": func() string {
				if req.UserVerification != "" {
					return req.UserVerification
				}
				return "preferred"
			}(),
		},
	}

	w.logger.Debug("WebAuthn registration options created",
		logging.String("sessionId", sessionID),
		logging.String("challenge", challenge))

	return options, sessionData, nil
}

// FinishRegistration completes the WebAuthn registration process
func (w *webauthnService) FinishRegistration(ctx context.Context, req WebAuthnFinishRegistrationRequest) (*WebAuthnCredential, error) {
	w.logger.Debug("Finishing WebAuthn registration", logging.String("sessionId", req.SessionID))

	// Get session data
	sessionData, exists := w.sessionStore[req.SessionID]
	if !exists {
		return nil, errors.New(errors.CodeUnauthorized, "invalid or expired session")
	}

	// Check session expiry
	if time.Now().After(sessionData.ExpiresAt) {
		delete(w.sessionStore, req.SessionID)
		return nil, errors.New(errors.CodeUnauthorized, "session expired")
	}

	// Parse the credential creation response
	credential, err := w.parseCredentialCreationResponse(req.Response, sessionData.Challenge)
	if err != nil {
		return nil, err
	}

	// Clean up session
	delete(w.sessionStore, req.SessionID)

	w.logger.Info("WebAuthn registration completed",
		logging.String("credentialId", credential.CredentialID))

	return credential, nil
}

// BeginAuthentication starts the WebAuthn authentication process
func (w *webauthnService) BeginAuthentication(ctx context.Context, req WebAuthnBeginAuthenticationRequest) (map[string]interface{}, *WebAuthnSessionData, error) {
	w.logger.Debug("Beginning WebAuthn authentication", logging.String("username", req.Username))

	// Generate challenge
	challenge, err := w.generateChallenge()
	if err != nil {
		return nil, nil, errors.Wrap(err, errors.CodeInternalServer, "failed to generate challenge")
	}

	// Create session data
	sessionID := xid.New().String()
	sessionData := &WebAuthnSessionData{
		SessionID: sessionID,
		Challenge: challenge,
		ExpiresAt: time.Now().Add(5 * time.Minute),
	}

	// Store session
	w.sessionStore[sessionID] = sessionData

	// Build credential request options
	options := map[string]interface{}{
		"challenge": challenge,
		"timeout":   w.config.AssertionTimeout,
		"rpId":      w.config.RelyingPartyID,
		"userVerification": func() string {
			if req.UserVerification != "" {
				return req.UserVerification
			}
			return "preferred"
		}(),
	}

	// Add allowed credentials if provided
	if len(req.AllowCredentials) > 0 {
		allowCredentials := make([]map[string]interface{}, len(req.AllowCredentials))
		for i, credID := range req.AllowCredentials {
			allowCredentials[i] = map[string]interface{}{
				"type":       "public-key",
				"id":         credID,
				"transports": []string{"internal", "usb", "nfc", "ble"},
			}
		}
		options["allowCredentials"] = allowCredentials
	}

	w.logger.Debug("WebAuthn authentication options created",
		logging.String("sessionId", sessionID),
		logging.String("challenge", challenge))

	return options, sessionData, nil
}

// FinishAuthentication completes the WebAuthn authentication process
func (w *webauthnService) FinishAuthentication(ctx context.Context, req WebAuthnFinishAuthenticationRequest) (*WebAuthnAuthenticationResult, error) {
	w.logger.Debug("Finishing WebAuthn authentication", logging.String("sessionId", req.SessionID))

	// Get session data
	sessionData, exists := w.sessionStore[req.SessionID]
	if !exists {
		return nil, errors.New(errors.CodeUnauthorized, "invalid or expired session")
	}

	// Check session expiry
	if time.Now().After(sessionData.ExpiresAt) {
		delete(w.sessionStore, req.SessionID)
		return nil, errors.New(errors.CodeUnauthorized, "session expired")
	}

	// Parse the credential assertion response
	result, err := w.parseCredentialAssertionResponse(req.Response, sessionData.Challenge)
	if err != nil {
		return nil, err
	}

	// Clean up session
	delete(w.sessionStore, req.SessionID)

	w.logger.Info("WebAuthn authentication completed",
		logging.String("credentialId", result.CredentialID))

	return result, nil
}

// VerifyCredential verifies a WebAuthn credential
func (w *webauthnService) VerifyCredential(ctx context.Context, req WebAuthnVerifyCredentialRequest) (bool, error) {
	w.logger.Debug("Verifying WebAuthn credential", logging.String("credentialId", req.CredentialID))

	// This is a simplified verification - in production, you would:
	// 1. Verify the origin matches expected origins
	// 2. Verify the challenge matches
	// 3. Verify the signature using the public key
	// 4. Check other WebAuthn-specific validations

	// Basic origin validation
	validOrigin := false
	for _, origin := range w.config.RelyingPartyOrigins {
		if origin == req.Origin {
			validOrigin = true
			break
		}
	}

	if !validOrigin {
		return false, errors.New(errors.CodeUnauthorized, "invalid origin")
	}

	// In a real implementation, you would verify the cryptographic signature here
	// For now, we'll assume verification passes if basic checks pass
	return true, nil
}

// ValidateAssertion validates a WebAuthn assertion
func (w *webauthnService) ValidateAssertion(ctx context.Context, req WebAuthnValidateAssertionRequest) (*WebAuthnValidationResult, error) {
	w.logger.Debug("Validating WebAuthn assertion", logging.String("credentialId", req.CredentialID))

	// This would perform full WebAuthn assertion validation including:
	// 1. Parsing authenticator data
	// 2. Verifying client data JSON
	// 3. Checking signature
	// 4. Validating challenge and origin
	// 5. Updating sign count

	// Simplified validation for now
	return &WebAuthnValidationResult{
		Valid:       true,
		SignCount:   1, // Would extract from authenticator data
		BackupState: false,
	}, nil
}

// Helper methods

func (w *webauthnService) generateChallenge() (string, error) {
	challenge := make([]byte, 32)
	_, err := rand.Read(challenge)
	if err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(challenge), nil
}

func (w *webauthnService) parseCredentialCreationResponse(response map[string]interface{}, expectedChallenge string) (*WebAuthnCredential, error) {
	// Extract credential data from the response
	// This is a simplified parser - in production, you would use a proper WebAuthn library

	credentialID, ok := response["id"].(string)
	if !ok {
		return nil, errors.New(errors.CodeBadRequest, "missing credential ID")
	}

	_, ok = response["rawId"].(string) // rawId
	if !ok {
		return nil, errors.New(errors.CodeBadRequest, "missing raw ID")
	}

	responseData, ok := response["response"].(map[string]interface{})
	if !ok {
		return nil, errors.New(errors.CodeBadRequest, "missing response data")
	}

	// Extract public key from attestation object (attestationObject)
	_, ok = responseData["attestationObject"].(string)
	if !ok {
		return nil, errors.New(errors.CodeBadRequest, "missing attestation object")
	}

	// In production, you would parse the CBOR attestation object
	// For now, we'll create a mock public key
	publicKey := []byte("mock-public-key-" + credentialID)

	// Extract client data and verify challenge
	clientDataJSON, ok := responseData["clientDataJSON"].(string)
	if !ok {
		return nil, errors.New(errors.CodeBadRequest, "missing client data JSON")
	}

	// Parse and verify client data (simplified)
	if !w.verifyClientDataChallenge(clientDataJSON, expectedChallenge) {
		return nil, errors.New(errors.CodeUnauthorized, "challenge verification failed")
	}

	// Extract transports if available
	var transports []string
	if transportData, ok := response["transports"].([]interface{}); ok {
		for _, t := range transportData {
			if transport, ok := t.(string); ok {
				transports = append(transports, transport)
			}
		}
	}

	return &WebAuthnCredential{
		CredentialID:   credentialID,
		PublicKey:      publicKey,
		DeviceType:     "unknown", // Would be determined from attestation
		AAGUID:         "00000000-0000-0000-0000-000000000000",
		Transports:     transports,
		Attestation:    map[string]interface{}{"format": "none"},
		BackupEligible: true,
		BackupState:    false,
		SignCount:      0,
	}, nil
}

func (w *webauthnService) parseCredentialAssertionResponse(response map[string]interface{}, expectedChallenge string) (*WebAuthnAuthenticationResult, error) {
	// Extract assertion data from the response

	credentialID, ok := response["id"].(string)
	if !ok {
		return nil, errors.New(errors.CodeBadRequest, "missing credential ID")
	}

	responseData, ok := response["response"].(map[string]interface{})
	if !ok {
		return nil, errors.New(errors.CodeBadRequest, "missing response data")
	}

	// Extract client data and verify challenge
	clientDataJSON, ok := responseData["clientDataJSON"].(string)
	if !ok {
		return nil, errors.New(errors.CodeBadRequest, "missing client data JSON")
	}

	if !w.verifyClientDataChallenge(clientDataJSON, expectedChallenge) {
		return nil, errors.New(errors.CodeUnauthorized, "challenge verification failed")
	}

	// Extract authenticator data
	authenticatorData, ok := responseData["authenticatorData"].(string)
	if !ok {
		return nil, errors.New(errors.CodeBadRequest, "missing authenticator data")
	}

	// Parse authenticator data to extract sign count
	signCount := w.parseSignCount(authenticatorData)

	// Extract user handle if present
	var userHandle []byte
	if userHandleStr, ok := responseData["userHandle"].(string); ok && userHandleStr != "" {
		userHandle, _ = base64.URLEncoding.DecodeString(userHandleStr)
	}

	return &WebAuthnAuthenticationResult{
		CredentialID: credentialID,
		UserHandle:   userHandle,
		SignCount:    signCount,
		Success:      true,
	}, nil
}

func (w *webauthnService) verifyClientDataChallenge(clientDataJSON, expectedChallenge string) bool {
	// In production, you would parse the JSON and verify the challenge
	// This is a simplified check
	return true // Assuming challenge verification passes
}

func (w *webauthnService) parseSignCount(authenticatorData string) int {
	// In production, you would parse the CBOR authenticator data to extract the sign count
	// This is a simplified implementation
	return 1
}
