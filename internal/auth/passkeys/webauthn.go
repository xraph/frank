package passkeys

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/google/uuid"
	"github.com/juicycleff/frank/config"
	appErrors "github.com/juicycleff/frank/pkg/errors"
	"github.com/juicycleff/frank/pkg/logging"
)

// WebAuthnProvider manages WebAuthn operations
type WebAuthnProvider struct {
	webAuthn *webauthn.WebAuthn
	logger   logging.Logger
	config   *config.Config
}

// NewWebAuthnProvider creates a new WebAuthn provider
func NewWebAuthnProvider(cfg *config.Config, logger logging.Logger) (*WebAuthnProvider, error) {
	var err error
	domains := cfg.Passkeys.RelyingPartyOrigins

	// Create WebAuthn configuration
	wconfig := &webauthn.Config{
		RPDisplayName: cfg.Passkeys.RelyingPartyName,
		RPID:          cfg.Passkeys.RelyingPartyID,
		RPOrigins:     domains,
		Timeouts: webauthn.TimeoutsConfig{
			Login: webauthn.TimeoutConfig{
				Timeout: time.Duration(cfg.Passkeys.AttestationTimeout),
			},
			Registration: webauthn.TimeoutConfig{
				Timeout: time.Duration(cfg.Passkeys.AttestationTimeout),
			},
		},
	}

	wa, err := webauthn.New(wconfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create WebAuthn provider: %w", err)
	}

	return &WebAuthnProvider{
		webAuthn: wa,
		logger:   logger,
		config:   cfg,
	}, nil
}

// BeginRegistration starts the WebAuthn registration process
func (p *WebAuthnProvider) BeginRegistration(ctx context.Context, user AuthenticatorUser) (*protocol.CredentialCreation, *webauthn.SessionData, string, error) {
	if user == nil {
		return nil, nil, "", appErrors.New(appErrors.CodeInvalidInput, "user cannot be nil")
	}

	p.logger.Info("Beginning WebAuthn registration",
		logging.String("user_id", string(user.WebAuthnID())),
		logging.String("user_name", user.WebAuthnDisplayName()),
	)

	// Create credential creation options
	options, sessionData, err := p.webAuthn.BeginRegistration(user)
	if err != nil {
		return nil, nil, "", fmt.Errorf("failed to begin registration: %w", err)
	}

	// Generate a session ID for this registration
	sessionID := uuid.New().String()

	// Return the credential creation options, session data, session ID, and nil error
	return options, sessionData, sessionID, nil
}

// FinishRegistration completes the WebAuthn registration process
func (p *WebAuthnProvider) FinishRegistration(
	ctx context.Context,
	user AuthenticatorUser,
	sessionData *webauthn.SessionData,
	response *http.Request,
) (*webauthn.Credential, error) {
	if user == nil {
		return nil, appErrors.New(appErrors.CodeInvalidInput, "user cannot be nil")
	}
	if sessionData == nil {
		return nil, appErrors.New(appErrors.CodeInvalidInput, "session data cannot be nil")
	}
	if response == nil {
		return nil, appErrors.New(appErrors.CodeInvalidInput, "request cannot be nil")
	}

	p.logger.Info("Finishing WebAuthn registration",
		logging.String("user_id", string(user.WebAuthnID())),
		logging.String("user_name", user.WebAuthnDisplayName()),
	)

	// Finish the registration
	credential, err := p.webAuthn.FinishRegistration(user, *sessionData, response)
	if err != nil {
		// Check for common error types
		var verificationError *protocol.Error
		if errors.As(err, &verificationError) {
			return nil, appErrors.Wrap(appErrors.CodePasskeyRegistration, err, "passkey verification failed")
		}
		return nil, fmt.Errorf("failed to finish registration: %w", err)
	}

	return credential, nil
}

// BeginLogin starts the WebAuthn authentication process
func (p *WebAuthnProvider) BeginLogin(ctx context.Context, user AuthenticatorUser) (*protocol.CredentialAssertion, *webauthn.SessionData, string, error) {
	if user == nil {
		return nil, nil, "", appErrors.New(appErrors.CodeInvalidInput, "user cannot be nil")
	}

	p.logger.Info("Beginning WebAuthn login",
		logging.String("user_id", string(user.WebAuthnID())),
		logging.String("user_name", user.WebAuthnDisplayName()),
	)

	// Create credential assertion options
	options, sessionData, err := p.webAuthn.BeginLogin(user)
	if err != nil {
		return nil, nil, "", fmt.Errorf("failed to begin login: %w", err)
	}

	// Generate a session ID for this login
	sessionID := uuid.New().String()

	// Return the credential assertion options, session data, session ID, and nil error
	return options, sessionData, sessionID, nil
}

// FinishLogin completes the WebAuthn authentication process
func (p *WebAuthnProvider) FinishLogin(
	ctx context.Context,
	user AuthenticatorUser,
	sessionData *webauthn.SessionData,
	req *http.Request,
) (*webauthn.Credential, error) {
	if user == nil {
		return nil, appErrors.New(appErrors.CodeInvalidInput, "user cannot be nil")
	}
	if sessionData == nil {
		return nil, appErrors.New(appErrors.CodeInvalidInput, "session data cannot be nil")
	}
	if req == nil {
		return nil, appErrors.New(appErrors.CodeInvalidInput, "request cannot be nil")
	}

	p.logger.Info("Finishing WebAuthn login",
		logging.String("user_id", string(user.WebAuthnID())),
		logging.String("user_name", user.WebAuthnDisplayName()),
	)

	// Finish the login
	credential, err := p.webAuthn.FinishLogin(user, *sessionData, req)
	if err != nil {
		// Check for common error types
		var verificationError *protocol.Error
		if errors.As(err, &verificationError) {
			return nil, appErrors.Wrap(appErrors.CodePasskeyAuthentication, err, "passkey verification failed")
		}
		return nil, fmt.Errorf("failed to finish login: %w", err)
	}

	// Update authenticator information
	err = p.updateAuthenticatorInfo(ctx, user, credential)
	if err != nil {
		p.logger.Warn("Failed to update authenticator info",
			logging.String("user_id", string(user.WebAuthnID())),
			logging.Error(err),
		)
		// Continue, as this is not a critical error
	}

	return credential, nil
}

// updateAuthenticatorInfo updates the authenticator's information after a successful login
func (p *WebAuthnProvider) updateAuthenticatorInfo(
	ctx context.Context,
	user AuthenticatorUser,
	credential *webauthn.Credential,
) error {
	// Find the corresponding authenticator
	authenticator, err := user.WebAuthnCredentialForID(credential.ID)
	if err != nil {
		return fmt.Errorf("failed to find authenticator: %w", err)
	}

	// Update the sign count and last used time
	authenticator.Authenticator.SignCount = credential.Authenticator.SignCount
	authenticator.UpdatedAt = time.Now()
	authenticator.LastUsed = time.Now()

	return nil
}
