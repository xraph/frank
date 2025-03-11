package passkeys

import (
	"context"
	"encoding/base64"
	"fmt"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/juicycleff/frank/ent"
	"github.com/juicycleff/frank/ent/passkey"
)

// AuthenticatorUser defines the interface for a user that can use WebAuthn
type AuthenticatorUser interface {
	// WebAuthnID returns the user's unique identifier
	WebAuthnID() []byte

	// WebAuthnName returns the user's display name
	WebAuthnName() string

	// WebAuthnDisplayName returns the user's display name
	WebAuthnDisplayName() string

	// WebAuthnIcon returns the user's icon
	WebAuthnIcon() string

	// WebAuthnCredentials returns the user's passkeys
	WebAuthnCredentials() []webauthn.Credential

	// WebAuthnCredentialForID returns a specific passkey by ID
	WebAuthnCredentialForID(credentialID []byte) (*PasskeyCredential, error)
}

// PasskeyCredential represents a WebAuthn credential with additional metadata
type PasskeyCredential struct {
	*webauthn.Credential
	ID          string
	Name        string
	DeviceType  string
	UserID      string
	Active      bool
	CreatedAt   time.Time
	UpdatedAt   time.Time
	LastUsed    time.Time
	Transports  []string
	Attestation map[string]interface{}
}

// WebAuthnUser implements AuthenticatorUser for the User entity
type WebAuthnUser struct {
	ID         string
	Name       string
	Email      string
	Passkeys   []*ent.Passkey
	Icon       string
	DeviceType string
}

// WebAuthnID returns the user's unique identifier
func (u *WebAuthnUser) WebAuthnID() []byte {
	return []byte(u.ID)
}

// WebAuthnName returns the user's name
func (u *WebAuthnUser) WebAuthnName() string {
	return u.Email
}

// WebAuthnDisplayName returns the user's display name
func (u *WebAuthnUser) WebAuthnDisplayName() string {
	if u.Name != "" {
		return u.Name
	}
	return u.Email
}

// WebAuthnIcon returns the user's icon
func (u *WebAuthnUser) WebAuthnIcon() string {
	return u.Icon
}

// WebAuthnCredentials returns the user's WebAuthn credentials
func (u *WebAuthnUser) WebAuthnCredentials() []webauthn.Credential {
	credentials := make([]webauthn.Credential, len(u.Passkeys))

	for i, p := range u.Passkeys {
		if !p.Active {
			continue
		}

		// Decode the credential ID
		credentialID, err := base64.RawURLEncoding.DecodeString(p.CredentialID)
		if err != nil {
			continue
		}

		// Convert from ent.Passkey to webauthn.Credential
		credential := webauthn.Credential{
			ID:              credentialID,
			PublicKey:       p.PublicKey,
			AttestationType: "none", // Default value if not stored
			Authenticator: webauthn.Authenticator{
				AAGUID:    []byte(p.Aaguid),
				SignCount: uint32(p.SignCount),
			},
		}

		// Add to credentials list
		credentials[i] = credential
	}

	return credentials
}

// WebAuthnCredentialForID returns a specific WebAuthn credential by ID
func (u *WebAuthnUser) WebAuthnCredentialForID(credentialID []byte) (*PasskeyCredential, error) {
	credIDStr := base64.RawURLEncoding.EncodeToString(credentialID)

	for _, p := range u.Passkeys {
		if p.CredentialID == credIDStr {
			// Convert credential ID to byte array
			cID, err := base64.RawURLEncoding.DecodeString(p.CredentialID)
			if err != nil {
				return nil, fmt.Errorf("failed to decode credential ID: %w", err)
			}

			// Create PasskeyCredential
			credential := &PasskeyCredential{
				Credential: &webauthn.Credential{
					ID:        cID,
					PublicKey: p.PublicKey,
					Authenticator: webauthn.Authenticator{
						AAGUID:    []byte(p.Aaguid),
						SignCount: uint32(p.SignCount),
					},
				},
				ID:         p.ID,
				Name:       p.Name,
				DeviceType: p.DeviceType,
				UserID:     p.UserID,
				Active:     p.Active,
				CreatedAt:  p.CreatedAt,
				UpdatedAt:  p.UpdatedAt,
				LastUsed:   *p.LastUsed,
			}

			// Handle transports and attestation if they exist
			if len(p.Transports) > 0 {
				credential.Transports = p.Transports
			}

			if len(p.Attestation) > 0 {
				credential.Attestation = p.Attestation
			}

			return credential, nil
		}
	}

	return nil, fmt.Errorf("credential not found for ID: %s", credIDStr)
}

// NewWebAuthnUser creates a new WebAuthnUser from an ent.User and its passkeys
func NewWebAuthnUser(user *ent.User, passkeys []*ent.Passkey) *WebAuthnUser {
	var name string
	if user.FirstName != "" && user.LastName != "" {
		name = user.FirstName + " " + user.LastName
	} else if user.FirstName != "" {
		name = user.FirstName
	} else {
		name = user.Email
	}

	return &WebAuthnUser{
		ID:       user.ID,
		Name:     name,
		Email:    user.Email,
		Passkeys: passkeys,
		Icon:     user.ProfileImageURL,
	}
}

// GetActivePasskeysByUserID retrieves active passkeys for a user from the database
func GetActivePasskeysByUserID(ctx context.Context, client *ent.Client, userID string) ([]*ent.Passkey, error) {
	return client.Passkey.
		Query().
		Where(
			passkey.UserID(userID),
			passkey.Active(true),
		).
		All(ctx)
}

// CreatePasskeyFromCredential creates a new passkey record from a WebAuthn credential
func CreatePasskeyFromCredential(
	ctx context.Context,
	client *ent.Client,
	userID string,
	credential *webauthn.Credential,
	name string,
	deviceType string,
) (*ent.Passkey, error) {
	// Encode credential ID as string
	credentialIDStr := base64.RawURLEncoding.EncodeToString(credential.ID)

	// Get transports as array
	transports := make([]string, len(credential.Transport))
	for i, t := range credential.Transport {
		transports[i] = string(t)
	}

	// Create new passkey
	return client.Passkey.
		Create().
		SetUserID(userID).
		SetCredentialID(credentialIDStr).
		SetPublicKey(credential.PublicKey).
		SetSignCount(int(credential.Authenticator.SignCount)).
		SetName(name).
		SetDeviceType(deviceType).
		SetAaguid(string(credential.Authenticator.AAGUID)).
		SetActive(true).
		SetTransports(transports).
		// SetDeviceType()
		// SetAttestationType(credential.AttestationType).
		Save(ctx)
}

// UpdatePasskeyAfterLogin updates a passkey after successful authentication
func UpdatePasskeyAfterLogin(
	ctx context.Context,
	client *ent.Client,
	passkeyID string,
	signCount int,
) error {
	_, err := client.Passkey.
		UpdateOneID(passkeyID).
		SetSignCount(signCount).
		SetLastUsed(time.Now()).
		Save(ctx)

	return err
}

// Transports converts protocol.AuthenticatorTransport to string slice
func Transports(ts []protocol.AuthenticatorTransport) []string {
	result := make([]string, len(ts))
	for i, t := range ts {
		result[i] = string(t)
	}
	return result
}
