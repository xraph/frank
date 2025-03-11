package sso

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/juicycleff/frank/config"
	"github.com/juicycleff/frank/ent"
	"github.com/juicycleff/frank/ent/identityprovider"
	"github.com/juicycleff/frank/ent/organization"
	"github.com/juicycleff/frank/ent/user"
	"github.com/juicycleff/frank/pkg/crypto"
	"github.com/juicycleff/frank/pkg/errors"
	"github.com/juicycleff/frank/pkg/logging"
)

// Service defines the interface for SSO functionality
type Service interface {
	Initialize(ctx context.Context) error
	InitiateSSO(ctx context.Context, providerID, redirectURI string, options map[string]interface{}) (string, error)
	CompleteSSO(ctx context.Context, state, code string) (*UserInfo, error)
	FindOrCreateUser(ctx context.Context, userInfo *UserInfo) (*ent.User, error)
	GetProviders(ctx context.Context, organizationID string) ([]*ent.IdentityProvider, error)
	GetProvider(ctx context.Context, providerID string) (*ent.IdentityProvider, error)
	ValidateAndRefreshToken(ctx context.Context, token, providerID string) (*UserInfo, error)
	CreateIdentityProvider(ctx context.Context, input *IdentityProviderInput, organizationID string) (*ent.IdentityProvider, error)
	UpdateIdentityProvider(ctx context.Context, providerID string, input *IdentityProviderInput) (*ent.IdentityProvider, error)
	DeleteIdentityProvider(ctx context.Context, providerID string) error
}

// service is the implementation of Service
type serviceImpl struct {
	client     *ent.Client
	config     *config.Config
	logger     logging.Logger
	providers  map[string]IdentityProvider
	stateStore StateStore
}

// StateStore is an interface for storing SSO state
type StateStore interface {
	StoreState(ctx context.Context, state string, data *StateData, expiry time.Duration) error
	GetState(ctx context.Context, state string) (*StateData, error)
	DeleteState(ctx context.Context, state string) error
}

// StateData contains information associated with an SSO state
type StateData struct {
	ProviderID       string
	OrganizationID   string
	RedirectURI      string
	Nonce            string
	PKCECodeVerifier string
	Options          map[string]interface{}
}

// New creates a new SSO service
func New(client *ent.Client, stateStore StateStore, cfg *config.Config, logger logging.Logger) Service {
	return &serviceImpl{
		client:     client,
		config:     cfg,
		logger:     logger,
		providers:  make(map[string]IdentityProvider),
		stateStore: stateStore,
	}
}

// Initialize loads and initializes all configured SSO providers
func (s *serviceImpl) Initialize(ctx context.Context) error {
	// Load all identity providers from the database
	providers, err := s.client.IdentityProvider.Query().
		Where(identityprovider.Active(true)).
		All(ctx)

	if err != nil {
		return errors.Wrap(errors.CodeDatabaseError, err, "failed to load identity providers")
	}

	s.logger.Info("Initializing SSO service", logging.Int("provider_count", len(providers)))

	// Initialize each provider
	for _, providerEntity := range providers {
		provider, err := CreateIdentityProvider(providerEntity)
		if err != nil {
			s.logger.Error("Failed to initialize identity provider",
				logging.String("provider_id", providerEntity.ID),
				logging.String("provider_name", providerEntity.Name),
				logging.Error(err),
			)
			continue
		}

		s.providers[providerEntity.ID] = provider
		s.logger.Info("Initialized identity provider",
			logging.String("provider_id", providerEntity.ID),
			logging.String("provider_name", providerEntity.Name),
			logging.String("provider_type", provider.GetType()),
		)
	}

	return nil
}

// InitiateSSO initiates SSO authentication with a provider
func (s *serviceImpl) InitiateSSO(ctx context.Context, providerID, redirectURI string, options map[string]interface{}) (string, error) {
	// Get the provider
	provider, err := s.getProvider(ctx, providerID)
	if err != nil {
		return "", err
	}

	// Generate state for security
	state, err := crypto.GenerateRandomString(32)
	if err != nil {
		return "", errors.Wrap(errors.CodeCryptoError, err, "failed to generate state")
	}

	// Generate nonce for OIDC
	nonce, err := crypto.GenerateRandomString(32)
	if err != nil {
		return "", errors.Wrap(errors.CodeCryptoError, err, "failed to generate nonce")
	}

	// Store state data
	stateData := &StateData{
		ProviderID:  providerID,
		RedirectURI: redirectURI,
		Nonce:       nonce,
		Options:     options,
	}

	// Get provider configuration
	providerConfig := provider.GetConfig()
	if providerConfig.OrganizationID != "" {
		stateData.OrganizationID = providerConfig.OrganizationID
	}

	// Store state with expiration
	if err := s.stateStore.StoreState(ctx, state, stateData, 15*time.Minute); err != nil {
		return "", errors.Wrap(errors.CodeStorageError, err, "failed to store state")
	}

	// Add nonce to options for OIDC
	if provider.GetType() == "oidc" {
		if options == nil {
			options = make(map[string]interface{})
		}
		options["nonce"] = nonce
	}

	// Get auth URL from provider
	authURL, err := provider.GetAuthURL(state, options)
	if err != nil {
		return "", err
	}

	return authURL, nil
}

// CompleteSSO completes the SSO flow and returns user information
func (s *serviceImpl) CompleteSSO(ctx context.Context, state, code string) (*UserInfo, error) {
	// Validate state and get stored data
	stateData, err := s.stateStore.GetState(ctx, state)
	if err != nil {
		return nil, errors.Wrap(errors.CodeInvalidOAuthState, err, "invalid or expired state")
	}

	// Delete the state to prevent replay attacks
	defer s.stateStore.DeleteState(ctx, state)

	// Get the provider
	provider, err := s.getProvider(ctx, stateData.ProviderID)
	if err != nil {
		return nil, err
	}

	// Complete the SSO flow
	userInfo, err := provider.ExchangeCode(ctx, code, state)
	if err != nil {
		return nil, err
	}

	// Set organization ID from state if not set in user info
	if userInfo.OrganizationID == "" && stateData.OrganizationID != "" {
		userInfo.OrganizationID = stateData.OrganizationID
	}

	return userInfo, nil
}

// FindOrCreateUser finds or creates a user based on SSO user information
func (s *serviceImpl) FindOrCreateUser(ctx context.Context, userInfo *UserInfo) (*ent.User, error) {
	// Try to find user by email
	existingUser, err := s.client.User.Query().
		Where(user.Email(userInfo.Email)).
		Only(ctx)

	if err != nil && !ent.IsNotFound(err) {
		return nil, errors.Wrap(errors.CodeDatabaseError, err, "failed to query user")
	}

	// If user exists, update their information
	if existingUser != nil {
		// Update user information
		updateQuery := existingUser.Update()

		if userInfo.Name != "" {
			// Parse full name into first and last name if not provided
			if userInfo.FirstName == "" || userInfo.LastName == "" {
				names := splitName(userInfo.Name)
				if userInfo.FirstName == "" {
					updateQuery = updateQuery.SetFirstName(names.First)
				}
				if userInfo.LastName == "" {
					updateQuery = updateQuery.SetLastName(names.Last)
				}
			} else {
				updateQuery = updateQuery.
					SetFirstName(userInfo.FirstName).
					SetLastName(userInfo.LastName)
			}
		}

		if userInfo.ProfilePicture != "" {
			updateQuery = updateQuery.SetProfileImageURL(userInfo.ProfilePicture)
		}

		if userInfo.Locale != "" {
			updateQuery = updateQuery.SetLocale(userInfo.Locale)
		}

		// Set email verified if it's verified by the provider
		if userInfo.EmailVerified {
			updateQuery = updateQuery.SetEmailVerified(true)
		}

		// Update metadata
		metadata := existingUser.Metadata
		if metadata == nil {
			metadata = make(map[string]interface{})
		}

		// Store provider information in metadata
		providerKey := fmt.Sprintf("sso_%s", userInfo.ProviderType)
		metadata[providerKey] = map[string]interface{}{
			"id":            userInfo.ID,
			"provider_name": userInfo.ProviderName,
			"provider_type": userInfo.ProviderType,
			"last_login":    time.Now().Format(time.RFC3339),
		}

		updateQuery = updateQuery.SetMetadata(metadata)

		// Update last login time
		updateQuery = updateQuery.SetLastLogin(time.Now())

		// Save updates
		updatedUser, err := updateQuery.Save(ctx)
		if err != nil {
			return nil, errors.Wrap(errors.CodeDatabaseError, err, "failed to update user")
		}

		// Ensure user is connected to the organization if specified
		if userInfo.OrganizationID != "" {
			if err := s.ensureUserInOrganization(ctx, updatedUser.ID, userInfo.OrganizationID); err != nil {
				s.logger.Error("Failed to add user to organization",
					logging.String("user_id", updatedUser.ID),
					logging.String("org_id", userInfo.OrganizationID),
					logging.Error(err),
				)
				// Continue anyway, don't fail the login
			}
		}

		return updatedUser, nil
	}

	// User doesn't exist, create a new user
	names := splitName(userInfo.Name)
	firstName := userInfo.FirstName
	lastName := userInfo.LastName

	if firstName == "" {
		firstName = names.First
	}

	if lastName == "" {
		lastName = names.Last
	}

	// Create metadata with provider information
	metadata := map[string]interface{}{
		fmt.Sprintf("sso_%s", userInfo.ProviderType): map[string]interface{}{
			"id":            userInfo.ID,
			"provider_name": userInfo.ProviderName,
			"provider_type": userInfo.ProviderType,
			"last_login":    time.Now().Format(time.RFC3339),
		},
	}

	// Create the user
	createQuery := s.client.User.Create().
		SetEmail(userInfo.Email).
		SetFirstName(firstName).
		SetLastName(lastName).
		SetEmailVerified(userInfo.EmailVerified).
		SetActive(true).
		SetLastLogin(time.Now()).
		SetMetadata(metadata)

	if userInfo.ProfilePicture != "" {
		createQuery = createQuery.SetProfileImageURL(userInfo.ProfilePicture)
	}

	if userInfo.Locale != "" {
		createQuery = createQuery.SetLocale(userInfo.Locale)
	}

	newUser, err := createQuery.Save(ctx)
	if err != nil {
		return nil, errors.Wrap(errors.CodeDatabaseError, err, "failed to create user")
	}

	// Add user to organization if specified
	if userInfo.OrganizationID != "" {
		if err := s.ensureUserInOrganization(ctx, newUser.ID, userInfo.OrganizationID); err != nil {
			s.logger.Error("Failed to add new user to organization",
				logging.String("user_id", newUser.ID),
				logging.String("org_id", userInfo.OrganizationID),
				logging.Error(err),
			)
			// Continue anyway, don't fail the user creation
		}
	}

	return newUser, nil
}

// GetProviders returns all available identity providers
func (s *serviceImpl) GetProviders(ctx context.Context, organizationID string) ([]*ent.IdentityProvider, error) {
	query := s.client.IdentityProvider.Query().
		Where(identityprovider.Active(true))

	if organizationID != "" {
		query = query.Where(identityprovider.OrganizationID(organizationID))
	}

	providers, err := query.All(ctx)
	if err != nil {
		return nil, errors.Wrap(errors.CodeDatabaseError, err, "failed to query identity providers")
	}

	return providers, nil
}

// GetProvider returns a specific identity provider
func (s *serviceImpl) GetProvider(ctx context.Context, providerID string) (*ent.IdentityProvider, error) {
	provider, err := s.client.IdentityProvider.Query().
		Where(identityprovider.ID(providerID), identityprovider.Active(true)).
		Only(ctx)

	if err != nil {
		if ent.IsNotFound(err) {
			return nil, errors.New(errors.CodeNotFound, "identity provider not found")
		}
		return nil, errors.Wrap(errors.CodeDatabaseError, err, "failed to query identity provider")
	}

	return provider, nil
}

// ValidateAndRefreshToken validates an SSO token and refreshes it if necessary
func (s *serviceImpl) ValidateAndRefreshToken(ctx context.Context, token, providerID string) (*UserInfo, error) {
	// Get the provider
	provider, err := s.getProvider(ctx, providerID)
	if err != nil {
		return nil, err
	}

	// Validate the token
	userInfo, err := provider.ValidateToken(ctx, token)
	if err != nil {
		return nil, err
	}

	return userInfo, nil
}

// CreateIdentityProvider creates a new identity provider
func (s *serviceImpl) CreateIdentityProvider(ctx context.Context, input *IdentityProviderInput, organizationID string) (*ent.IdentityProvider, error) {
	// Check if provider with same name already exists for the organization
	exists, err := s.client.IdentityProvider.Query().
		Where(
			identityprovider.Name(input.Name),
			identityprovider.OrganizationID(organizationID),
		).
		Exist(ctx)

	if err != nil {
		return nil, errors.Wrap(errors.CodeDatabaseError, err, "failed to check for existing provider")
	}

	if exists {
		return nil, errors.New(errors.CodeAlreadyExists, "identity provider with the same name already exists")
	}

	// Verify that the organization exists
	orgExists, err := s.client.Organization.Query().
		Where(organization.ID(organizationID)).
		Exist(ctx)

	if err != nil {
		return nil, errors.Wrap(errors.CodeDatabaseError, err, "failed to check organization")
	}

	if !orgExists {
		return nil, errors.New(errors.CodeNotFound, "organization not found")
	}

	// Create the provider
	createQuery := s.client.IdentityProvider.Create().
		SetName(input.Name).
		SetOrganizationID(organizationID).
		SetProviderType(input.ProviderType).
		SetActive(true)

	// Set optional fields
	if input.ClientID != "" {
		createQuery = createQuery.SetClientID(input.ClientID)
	}

	if input.ClientSecret != "" {
		createQuery = createQuery.SetClientSecret(input.ClientSecret)
	}

	if input.Issuer != "" {
		createQuery = createQuery.SetIssuer(input.Issuer)
	}

	if input.MetadataURL != "" {
		createQuery = createQuery.SetMetadataURL(input.MetadataURL)
	}

	if input.AuthorizationEndpoint != "" {
		createQuery = createQuery.SetAuthorizationEndpoint(input.AuthorizationEndpoint)
	}

	if input.TokenEndpoint != "" {
		createQuery = createQuery.SetTokenEndpoint(input.TokenEndpoint)
	}

	if input.UserinfoEndpoint != "" {
		createQuery = createQuery.SetUserinfoEndpoint(input.UserinfoEndpoint)
	}

	if input.JwksURI != "" {
		createQuery = createQuery.SetJwksURI(input.JwksURI)
	}

	if input.Certificate != "" {
		createQuery = createQuery.SetCertificate(input.Certificate)
	}

	if input.PrivateKey != "" {
		createQuery = createQuery.SetPrivateKey(input.PrivateKey)
	}

	if len(input.Domains) > 0 {
		createQuery = createQuery.SetDomains(input.Domains)
	}

	if input.AttributesMapping != nil {
		createQuery = createQuery.SetAttributesMapping(input.AttributesMapping)
	}

	if input.Metadata != nil {
		createQuery = createQuery.SetMetadata(input.Metadata)
	}

	provider, err := createQuery.Save(ctx)
	if err != nil {
		return nil, errors.Wrap(errors.CodeDatabaseError, err, "failed to create identity provider")
	}

	// Initialize the provider
	newProvider, err := CreateIdentityProvider(provider)
	if err != nil {
		s.logger.Error("Failed to initialize new identity provider",
			logging.String("provider_id", provider.ID),
			logging.Error(err),
		)
	} else {
		// Add to active providers
		s.providers[provider.ID] = newProvider
	}

	return provider, nil
}

// UpdateIdentityProvider updates an existing identity provider
func (s *serviceImpl) UpdateIdentityProvider(ctx context.Context, providerID string, input *IdentityProviderInput) (*ent.IdentityProvider, error) {
	// Get the provider
	provider, err := s.client.IdentityProvider.Query().
		Where(identityprovider.ID(providerID)).
		Only(ctx)

	if err != nil {
		if ent.IsNotFound(err) {
			return nil, errors.New(errors.CodeNotFound, "identity provider not found")
		}
		return nil, errors.Wrap(errors.CodeDatabaseError, err, "failed to query identity provider")
	}

	// Check name uniqueness if changing the name
	if input.Name != "" && input.Name != provider.Name {
		exists, err := s.client.IdentityProvider.Query().
			Where(
				identityprovider.Name(input.Name),
				identityprovider.OrganizationID(provider.OrganizationID),
				identityprovider.IDNEQ(providerID),
			).
			Exist(ctx)

		if err != nil {
			return nil, errors.Wrap(errors.CodeDatabaseError, err, "failed to check for existing provider")
		}

		if exists {
			return nil, errors.New(errors.CodeAlreadyExists, "identity provider with the same name already exists")
		}
	}

	// Update the provider
	updateQuery := s.client.IdentityProvider.UpdateOneID(providerID)

	if input.Name != "" {
		updateQuery = updateQuery.SetName(input.Name)
	}

	if input.ProviderType != "" && input.ProviderType != provider.ProviderType {
		// Cannot change provider type if it's already in use
		// You would need to check if users are using this provider
		updateQuery = updateQuery.SetProviderType(input.ProviderType)
	}

	if input.ClientID != "" {
		updateQuery = updateQuery.SetClientID(input.ClientID)
	}

	if input.ClientSecret != "" {
		updateQuery = updateQuery.SetClientSecret(input.ClientSecret)
	}

	if input.Issuer != "" {
		updateQuery = updateQuery.SetIssuer(input.Issuer)
	}

	if input.MetadataURL != "" {
		updateQuery = updateQuery.SetMetadataURL(input.MetadataURL)
	}

	if input.AuthorizationEndpoint != "" {
		updateQuery = updateQuery.SetAuthorizationEndpoint(input.AuthorizationEndpoint)
	}

	if input.TokenEndpoint != "" {
		updateQuery = updateQuery.SetTokenEndpoint(input.TokenEndpoint)
	}

	if input.UserinfoEndpoint != "" {
		updateQuery = updateQuery.SetUserinfoEndpoint(input.UserinfoEndpoint)
	}

	if input.JwksURI != "" {
		updateQuery = updateQuery.SetJwksURI(input.JwksURI)
	}

	if input.Certificate != "" {
		updateQuery = updateQuery.SetCertificate(input.Certificate)
	}

	if input.PrivateKey != "" {
		updateQuery = updateQuery.SetPrivateKey(input.PrivateKey)
	}

	if len(input.Domains) > 0 {
		updateQuery = updateQuery.SetDomains(input.Domains)
	}

	if input.AttributesMapping != nil {
		updateQuery = updateQuery.SetAttributesMapping(input.AttributesMapping)
	}

	if input.Metadata != nil {
		updateQuery = updateQuery.SetMetadata(input.Metadata)
	}

	// Update active status if provided
	if input.Active != nil {
		updateQuery = updateQuery.SetActive(*input.Active)
	}

	updatedProvider, err := updateQuery.Save(ctx)
	if err != nil {
		return nil, errors.Wrap(errors.CodeDatabaseError, err, "failed to update identity provider")
	}

	// Re-initialize the provider
	delete(s.providers, providerID)

	// Only initialize if the provider is active
	if updatedProvider.Active {
		newProvider, err := CreateIdentityProvider(updatedProvider)
		if err != nil {
			s.logger.Error("Failed to re-initialize identity provider",
				logging.String("provider_id", updatedProvider.ID),
				logging.Error(err),
			)
		} else {
			s.providers[updatedProvider.ID] = newProvider
		}
	}

	return updatedProvider, nil
}

// DeleteIdentityProvider deletes an identity provider
func (s *serviceImpl) DeleteIdentityProvider(ctx context.Context, providerID string) error {
	// Check if provider exists
	exists, err := s.client.IdentityProvider.Query().
		Where(identityprovider.ID(providerID)).
		Exist(ctx)

	if err != nil {
		return errors.Wrap(errors.CodeDatabaseError, err, "failed to check for provider")
	}

	if !exists {
		return errors.New(errors.CodeNotFound, "identity provider not found")
	}

	// Delete the provider
	if err := s.client.IdentityProvider.DeleteOneID(providerID).Exec(ctx); err != nil {
		return errors.Wrap(errors.CodeDatabaseError, err, "failed to delete identity provider")
	}

	// Remove from active providers
	delete(s.providers, providerID)

	return nil
}

// getProvider retrieves an IdentityProvider by ID
func (s *serviceImpl) getProvider(ctx context.Context, providerID string) (IdentityProvider, error) {
	// Check if the provider is already initialized
	if provider, ok := s.providers[providerID]; ok {
		return provider, nil
	}

	// Provider not initialized, load it from the database
	providerEntity, err := s.client.IdentityProvider.Query().
		Where(identityprovider.ID(providerID), identityprovider.Active(true)).
		Only(ctx)

	if err != nil {
		if ent.IsNotFound(err) {
			return nil, errors.New(errors.CodeNotFound, "identity provider not found")
		}
		return nil, errors.Wrap(errors.CodeDatabaseError, err, "failed to query identity provider")
	}

	// Create the provider
	provider, err := CreateIdentityProvider(providerEntity)
	if err != nil {
		return nil, err
	}

	// Cache the provider for future use
	s.providers[providerID] = provider

	return provider, nil
}

// ensureUserInOrganization ensures that a user is a member of an organization
func (s *serviceImpl) ensureUserInOrganization(ctx context.Context, userID, organizationID string) error {
	// Check if the organization exists
	org, err := s.client.Organization.Query().
		Where(organization.ID(organizationID)).
		Only(ctx)

	if err != nil {
		if ent.IsNotFound(err) {
			return errors.New(errors.CodeNotFound, "organization not found")
		}
		return errors.Wrap(errors.CodeDatabaseError, err, "failed to query organization")
	}

	// Check if user is already in the organization
	isMember, err := s.client.User.Query().
		Where(user.ID(userID)).
		QueryOrganizations().
		Where(organization.ID(organizationID)).
		Exist(ctx)

	if err != nil {
		return errors.Wrap(errors.CodeDatabaseError, err, "failed to check organization membership")
	}

	// If already a member, nothing to do
	if isMember {
		return nil
	}

	// Add user to organization
	_, err = s.client.Organization.UpdateOne(org).
		AddUserIDs(userID).
		Save(ctx)

	if err != nil {
		return errors.Wrap(errors.CodeDatabaseError, err, "failed to add user to organization")
	}

	// If this is the user's first organization, set it as primary
	userEntity, err := s.client.User.Query().
		Where(user.ID(userID)).
		Only(ctx)

	if err != nil {
		return errors.Wrap(errors.CodeDatabaseError, err, "failed to query user")
	}

	if userEntity.PrimaryOrganizationID == "" {
		_, err = s.client.User.UpdateOne(userEntity).
			SetPrimaryOrganizationID(organizationID).
			Save(ctx)

		if err != nil {
			return errors.Wrap(errors.CodeDatabaseError, err, "failed to set primary organization")
		}
	}

	return nil
}

// NameParts contains the parts of a person's name
type NameParts struct {
	First string
	Last  string
}

// splitName splits a full name into first and last name
func splitName(fullName string) NameParts {
	if fullName == "" {
		return NameParts{}
	}

	// Split by spaces
	names := strings.Fields(fullName)

	if len(names) == 1 {
		// Only one name, treat as first name
		return NameParts{
			First: names[0],
			Last:  "",
		}
	}

	// First name is the first component, last name is everything else
	firstName := names[0]
	lastName := strings.Join(names[1:], " ")

	return NameParts{
		First: firstName,
		Last:  lastName,
	}
}

// Default error types
var (
	ErrUnsupportedProviderType = errors.New(errors.CodeInvalidInput, "unsupported identity provider type")
	ErrInvalidConfiguration    = errors.New(errors.CodeConfigurationError, "invalid provider configuration")
	ErrAuthenticationFailed    = errors.New(errors.CodeOAuthFailed, "authentication failed")
	ErrInvalidState            = errors.New(errors.CodeInvalidOAuthState, "invalid or expired state")
)

// IdentityProviderInput represents input for creating or updating an identity provider
type IdentityProviderInput struct {
	Name                  string                 `json:"name"`
	ProviderType          string                 `json:"provider_type"`
	ClientID              string                 `json:"client_id,omitempty"`
	ClientSecret          string                 `json:"client_secret,omitempty"`
	Issuer                string                 `json:"issuer,omitempty"`
	MetadataURL           string                 `json:"metadata_url,omitempty"`
	AuthorizationEndpoint string                 `json:"authorization_endpoint,omitempty"`
	TokenEndpoint         string                 `json:"token_endpoint,omitempty"`
	UserinfoEndpoint      string                 `json:"userinfo_endpoint,omitempty"`
	JwksURI               string                 `json:"jwks_uri,omitempty"`
	Certificate           string                 `json:"certificate,omitempty"`
	PrivateKey            string                 `json:"private_key,omitempty"`
	Domains               []string               `json:"domains,omitempty"`
	AttributesMapping     map[string]string      `json:"attributes_mapping,omitempty"`
	Metadata              map[string]interface{} `json:"metadata,omitempty"`
	Active                *bool                  `json:"active,omitempty"`
}
