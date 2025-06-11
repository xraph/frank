package user

import (
	"context"
	"strings"

	"github.com/juicycleff/frank/ent"
	"github.com/juicycleff/frank/ent/user"
	"github.com/juicycleff/frank/internal/model"
	"github.com/juicycleff/frank/internal/repository"
	"github.com/juicycleff/frank/pkg/errors"
	"github.com/juicycleff/frank/pkg/logging"
	"github.com/rs/xid"
)

// ProfileService defines the user profile service interface
type ProfileService interface {
	// Profile management
	UpdateProfile(ctx context.Context, userID xid.ID, req model.UserProfileUpdateRequest) (*model.User, error)
	GetProfile(ctx context.Context, userID xid.ID) (*model.User, error)
	UpdateProfileImage(ctx context.Context, userID xid.ID, imageURL string) (*model.User, error)
	RemoveProfileImage(ctx context.Context, userID xid.ID) (*model.User, error)

	// Custom attributes management
	SetCustomAttribute(ctx context.Context, userID xid.ID, key string, value interface{}) error
	GetCustomAttribute(ctx context.Context, userID xid.ID, key string) (interface{}, error)
	RemoveCustomAttribute(ctx context.Context, userID xid.ID, key string) error
	ListCustomAttributes(ctx context.Context, userID xid.ID) (map[string]interface{}, error)
	UpdateCustomAttributes(ctx context.Context, userID xid.ID, attributes map[string]interface{}) error

	// Contact information management
	UpdateContactInfo(ctx context.Context, userID xid.ID, email, phoneNumber string) (*model.User, error)
	UpdateEmail(ctx context.Context, userID xid.ID, newEmail string) (string, error)             // Returns verification token
	UpdatePhoneNumber(ctx context.Context, userID xid.ID, newPhoneNumber string) (string, error) // Returns verification token
	ConfirmEmailUpdate(ctx context.Context, token string) (*model.User, error)
	ConfirmPhoneUpdate(ctx context.Context, token string) (*model.User, error)

	// Localization settings
	UpdateLocalization(ctx context.Context, userID xid.ID, locale, timezone string) (*model.User, error)
	GetSupportedLocales(ctx context.Context) ([]string, error)
	GetSupportedTimezones(ctx context.Context) ([]string, error)

	// Profile validation
	ValidateProfileData(ctx context.Context, req model.UserProfileUpdateRequest) error
	ValidateCustomAttribute(ctx context.Context, key string, value interface{}) error

	// Profile completion and analytics
	GetProfileCompletionScore(ctx context.Context, userID xid.ID) (*ProfileCompletion, error)
	GetProfileActivity(ctx context.Context, userID xid.ID, days int) (*ProfileActivity, error)
	GetProfileSuggestions(ctx context.Context, userID xid.ID) ([]ProfileSuggestion, error)
}

// profileService implements the ProfileService interface
type profileService struct {
	userRepo         repository.UserRepository
	verificationRepo repository.VerificationRepository
	auditRepo        repository.AuditRepository
	logger           logging.Logger
}

// NewProfileService creates a new profile service instance
func NewProfileService(
	userRepo repository.UserRepository,
	verificationRepo repository.VerificationRepository,
	auditRepo repository.AuditRepository,
	logger logging.Logger,
) ProfileService {
	return &profileService{
		userRepo:         userRepo,
		verificationRepo: verificationRepo,
		auditRepo:        auditRepo,
		logger:           logger,
	}
}

// UpdateProfile updates a user's profile information
func (s *profileService) UpdateProfile(ctx context.Context, userID xid.ID, req model.UserProfileUpdateRequest) (*model.User, error) {
	s.logger.Info("Updating user profile", logging.String("user_id", userID.String()))

	// Validate profile data
	if err := s.ValidateProfileData(ctx, req); err != nil {
		return nil, err
	}

	// Get existing user
	existingUser, err := s.userRepo.GetByID(ctx, userID)
	if err != nil {
		if ent.IsNotFound(err) {
			return nil, errors.New(errors.CodeNotFound, "user not found")
		}
		return nil, errors.Wrap(err, errors.CodeInternalServer, "failed to get user")
	}

	// Track changes for audit log
	changes := make(map[string]interface{})

	// Create update input
	input := repository.UpdateUserInput{}

	if req.FirstName != "" && req.FirstName != existingUser.FirstName {
		input.FirstName = &req.FirstName
		changes["first_name"] = map[string]interface{}{
			"old": existingUser.FirstName,
			"new": req.FirstName,
		}
	}

	if req.LastName != "" && req.LastName != existingUser.LastName {
		input.LastName = &req.LastName
		changes["last_name"] = map[string]interface{}{
			"old": existingUser.LastName,
			"new": req.LastName,
		}
	}

	if req.Username != "" && req.Username != existingUser.Username {
		// Validate username uniqueness
		if err := s.validateUsernameUniqueness(ctx, req.Username, existingUser.UserType, &existingUser.OrganizationID, &userID); err != nil {
			return nil, err
		}
		input.Username = &req.Username
		changes["username"] = map[string]interface{}{
			"old": existingUser.Username,
			"new": req.Username,
		}
	}

	if req.ProfileImageURL != "" && req.ProfileImageURL != existingUser.ProfileImageURL {
		input.ProfileImageURL = &req.ProfileImageURL
		changes["profile_image_url"] = map[string]interface{}{
			"old": existingUser.ProfileImageURL,
			"new": req.ProfileImageURL,
		}
	}

	if req.Locale != "" && req.Locale != existingUser.Locale {
		if err := s.validateLocale(req.Locale); err != nil {
			return nil, err
		}
		input.Locale = &req.Locale
		changes["locale"] = map[string]interface{}{
			"old": existingUser.Locale,
			"new": req.Locale,
		}
	}

	if req.Timezone != "" && req.Timezone != existingUser.Timezone {
		if err := s.validateTimezone(req.Timezone); err != nil {
			return nil, err
		}
		input.Timezone = &req.Timezone
		changes["timezone"] = map[string]interface{}{
			"old": existingUser.Timezone,
			"new": req.Timezone,
		}
	}

	if req.CustomAttributes != nil {
		// Merge with existing custom attributes
		mergedAttributes := make(map[string]interface{})
		if existingUser.CustomAttributes != nil {
			for k, v := range existingUser.CustomAttributes {
				mergedAttributes[k] = v
			}
		}
		for k, v := range req.CustomAttributes {
			if err := s.ValidateCustomAttribute(ctx, k, v); err != nil {
				return nil, err
			}
			mergedAttributes[k] = v
		}
		input.CustomAttributes = mergedAttributes
		changes["custom_attributes"] = map[string]interface{}{
			"old": existingUser.CustomAttributes,
			"new": mergedAttributes,
		}
	}

	// Update user if there are changes
	if len(changes) == 0 {
		return s.convertEntUserToModel(existingUser), nil
	}

	updatedUser, err := s.userRepo.Update(ctx, userID, input)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeInternalServer, "failed to update user profile")
	}

	// Create audit log
	s.createAuditLog(ctx, &model.CreateAuditLogRequest{
		UserID:         &userID,
		Action:         "user.profile_updated",
		Resource:       "user",
		ResourceID:     &userID,
		Status:         "success",
		OrganizationID: &updatedUser.OrganizationID,
		Changes:        changes,
		Details: map[string]interface{}{
			"updated_fields": s.getUpdatedFieldsList(changes),
		},
	})

	s.logger.Info("User profile updated successfully",
		logging.String("user_id", userID.String()),
		logging.Int("fields_updated", len(changes)))

	return s.convertEntUserToModel(updatedUser), nil
}

// GetProfile retrieves a user's profile
func (s *profileService) GetProfile(ctx context.Context, userID xid.ID) (*model.User, error) {
	entUser, err := s.userRepo.GetByID(ctx, userID)
	if err != nil {
		if ent.IsNotFound(err) {
			return nil, errors.New(errors.CodeNotFound, "user not found")
		}
		return nil, errors.Wrap(err, errors.CodeInternalServer, "failed to get user profile")
	}

	return s.convertEntUserToModel(entUser), nil
}

// UpdateProfileImage updates a user's profile image
func (s *profileService) UpdateProfileImage(ctx context.Context, userID xid.ID, imageURL string) (*model.User, error) {
	if imageURL == "" {
		return nil, errors.New(errors.CodeBadRequest, "image URL is required")
	}

	// Validate image URL format
	if err := s.validateImageURL(imageURL); err != nil {
		return nil, err
	}

	// Get existing user
	existingUser, err := s.userRepo.GetByID(ctx, userID)
	if err != nil {
		if ent.IsNotFound(err) {
			return nil, errors.New(errors.CodeNotFound, "user not found")
		}
		return nil, errors.Wrap(err, errors.CodeInternalServer, "failed to get user")
	}

	// Update profile image
	input := repository.UpdateUserInput{
		UpdateUserRequest: model.UpdateUserRequest{
			ProfileImageURL: &imageURL,
		},
	}

	updatedUser, err := s.userRepo.Update(ctx, userID, input)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeInternalServer, "failed to update profile image")
	}

	// Create audit log
	s.createAuditLog(ctx, &model.CreateAuditLogRequest{
		UserID:         &userID,
		Action:         "user.profile_image_updated",
		Resource:       "user",
		ResourceID:     &userID,
		Status:         "success",
		OrganizationID: &updatedUser.OrganizationID,
		Changes: map[string]interface{}{
			"profile_image_url": map[string]interface{}{
				"old": existingUser.ProfileImageURL,
				"new": imageURL,
			},
		},
	})

	return s.convertEntUserToModel(updatedUser), nil
}

// RemoveProfileImage removes a user's profile image
func (s *profileService) RemoveProfileImage(ctx context.Context, userID xid.ID) (*model.User, error) {
	// Get existing user
	existingUser, err := s.userRepo.GetByID(ctx, userID)
	if err != nil {
		if ent.IsNotFound(err) {
			return nil, errors.New(errors.CodeNotFound, "user not found")
		}
		return nil, errors.Wrap(err, errors.CodeInternalServer, "failed to get user")
	}

	if existingUser.ProfileImageURL == "" {
		return s.convertEntUserToModel(existingUser), nil // Already no image
	}

	// Remove profile image
	emptyURL := ""
	input := repository.UpdateUserInput{
		UpdateUserRequest: model.UpdateUserRequest{
			ProfileImageURL: &emptyURL,
		},
	}

	updatedUser, err := s.userRepo.Update(ctx, userID, input)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeInternalServer, "failed to remove profile image")
	}

	// Create audit log
	s.createAuditLog(ctx, &model.CreateAuditLogRequest{
		UserID:         &userID,
		Action:         "user.profile_image_removed",
		Resource:       "user",
		ResourceID:     &userID,
		Status:         "success",
		OrganizationID: &updatedUser.OrganizationID,
		Changes: map[string]interface{}{
			"profile_image_url": map[string]interface{}{
				"old": existingUser.ProfileImageURL,
				"new": "",
			},
		},
	})

	return s.convertEntUserToModel(updatedUser), nil
}

// SetCustomAttribute sets a custom attribute for a user
func (s *profileService) SetCustomAttribute(ctx context.Context, userID xid.ID, key string, value interface{}) error {
	if key == "" {
		return errors.New(errors.CodeBadRequest, "attribute key is required")
	}

	// Validate custom attribute
	if err := s.ValidateCustomAttribute(ctx, key, value); err != nil {
		return err
	}

	// Get existing user
	existingUser, err := s.userRepo.GetByID(ctx, userID)
	if err != nil {
		if ent.IsNotFound(err) {
			return errors.New(errors.CodeNotFound, "user not found")
		}
		return errors.Wrap(err, errors.CodeInternalServer, "failed to get user")
	}

	// Merge with existing custom attributes
	customAttributes := make(map[string]interface{})
	if existingUser.CustomAttributes != nil {
		for k, v := range existingUser.CustomAttributes {
			customAttributes[k] = v
		}
	}

	oldValue := customAttributes[key]
	customAttributes[key] = value

	// Update user
	input := repository.UpdateUserInput{
		UpdateUserRequest: model.UpdateUserRequest{
			CustomAttributes: customAttributes,
		},
	}

	if _, err := s.userRepo.Update(ctx, userID, input); err != nil {
		return errors.Wrap(err, errors.CodeInternalServer, "failed to set custom attribute")
	}

	// Create audit log
	s.createAuditLog(ctx, &model.CreateAuditLogRequest{
		UserID:         &userID,
		Action:         "user.custom_attribute_set",
		Resource:       "user",
		ResourceID:     &userID,
		Status:         "success",
		OrganizationID: &existingUser.OrganizationID,
		Details: map[string]interface{}{
			"attribute_key": key,
			"old_value":     oldValue,
			"new_value":     value,
		},
	})

	return nil
}

// GetCustomAttribute gets a custom attribute value for a user
func (s *profileService) GetCustomAttribute(ctx context.Context, userID xid.ID, key string) (interface{}, error) {
	if key == "" {
		return nil, errors.New(errors.CodeBadRequest, "attribute key is required")
	}

	// Get user
	entUser, err := s.userRepo.GetByID(ctx, userID)
	if err != nil {
		if ent.IsNotFound(err) {
			return nil, errors.New(errors.CodeNotFound, "user not found")
		}
		return nil, errors.Wrap(err, errors.CodeInternalServer, "failed to get user")
	}

	if entUser.CustomAttributes == nil {
		return nil, errors.New(errors.CodeNotFound, "attribute not found")
	}

	value, exists := entUser.CustomAttributes[key]
	if !exists {
		return nil, errors.New(errors.CodeNotFound, "attribute not found")
	}

	return value, nil
}

// RemoveCustomAttribute removes a custom attribute for a user
func (s *profileService) RemoveCustomAttribute(ctx context.Context, userID xid.ID, key string) error {
	if key == "" {
		return errors.New(errors.CodeBadRequest, "attribute key is required")
	}

	// Get existing user
	existingUser, err := s.userRepo.GetByID(ctx, userID)
	if err != nil {
		if ent.IsNotFound(err) {
			return errors.New(errors.CodeNotFound, "user not found")
		}
		return errors.Wrap(err, errors.CodeInternalServer, "failed to get user")
	}

	if existingUser.CustomAttributes == nil {
		return errors.New(errors.CodeNotFound, "attribute not found")
	}

	oldValue, exists := existingUser.CustomAttributes[key]
	if !exists {
		return errors.New(errors.CodeNotFound, "attribute not found")
	}

	// Create new attributes map without the key
	customAttributes := make(map[string]interface{})
	for k, v := range existingUser.CustomAttributes {
		if k != key {
			customAttributes[k] = v
		}
	}

	// Update user
	input := repository.UpdateUserInput{
		UpdateUserRequest: model.UpdateUserRequest{
			CustomAttributes: customAttributes,
		},
	}

	if _, err := s.userRepo.Update(ctx, userID, input); err != nil {
		return errors.Wrap(err, errors.CodeInternalServer, "failed to remove custom attribute")
	}

	// Create audit log
	s.createAuditLog(ctx, &model.CreateAuditLogRequest{
		UserID:         &userID,
		Action:         "user.custom_attribute_removed",
		Resource:       "user",
		ResourceID:     &userID,
		Status:         "success",
		OrganizationID: &existingUser.OrganizationID,
		Details: map[string]interface{}{
			"attribute_key": key,
			"old_value":     oldValue,
		},
	})

	return nil
}

// ListCustomAttributes lists all custom attributes for a user
func (s *profileService) ListCustomAttributes(ctx context.Context, userID xid.ID) (map[string]interface{}, error) {
	// Get user
	entUser, err := s.userRepo.GetByID(ctx, userID)
	if err != nil {
		if ent.IsNotFound(err) {
			return nil, errors.New(errors.CodeNotFound, "user not found")
		}
		return nil, errors.Wrap(err, errors.CodeInternalServer, "failed to get user")
	}

	if entUser.CustomAttributes == nil {
		return make(map[string]interface{}), nil
	}

	// Return a copy to prevent modification
	attributes := make(map[string]interface{})
	for k, v := range entUser.CustomAttributes {
		attributes[k] = v
	}

	return attributes, nil
}

// UpdateLocalization updates a user's localization settings
func (s *profileService) UpdateLocalization(ctx context.Context, userID xid.ID, locale, timezone string) (*model.User, error) {
	// Validate locale and timezone
	if locale != "" {
		if err := s.validateLocale(locale); err != nil {
			return nil, err
		}
	}
	if timezone != "" {
		if err := s.validateTimezone(timezone); err != nil {
			return nil, err
		}
	}

	// Get existing user
	existingUser, err := s.userRepo.GetByID(ctx, userID)
	if err != nil {
		if ent.IsNotFound(err) {
			return nil, errors.New(errors.CodeNotFound, "user not found")
		}
		return nil, errors.Wrap(err, errors.CodeInternalServer, "failed to get user")
	}

	// Prepare update input
	input := repository.UpdateUserInput{}
	changes := make(map[string]interface{})

	if locale != "" && locale != existingUser.Locale {
		input.Locale = &locale
		changes["locale"] = map[string]interface{}{
			"old": existingUser.Locale,
			"new": locale,
		}
	}

	if timezone != "" && timezone != existingUser.Timezone {
		input.Timezone = &timezone
		changes["timezone"] = map[string]interface{}{
			"old": existingUser.Timezone,
			"new": timezone,
		}
	}

	// Update if there are changes
	if len(changes) == 0 {
		return s.convertEntUserToModel(existingUser), nil
	}

	updatedUser, err := s.userRepo.Update(ctx, userID, input)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeInternalServer, "failed to update localization settings")
	}

	// Create audit log
	s.createAuditLog(ctx, &model.CreateAuditLogRequest{
		UserID:         &userID,
		Action:         "user.localization_updated",
		Resource:       "user",
		ResourceID:     &userID,
		Status:         "success",
		OrganizationID: &updatedUser.OrganizationID,
		Changes:        changes,
	})

	return s.convertEntUserToModel(updatedUser), nil
}

// GetProfileCompletionScore calculates profile completion score
func (s *profileService) GetProfileCompletionScore(ctx context.Context, userID xid.ID) (*ProfileCompletion, error) {
	// Get user
	entUser, err := s.userRepo.GetByID(ctx, userID)
	if err != nil {
		if ent.IsNotFound(err) {
			return nil, errors.New(errors.CodeNotFound, "user not found")
		}
		return nil, errors.Wrap(err, errors.CodeInternalServer, "failed to get user")
	}

	// Define required fields and their weights
	fields := map[string]bool{
		"first_name":     entUser.FirstName != "",
		"last_name":      entUser.LastName != "",
		"email":          entUser.Email != "",
		"email_verified": entUser.EmailVerified,
		"phone_number":   entUser.PhoneNumber != "",
		"phone_verified": entUser.PhoneVerified,
		"profile_image":  entUser.ProfileImageURL != "",
		"locale":         entUser.Locale != "",
		"timezone":       entUser.Timezone != "",
		"username":       entUser.Username != "",
	}

	totalFields := len(fields)
	completedFields := 0
	var missingFields []string
	var suggestions []string

	for field, completed := range fields {
		if completed {
			completedFields++
		} else {
			missingFields = append(missingFields, field)
			suggestions = append(suggestions, s.getFieldSuggestion(field))
		}
	}

	score := (float64(completedFields) / float64(totalFields)) * 100

	return &ProfileCompletion{
		Score:           score,
		TotalFields:     totalFields,
		CompletedFields: completedFields,
		MissingFields:   missingFields,
		Suggestions:     suggestions,
	}, nil
}

// Helper methods

func (s *profileService) ValidateProfileData(ctx context.Context, req model.UserProfileUpdateRequest) error {
	// Validate first name
	if req.FirstName != "" && len(strings.TrimSpace(req.FirstName)) < 1 {
		return errors.New(errors.CodeBadRequest, "first name cannot be empty")
	}

	// Validate last name
	if req.LastName != "" && len(strings.TrimSpace(req.LastName)) < 1 {
		return errors.New(errors.CodeBadRequest, "last name cannot be empty")
	}

	// Validate username
	if req.Username != "" {
		if len(req.Username) < 3 {
			return errors.New(errors.CodeBadRequest, "username must be at least 3 characters")
		}
		if !s.isValidUsername(req.Username) {
			return errors.New(errors.CodeBadRequest, "username contains invalid characters")
		}
	}

	// Validate profile image URL
	if req.ProfileImageURL != "" {
		if err := s.validateImageURL(req.ProfileImageURL); err != nil {
			return err
		}
	}

	// Validate locale
	if req.Locale != "" {
		if err := s.validateLocale(req.Locale); err != nil {
			return err
		}
	}

	// Validate timezone
	if req.Timezone != "" {
		if err := s.validateTimezone(req.Timezone); err != nil {
			return err
		}
	}

	// Validate custom attributes
	if req.CustomAttributes != nil {
		for key, value := range req.CustomAttributes {
			if err := s.ValidateCustomAttribute(ctx, key, value); err != nil {
				return err
			}
		}
	}

	return nil
}

func (s *profileService) ValidateCustomAttribute(ctx context.Context, key string, value interface{}) error {
	// Validate key
	if key == "" {
		return errors.New(errors.CodeBadRequest, "custom attribute key cannot be empty")
	}
	if len(key) > 100 {
		return errors.New(errors.CodeBadRequest, "custom attribute key is too long")
	}
	if !s.isValidAttributeKey(key) {
		return errors.New(errors.CodeBadRequest, "custom attribute key contains invalid characters")
	}

	// Validate value type and size
	switch v := value.(type) {
	case string:
		if len(v) > 1000 {
			return errors.New(errors.CodeBadRequest, "custom attribute string value is too long")
		}
	case int, int32, int64, float32, float64, bool:
		// These types are fine
	case nil:
		// Nil values are allowed (for deletion)
	default:
		return errors.New(errors.CodeBadRequest, "custom attribute value type not supported")
	}

	return nil
}

func (s *profileService) validateUsernameUniqueness(ctx context.Context, username string, userType user.UserType, organizationID *xid.ID, excludeUserID *xid.ID) error {
	exists, err := s.userRepo.ExistsByUsername(ctx, username, userType, organizationID)
	if err != nil {
		return errors.Wrap(err, errors.CodeInternalServer, "failed to check username uniqueness")
	}

	if exists {
		if excludeUserID != nil {
			existingUser, err := s.userRepo.GetByUsername(ctx, username, userType, organizationID)
			if err == nil && existingUser.ID == *excludeUserID {
				return nil // Same user, allow update
			}
		}
		return errors.New(errors.CodeConflict, "username already exists")
	}

	return nil
}

func (s *profileService) validateImageURL(imageURL string) error {
	if !strings.HasPrefix(imageURL, "http://") && !strings.HasPrefix(imageURL, "https://") {
		return errors.New(errors.CodeBadRequest, "invalid image URL format")
	}
	if len(imageURL) > 500 {
		return errors.New(errors.CodeBadRequest, "image URL is too long")
	}
	return nil
}

func (s *profileService) validateLocale(locale string) error {
	// Basic locale validation - in production, use a proper locale validation library
	if len(locale) < 2 || len(locale) > 10 {
		return errors.New(errors.CodeBadRequest, "invalid locale format")
	}
	return nil
}

func (s *profileService) validateTimezone(timezone string) error {
	// Basic timezone validation - in production, use a proper timezone validation library
	if len(timezone) < 3 || len(timezone) > 50 {
		return errors.New(errors.CodeBadRequest, "invalid timezone format")
	}
	return nil
}

func (s *profileService) isValidUsername(username string) bool {
	// Basic username validation - alphanumeric, underscore, hyphen
	for _, char := range username {
		if !((char >= 'a' && char <= 'z') ||
			(char >= 'A' && char <= 'Z') ||
			(char >= '0' && char <= '9') ||
			char == '_' || char == '-') {
			return false
		}
	}
	return true
}

func (s *profileService) isValidAttributeKey(key string) bool {
	// Basic attribute key validation - alphanumeric, underscore
	for _, char := range key {
		if !((char >= 'a' && char <= 'z') ||
			(char >= 'A' && char <= 'Z') ||
			(char >= '0' && char <= '9') ||
			char == '_') {
			return false
		}
	}
	return true
}

func (s *profileService) getUpdatedFieldsList(changes map[string]interface{}) []string {
	var fields []string
	for field := range changes {
		fields = append(fields, field)
	}
	return fields
}

func (s *profileService) getFieldSuggestion(field string) string {
	suggestions := map[string]string{
		"first_name":     "Add your first name",
		"last_name":      "Add your last name",
		"email":          "Add your email address",
		"email_verified": "Verify your email address",
		"phone_number":   "Add your phone number",
		"phone_verified": "Verify your phone number",
		"profile_image":  "Upload a profile picture",
		"locale":         "Set your preferred language",
		"timezone":       "Set your timezone",
		"username":       "Choose a username",
	}
	if suggestion, exists := suggestions[field]; exists {
		return suggestion
	}
	return "Complete this field"
}

func (s *profileService) convertEntUserToModel(entUser *ent.User) *model.User {
	// Convert ent.User to model.User
	return &model.User{
		Base: model.Base{
			ID:        entUser.ID,
			CreatedAt: entUser.CreatedAt,
			UpdatedAt: entUser.UpdatedAt,
		},
		Email:                 entUser.Email,
		PhoneNumber:           entUser.PhoneNumber,
		FirstName:             entUser.FirstName,
		LastName:              entUser.LastName,
		Username:              entUser.Username,
		EmailVerified:         entUser.EmailVerified,
		PhoneVerified:         entUser.PhoneVerified,
		Active:                entUser.Active,
		Blocked:               entUser.Blocked,
		LastLogin:             entUser.LastLogin,
		LastPasswordChange:    entUser.LastPasswordChange,
		Metadata:              entUser.Metadata,
		ProfileImageURL:       entUser.ProfileImageURL,
		Locale:                entUser.Locale,
		Timezone:              entUser.Timezone,
		UserType:              entUser.UserType.String(),
		OrganizationID:        &entUser.OrganizationID,
		PrimaryOrganizationID: &entUser.PrimaryOrganizationID,
		IsPlatformAdmin:       entUser.IsPlatformAdmin,
		AuthProvider:          entUser.AuthProvider,
		ExternalID:            entUser.ExternalID,
		CustomerID:            entUser.CustomerID,
		CustomAttributes:      entUser.CustomAttributes,
		CreatedBy:             entUser.CreatedBy,
		LoginCount:            entUser.LoginCount,
		LastLoginIP:           entUser.LastLoginIP,
	}
}

func (s *profileService) createAuditLog(ctx context.Context, input *model.CreateAuditLogRequest) {
	// Create audit log asynchronously
	go func() {
		auditInput := repository.CreateAuditInput{
			OrganizationID: input.OrganizationID,
			UserID:         input.UserID,
			SessionID:      input.SessionID,
			Action:         input.Action,
			ResourceType:   input.Resource,
			ResourceID:     input.ResourceID,
			Status:         input.Status,
			IPAddress:      input.IPAddress,
			UserAgent:      input.UserAgent,
			Location:       input.Location,
			Details:        input.Details,
			Changes:        input.Changes,
			Error:          input.Error,
			Duration:       input.Duration,
			RiskLevel:      input.RiskLevel,
			Tags:           input.Tags,
			Source:         input.Source,
		}

		if _, err := s.auditRepo.Create(context.Background(), auditInput); err != nil {
			s.logger.Error("Failed to create audit log", logging.Error(err))
		}
	}()
}

// Placeholder implementations for remaining methods
func (s *profileService) UpdateCustomAttributes(ctx context.Context, userID xid.ID, attributes map[string]interface{}) error {
	// TODO: Implement bulk custom attributes update
	return nil
}

func (s *profileService) UpdateContactInfo(ctx context.Context, userID xid.ID, email, phoneNumber string) (*model.User, error) {
	// TODO: Implement contact info update
	return nil, nil
}

func (s *profileService) UpdateEmail(ctx context.Context, userID xid.ID, newEmail string) (string, error) {
	// TODO: Implement email update with verification
	return "", nil
}

func (s *profileService) UpdatePhoneNumber(ctx context.Context, userID xid.ID, newPhoneNumber string) (string, error) {
	// TODO: Implement phone number update with verification
	return "", nil
}

func (s *profileService) ConfirmEmailUpdate(ctx context.Context, token string) (*model.User, error) {
	// TODO: Implement email update confirmation
	return nil, nil
}

func (s *profileService) ConfirmPhoneUpdate(ctx context.Context, token string) (*model.User, error) {
	// TODO: Implement phone update confirmation
	return nil, nil
}

func (s *profileService) GetSupportedLocales(ctx context.Context) ([]string, error) {
	// TODO: Implement get supported locales
	return []string{"en", "es", "fr", "de", "ja", "zh"}, nil
}

func (s *profileService) GetSupportedTimezones(ctx context.Context) ([]string, error) {
	// TODO: Implement get supported timezones
	return []string{"UTC", "America/New_York", "America/Los_Angeles", "Europe/London", "Asia/Tokyo"}, nil
}

func (s *profileService) GetProfileActivity(ctx context.Context, userID xid.ID, days int) (*ProfileActivity, error) {
	// TODO: Implement get profile activity
	return nil, nil
}

func (s *profileService) GetProfileSuggestions(ctx context.Context, userID xid.ID) ([]ProfileSuggestion, error) {
	// TODO: Implement get profile suggestions
	return nil, nil
}
