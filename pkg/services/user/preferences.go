package user

import (
	"context"
	"encoding/json"
	"time"

	"github.com/juicycleff/frank/ent"
	"github.com/juicycleff/frank/internal/repository"
	"github.com/juicycleff/frank/pkg/errors"
	"github.com/juicycleff/frank/pkg/logging"
	"github.com/juicycleff/frank/pkg/model"
	"github.com/rs/xid"
)

// PreferencesService defines the user preferences service interface
type PreferencesService interface {
	// General preferences
	GetPreferences(ctx context.Context, userID xid.ID) (*UserPreferences, error)
	UpdatePreferences(ctx context.Context, userID xid.ID, req UpdatePreferencesRequest) (*UserPreferences, error)
	ResetPreferences(ctx context.Context, userID xid.ID) (*UserPreferences, error)

	// Notification preferences
	GetNotificationPreferences(ctx context.Context, userID xid.ID) (*NotificationPreferences, error)
	UpdateNotificationPreferences(ctx context.Context, userID xid.ID, req UpdateNotificationPreferencesRequest) (*NotificationPreferences, error)
	SetNotificationMethod(ctx context.Context, userID xid.ID, notificationType string, method NotificationMethod, enabled bool) error

	// Privacy preferences
	GetPrivacyPreferences(ctx context.Context, userID xid.ID) (*PrivacyPreferences, error)
	UpdatePrivacyPreferences(ctx context.Context, userID xid.ID, req UpdatePrivacyPreferencesRequest) (*PrivacyPreferences, error)

	// Security preferences
	GetSecurityPreferences(ctx context.Context, userID xid.ID) (*SecurityPreferences, error)
	UpdateSecurityPreferences(ctx context.Context, userID xid.ID, req UpdateSecurityPreferencesRequest) (*SecurityPreferences, error)

	// Theme and appearance preferences
	GetAppearancePreferences(ctx context.Context, userID xid.ID) (*AppearancePreferences, error)
	UpdateAppearancePreferences(ctx context.Context, userID xid.ID, req UpdateAppearancePreferencesRequest) (*AppearancePreferences, error)

	// Communication preferences
	GetCommunicationPreferences(ctx context.Context, userID xid.ID) (*CommunicationPreferences, error)
	UpdateCommunicationPreferences(ctx context.Context, userID xid.ID, req UpdateCommunicationPreferencesRequest) (*CommunicationPreferences, error)

	// Accessibility preferences
	GetAccessibilityPreferences(ctx context.Context, userID xid.ID) (*AccessibilityPreferences, error)
	UpdateAccessibilityPreferences(ctx context.Context, userID xid.ID, req UpdateAccessibilityPreferencesRequest) (*AccessibilityPreferences, error)

	// Preference categories and templates
	GetPreferenceCategories(ctx context.Context) ([]PreferenceCategory, error)
	GetPreferenceTemplates(ctx context.Context, userType string) ([]PreferenceTemplate, error)
	ApplyPreferenceTemplate(ctx context.Context, userID xid.ID, templateID string) (*UserPreferences, error)

	// Import/Export preferences
	ExportPreferences(ctx context.Context, userID xid.ID) (*PreferencesExport, error)
	ImportPreferences(ctx context.Context, userID xid.ID, data PreferencesImport) (*UserPreferences, error)

	// Preference validation
	ValidatePreferences(ctx context.Context, preferences UserPreferences) error
	ValidatePreferenceValue(ctx context.Context, key string, value interface{}) error
}

// preferencesService implements the PreferencesService interface
type preferencesService struct {
	userRepo  repository.UserRepository
	auditRepo repository.AuditRepository
	logger    logging.Logger
}

// NewPreferencesService creates a new preferences service instance
func NewPreferencesService(
	userRepo repository.UserRepository,
	auditRepo repository.AuditRepository,
	logger logging.Logger,
) PreferencesService {
	return &preferencesService{
		userRepo:  userRepo,
		auditRepo: auditRepo,
		logger:    logger,
	}
}

// GetPreferences retrieves all user preferences
func (s *preferencesService) GetPreferences(ctx context.Context, userID xid.ID) (*UserPreferences, error) {
	s.logger.Info("Getting user preferences", logging.String("user_id", userID.String()))

	// Get user to access custom attributes where preferences are stored
	entUser, err := s.userRepo.GetByID(ctx, userID)
	if err != nil {
		if ent.IsNotFound(err) {
			return nil, errors.New(errors.CodeNotFound, "user not found")
		}
		return nil, errors.Wrap(err, errors.CodeInternalServer, "failed to get user")
	}

	// Extract preferences from custom attributes or return defaults
	preferences := s.getPreferencesFromUser(entUser)
	return preferences, nil
}

// UpdatePreferences updates user preferences
func (s *preferencesService) UpdatePreferences(ctx context.Context, userID xid.ID, req UpdatePreferencesRequest) (*UserPreferences, error) {
	s.logger.Info("Updating user preferences", logging.String("user_id", userID.String()))

	// Get existing user and preferences
	entUser, err := s.userRepo.GetByID(ctx, userID)
	if err != nil {
		if ent.IsNotFound(err) {
			return nil, errors.New(errors.CodeNotFound, "user not found")
		}
		return nil, errors.Wrap(err, errors.CodeInternalServer, "failed to get user")
	}

	currentPreferences := s.getPreferencesFromUser(entUser)

	// Apply updates
	updatedPreferences := s.applyPreferenceUpdates(currentPreferences, req)

	// Validate updated preferences
	if err := s.ValidatePreferences(ctx, *updatedPreferences); err != nil {
		return nil, err
	}

	// Store preferences back to user custom attributes
	customAttributes := entUser.CustomAttributes
	if customAttributes == nil {
		customAttributes = make(map[string]interface{})
	}

	// Serialize preferences to store in custom attributes
	preferencesData, err := json.Marshal(updatedPreferences)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeInternalServer, "failed to serialize preferences")
	}

	var preferencesMap map[string]interface{}
	if err := json.Unmarshal(preferencesData, &preferencesMap); err != nil {
		return nil, errors.Wrap(err, errors.CodeInternalServer, "failed to convert preferences")
	}

	customAttributes["preferences"] = preferencesMap
	customAttributes["preferences_version"] = updatedPreferences.Version + 1

	// Update user
	input := repository.UpdateUserInput{
		UpdateUserRequest: model.UpdateUserRequest{
			CustomAttributes: customAttributes,
		},
	}

	if _, err := s.userRepo.Update(ctx, userID, input); err != nil {
		return nil, errors.Wrap(err, errors.CodeInternalServer, "failed to update user preferences")
	}

	// Update version and timestamp
	updatedPreferences.Version++
	updatedPreferences.LastUpdated = time.Now()

	// Create audit log
	s.createAuditLog(ctx, &model.CreateAuditLogRequest{
		UserID:         &userID,
		Action:         "user.preferences_updated",
		Resource:       "user",
		ResourceID:     &userID,
		Status:         "success",
		OrganizationID: &entUser.OrganizationID,
		Details: map[string]interface{}{
			"updated_categories": s.getUpdatedCategories(req),
		},
	})

	s.logger.Info("User preferences updated successfully", logging.String("user_id", userID.String()))
	return updatedPreferences, nil
}

// GetNotificationPreferences retrieves notification preferences
func (s *preferencesService) GetNotificationPreferences(ctx context.Context, userID xid.ID) (*NotificationPreferences, error) {
	preferences, err := s.GetPreferences(ctx, userID)
	if err != nil {
		return nil, err
	}
	return &preferences.Notification, nil
}

// UpdateNotificationPreferences updates notification preferences
func (s *preferencesService) UpdateNotificationPreferences(ctx context.Context, userID xid.ID, req UpdateNotificationPreferencesRequest) (*NotificationPreferences, error) {
	updateReq := UpdatePreferencesRequest{
		Notification: &req,
	}

	preferences, err := s.UpdatePreferences(ctx, userID, updateReq)
	if err != nil {
		return nil, err
	}

	return &preferences.Notification, nil
}

// ValidatePreferences validates user preferences
func (s *preferencesService) ValidatePreferences(ctx context.Context, preferences UserPreferences) error {
	// Validate notification preferences
	if err := s.validateNotificationPreferences(preferences.Notification); err != nil {
		return err
	}

	// Validate privacy preferences
	if err := s.validatePrivacyPreferences(preferences.Privacy); err != nil {
		return err
	}

	// Validate security preferences
	if err := s.validateSecurityPreferences(preferences.Security); err != nil {
		return err
	}

	// Validate appearance preferences
	if err := s.validateAppearancePreferences(preferences.Appearance); err != nil {
		return err
	}

	// Validate communication preferences
	if err := s.validateCommunicationPreferences(preferences.Communication); err != nil {
		return err
	}

	// Validate accessibility preferences
	if err := s.validateAccessibilityPreferences(preferences.Accessibility); err != nil {
		return err
	}

	return nil
}

// ValidatePreferenceValue validates a specific preference value
func (s *preferencesService) ValidatePreferenceValue(ctx context.Context, key string, value interface{}) error {
	// Implementation for validating individual preference values
	switch key {
	case "theme":
		if str, ok := value.(string); ok {
			validThemes := []string{"light", "dark", "auto"}
			for _, valid := range validThemes {
				if str == valid {
					return nil
				}
			}
			return errors.New(errors.CodeBadRequest, "invalid theme value")
		}
		return errors.New(errors.CodeBadRequest, "theme must be a string")

	case "language":
		if str, ok := value.(string); ok {
			if len(str) < 2 || len(str) > 10 {
				return errors.New(errors.CodeBadRequest, "invalid language code")
			}
			return nil
		}
		return errors.New(errors.CodeBadRequest, "language must be a string")

	// Add more validation rules as needed
	default:
		return nil // Unknown keys are allowed for extensibility
	}
}

// Helper methods

func (s *preferencesService) getPreferencesFromUser(entUser *ent.User) *UserPreferences {
	// Default preferences
	preferences := &UserPreferences{
		UserID:      entUser.ID,
		LastUpdated: time.Now(),
		Version:     1,
		Notification: NotificationPreferences{
			Email: NotificationMethodSettings{
				Enabled:    true,
				Categories: make(map[string]bool),
				Frequency:  "immediate",
				Format:     "html",
			},
			SMS: NotificationMethodSettings{
				Enabled:    false,
				Categories: make(map[string]bool),
				Frequency:  "immediate",
				Format:     "text",
			},
			Push: NotificationMethodSettings{
				Enabled:    true,
				Categories: make(map[string]bool),
				Frequency:  "immediate",
			},
			InApp: NotificationMethodSettings{
				Enabled:    true,
				Categories: make(map[string]bool),
				Frequency:  "immediate",
			},
			Desktop: NotificationMethodSettings{
				Enabled:    false,
				Categories: make(map[string]bool),
				Frequency:  "immediate",
			},
			GlobalMute: false,
			Frequency:  "immediate",
		},
		Privacy: PrivacyPreferences{
			ProfileVisibility:   "organization",
			ShowEmail:           false,
			ShowPhoneNumber:     false,
			ShowLastSeen:        true,
			ShowOnlineStatus:    true,
			AllowDirectMessages: true,
			SearchableByEmail:   false,
			SearchableByPhone:   false,
			MarketingConsent:    false,
			AnalyticsConsent:    true,
			ThirdPartySharing:   false,
		},
		Security: SecurityPreferences{
			MFARequired:        false,
			MFAMethods:         []string{"totp"},
			PasswordExpiry:     90,
			SessionTimeout:     3600,
			LoginNotifications: true,
			SuspiciousActivity: true,
			DeviceTracking:     true,
			LocationTracking:   true,
			APIKeyAccess:       false,
		},
		Appearance: AppearancePreferences{
			Theme:         "auto",
			ColorScheme:   "blue",
			FontSize:      "medium",
			FontFamily:    "system",
			CompactMode:   false,
			HighContrast:  false,
			ReducedMotion: false,
		},
		Communication: CommunicationPreferences{
			Language:         entUser.Locale,
			DateFormat:       "YYYY-MM-DD",
			TimeFormat:       "24h",
			NumberFormat:     "1,234.56",
			CurrencyFormat:   "USD",
			WeekStartsOn:     "monday",
			AutoTranslate:    false,
			ShowTranslations: true,
			EmailFormat:      "html",
		},
		Accessibility: AccessibilityPreferences{
			ScreenReader:       false,
			HighContrast:       false,
			LargeText:          false,
			ReducedMotion:      false,
			KeyboardNavigation: true,
			FocusIndicators:    true,
			SkipLinks:          true,
			AltTextRequired:    false,
			AudioDescriptions:  false,
			CaptionsRequired:   false,
		},
	}

	// If user has stored preferences, merge them
	if entUser.CustomAttributes != nil {
		if prefsData, exists := entUser.CustomAttributes["preferences"]; exists {
			if prefsMap, ok := prefsData.(map[string]interface{}); ok {
				s.mergeStoredPreferences(preferences, prefsMap)
			}
		}

		if version, exists := entUser.CustomAttributes["preferences_version"]; exists {
			if versionInt, ok := version.(int); ok {
				preferences.Version = versionInt
			}
		}
	}

	return preferences
}

func (s *preferencesService) mergeStoredPreferences(preferences *UserPreferences, stored map[string]interface{}) {
	// Convert stored preferences back to struct
	// This is a simplified implementation - in production, you'd want more robust JSON unmarshaling
	data, _ := json.Marshal(stored)
	json.Unmarshal(data, preferences)
}

func (s *preferencesService) applyPreferenceUpdates(current *UserPreferences, req UpdatePreferencesRequest) *UserPreferences {
	updated := *current // Copy current preferences

	// Apply notification updates
	if req.Notification != nil {
		s.applyNotificationUpdates(&updated.Notification, *req.Notification)
	}

	// Apply privacy updates
	if req.Privacy != nil {
		s.applyPrivacyUpdates(&updated.Privacy, *req.Privacy)
	}

	// Apply security updates
	if req.Security != nil {
		s.applySecurityUpdates(&updated.Security, *req.Security)
	}

	// Apply appearance updates
	if req.Appearance != nil {
		s.applyAppearanceUpdates(&updated.Appearance, *req.Appearance)
	}

	// Apply communication updates
	if req.Communication != nil {
		s.applyCommunicationUpdates(&updated.Communication, *req.Communication)
	}

	// Apply accessibility updates
	if req.Accessibility != nil {
		s.applyAccessibilityUpdates(&updated.Accessibility, *req.Accessibility)
	}

	// Apply custom preferences
	if req.CustomPreferences != nil {
		if updated.CustomPreferences == nil {
			updated.CustomPreferences = make(map[string]interface{})
		}
		for k, v := range req.CustomPreferences {
			updated.CustomPreferences[k] = v
		}
	}

	return &updated
}

func (s *preferencesService) applyNotificationUpdates(current *NotificationPreferences, req UpdateNotificationPreferencesRequest) {
	if req.Email != nil {
		current.Email = *req.Email
	}
	if req.SMS != nil {
		current.SMS = *req.SMS
	}
	if req.Push != nil {
		current.Push = *req.Push
	}
	if req.InApp != nil {
		current.InApp = *req.InApp
	}
	if req.Desktop != nil {
		current.Desktop = *req.Desktop
	}
	if req.Digest != nil {
		current.Digest = *req.Digest
	}
	if req.GlobalMute != nil {
		current.GlobalMute = *req.GlobalMute
	}
	if req.QuietHours != nil {
		current.QuietHours = *req.QuietHours
	}
	if req.Frequency != nil {
		current.Frequency = *req.Frequency
	}
}

func (s *preferencesService) applyPrivacyUpdates(current *PrivacyPreferences, req UpdatePrivacyPreferencesRequest) {
	if req.ProfileVisibility != nil {
		current.ProfileVisibility = *req.ProfileVisibility
	}
	if req.ShowEmail != nil {
		current.ShowEmail = *req.ShowEmail
	}
	if req.ShowPhoneNumber != nil {
		current.ShowPhoneNumber = *req.ShowPhoneNumber
	}
	if req.ShowLastSeen != nil {
		current.ShowLastSeen = *req.ShowLastSeen
	}
	if req.ShowOnlineStatus != nil {
		current.ShowOnlineStatus = *req.ShowOnlineStatus
	}
	if req.AllowDirectMessages != nil {
		current.AllowDirectMessages = *req.AllowDirectMessages
	}
	if req.SearchableByEmail != nil {
		current.SearchableByEmail = *req.SearchableByEmail
	}
	if req.SearchableByPhone != nil {
		current.SearchableByPhone = *req.SearchableByPhone
	}
	if req.DataSharing != nil {
		current.DataSharing = *req.DataSharing
	}
	if req.CookiePreferences != nil {
		current.CookiePreferences = *req.CookiePreferences
	}
	if req.MarketingConsent != nil {
		current.MarketingConsent = *req.MarketingConsent
	}
	if req.AnalyticsConsent != nil {
		current.AnalyticsConsent = *req.AnalyticsConsent
	}
	if req.ThirdPartySharing != nil {
		current.ThirdPartySharing = *req.ThirdPartySharing
	}
}

func (s *preferencesService) applySecurityUpdates(current *SecurityPreferences, req UpdateSecurityPreferencesRequest) {
	if req.MFARequired != nil {
		current.MFARequired = *req.MFARequired
	}
	if req.MFAMethods != nil {
		current.MFAMethods = req.MFAMethods
	}
	if req.PasswordExpiry != nil {
		current.PasswordExpiry = *req.PasswordExpiry
	}
	if req.SessionTimeout != nil {
		current.SessionTimeout = *req.SessionTimeout
	}
	if req.LoginNotifications != nil {
		current.LoginNotifications = *req.LoginNotifications
	}
	if req.SuspiciousActivity != nil {
		current.SuspiciousActivity = *req.SuspiciousActivity
	}
	if req.DeviceTracking != nil {
		current.DeviceTracking = *req.DeviceTracking
	}
	if req.LocationTracking != nil {
		current.LocationTracking = *req.LocationTracking
	}
	if req.APIKeyAccess != nil {
		current.APIKeyAccess = *req.APIKeyAccess
	}
	if req.OAuthApplications != nil {
		current.OAuthApplications = *req.OAuthApplications
	}
	if req.SecurityAlerts != nil {
		current.SecurityAlerts = *req.SecurityAlerts
	}
	if req.BackupCodes != nil {
		current.BackupCodes = *req.BackupCodes
	}
}

func (s *preferencesService) applyAppearanceUpdates(current *AppearancePreferences, req UpdateAppearancePreferencesRequest) {
	if req.Theme != nil {
		current.Theme = *req.Theme
	}
	if req.ColorScheme != nil {
		current.ColorScheme = *req.ColorScheme
	}
	if req.FontSize != nil {
		current.FontSize = *req.FontSize
	}
	if req.FontFamily != nil {
		current.FontFamily = *req.FontFamily
	}
	if req.CompactMode != nil {
		current.CompactMode = *req.CompactMode
	}
	if req.HighContrast != nil {
		current.HighContrast = *req.HighContrast
	}
	if req.ReducedMotion != nil {
		current.ReducedMotion = *req.ReducedMotion
	}
	if req.CustomCSS != nil {
		current.CustomCSS = *req.CustomCSS
	}
	if req.Layout != nil {
		current.Layout = *req.Layout
	}
	if req.Dashboard != nil {
		current.Dashboard = *req.Dashboard
	}
}

func (s *preferencesService) applyCommunicationUpdates(current *CommunicationPreferences, req UpdateCommunicationPreferencesRequest) {
	if req.Language != nil {
		current.Language = *req.Language
	}
	if req.DateFormat != nil {
		current.DateFormat = *req.DateFormat
	}
	if req.TimeFormat != nil {
		current.TimeFormat = *req.TimeFormat
	}
	if req.NumberFormat != nil {
		current.NumberFormat = *req.NumberFormat
	}
	if req.CurrencyFormat != nil {
		current.CurrencyFormat = *req.CurrencyFormat
	}
	if req.WeekStartsOn != nil {
		current.WeekStartsOn = *req.WeekStartsOn
	}
	if req.AutoTranslate != nil {
		current.AutoTranslate = *req.AutoTranslate
	}
	if req.ShowTranslations != nil {
		current.ShowTranslations = *req.ShowTranslations
	}
	if req.EmailFormat != nil {
		current.EmailFormat = *req.EmailFormat
	}
	if req.EmailSignature != nil {
		current.EmailSignature = *req.EmailSignature
	}
	if req.SocialLinks != nil {
		if current.SocialLinks == nil {
			current.SocialLinks = make(map[string]string)
		}
		for k, v := range req.SocialLinks {
			current.SocialLinks[k] = v
		}
	}
}

func (s *preferencesService) applyAccessibilityUpdates(current *AccessibilityPreferences, req UpdateAccessibilityPreferencesRequest) {
	if req.ScreenReader != nil {
		current.ScreenReader = *req.ScreenReader
	}
	if req.HighContrast != nil {
		current.HighContrast = *req.HighContrast
	}
	if req.LargeText != nil {
		current.LargeText = *req.LargeText
	}
	if req.ReducedMotion != nil {
		current.ReducedMotion = *req.ReducedMotion
	}
	if req.KeyboardNavigation != nil {
		current.KeyboardNavigation = *req.KeyboardNavigation
	}
	if req.FocusIndicators != nil {
		current.FocusIndicators = *req.FocusIndicators
	}
	if req.SkipLinks != nil {
		current.SkipLinks = *req.SkipLinks
	}
	if req.AltTextRequired != nil {
		current.AltTextRequired = *req.AltTextRequired
	}
	if req.AudioDescriptions != nil {
		current.AudioDescriptions = *req.AudioDescriptions
	}
	if req.CaptionsRequired != nil {
		current.CaptionsRequired = *req.CaptionsRequired
	}
	if req.ColorBlindSupport != nil {
		current.ColorBlindSupport = *req.ColorBlindSupport
	}
}

func (s *preferencesService) getUpdatedCategories(req UpdatePreferencesRequest) []string {
	var categories []string
	if req.Notification != nil {
		categories = append(categories, "notification")
	}
	if req.Privacy != nil {
		categories = append(categories, "privacy")
	}
	if req.Security != nil {
		categories = append(categories, "security")
	}
	if req.Appearance != nil {
		categories = append(categories, "appearance")
	}
	if req.Communication != nil {
		categories = append(categories, "communication")
	}
	if req.Accessibility != nil {
		categories = append(categories, "accessibility")
	}
	if req.CustomPreferences != nil {
		categories = append(categories, "custom")
	}
	return categories
}

// Validation methods
func (s *preferencesService) validateNotificationPreferences(prefs NotificationPreferences) error {
	validFrequencies := []string{"immediate", "hourly", "daily", "weekly", "never"}
	if !s.isValidChoice(prefs.Frequency, validFrequencies) {
		return errors.New(errors.CodeBadRequest, "invalid notification frequency")
	}
	return nil
}

func (s *preferencesService) validatePrivacyPreferences(prefs PrivacyPreferences) error {
	validVisibilities := []string{"public", "organization", "private"}
	if !s.isValidChoice(prefs.ProfileVisibility, validVisibilities) {
		return errors.New(errors.CodeBadRequest, "invalid profile visibility")
	}
	return nil
}

func (s *preferencesService) validateSecurityPreferences(prefs SecurityPreferences) error {
	if prefs.PasswordExpiry < 0 || prefs.PasswordExpiry > 365 {
		return errors.New(errors.CodeBadRequest, "password expiry must be between 0 and 365 days")
	}
	if prefs.SessionTimeout < 300 || prefs.SessionTimeout > 86400 {
		return errors.New(errors.CodeBadRequest, "session timeout must be between 5 minutes and 24 hours")
	}
	return nil
}

func (s *preferencesService) validateAppearancePreferences(prefs AppearancePreferences) error {
	validThemes := []string{"light", "dark", "auto"}
	if !s.isValidChoice(prefs.Theme, validThemes) {
		return errors.New(errors.CodeBadRequest, "invalid theme")
	}

	validFontSizes := []string{"small", "medium", "large", "extra-large"}
	if !s.isValidChoice(prefs.FontSize, validFontSizes) {
		return errors.New(errors.CodeBadRequest, "invalid font size")
	}
	return nil
}

func (s *preferencesService) validateCommunicationPreferences(prefs CommunicationPreferences) error {
	validTimeFormats := []string{"12h", "24h"}
	if !s.isValidChoice(prefs.TimeFormat, validTimeFormats) {
		return errors.New(errors.CodeBadRequest, "invalid time format")
	}

	validEmailFormats := []string{"html", "text"}
	if !s.isValidChoice(prefs.EmailFormat, validEmailFormats) {
		return errors.New(errors.CodeBadRequest, "invalid email format")
	}
	return nil
}

func (s *preferencesService) validateAccessibilityPreferences(prefs AccessibilityPreferences) error {
	validColorBlindTypes := []string{"protanopia", "deuteranopia", "tritanopia", "protanomaly", "deuteranomaly", "tritanomaly"}
	if prefs.ColorBlindSupport.Enabled && !s.isValidChoice(prefs.ColorBlindSupport.Type, validColorBlindTypes) {
		return errors.New(errors.CodeBadRequest, "invalid color blind support type")
	}
	return nil
}

func (s *preferencesService) isValidChoice(value string, validChoices []string) bool {
	for _, choice := range validChoices {
		if value == choice {
			return true
		}
	}
	return false
}

func (s *preferencesService) createAuditLog(ctx context.Context, input *model.CreateAuditLogRequest) {
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
func (s *preferencesService) ResetPreferences(ctx context.Context, userID xid.ID) (*UserPreferences, error) {
	// TODO: Implement reset preferences
	return nil, nil
}

func (s *preferencesService) SetNotificationMethod(ctx context.Context, userID xid.ID, notificationType string, method NotificationMethod, enabled bool) error {
	// TODO: Implement set notification method
	return nil
}

func (s *preferencesService) GetPrivacyPreferences(ctx context.Context, userID xid.ID) (*PrivacyPreferences, error) {
	// TODO: Implement get privacy preferences
	return nil, nil
}

func (s *preferencesService) UpdatePrivacyPreferences(ctx context.Context, userID xid.ID, req UpdatePrivacyPreferencesRequest) (*PrivacyPreferences, error) {
	// TODO: Implement update privacy preferences
	return nil, nil
}

func (s *preferencesService) GetSecurityPreferences(ctx context.Context, userID xid.ID) (*SecurityPreferences, error) {
	// TODO: Implement get security preferences
	return nil, nil
}

func (s *preferencesService) UpdateSecurityPreferences(ctx context.Context, userID xid.ID, req UpdateSecurityPreferencesRequest) (*SecurityPreferences, error) {
	// TODO: Implement update security preferences
	return nil, nil
}

func (s *preferencesService) GetAppearancePreferences(ctx context.Context, userID xid.ID) (*AppearancePreferences, error) {
	// TODO: Implement get appearance preferences
	return nil, nil
}

func (s *preferencesService) UpdateAppearancePreferences(ctx context.Context, userID xid.ID, req UpdateAppearancePreferencesRequest) (*AppearancePreferences, error) {
	// TODO: Implement update appearance preferences
	return nil, nil
}

func (s *preferencesService) GetCommunicationPreferences(ctx context.Context, userID xid.ID) (*CommunicationPreferences, error) {
	// TODO: Implement get communication preferences
	return nil, nil
}

func (s *preferencesService) UpdateCommunicationPreferences(ctx context.Context, userID xid.ID, req UpdateCommunicationPreferencesRequest) (*CommunicationPreferences, error) {
	// TODO: Implement update communication preferences
	return nil, nil
}

func (s *preferencesService) GetAccessibilityPreferences(ctx context.Context, userID xid.ID) (*AccessibilityPreferences, error) {
	// TODO: Implement get accessibility preferences
	return nil, nil
}

func (s *preferencesService) UpdateAccessibilityPreferences(ctx context.Context, userID xid.ID, req UpdateAccessibilityPreferencesRequest) (*AccessibilityPreferences, error) {
	// TODO: Implement update accessibility preferences
	return nil, nil
}

func (s *preferencesService) GetPreferenceCategories(ctx context.Context) ([]PreferenceCategory, error) {
	// TODO: Implement get preference categories
	return nil, nil
}

func (s *preferencesService) GetPreferenceTemplates(ctx context.Context, userType string) ([]PreferenceTemplate, error) {
	// TODO: Implement get preference templates
	return nil, nil
}

func (s *preferencesService) ApplyPreferenceTemplate(ctx context.Context, userID xid.ID, templateID string) (*UserPreferences, error) {
	// TODO: Implement apply preference template
	return nil, nil
}

func (s *preferencesService) ExportPreferences(ctx context.Context, userID xid.ID) (*PreferencesExport, error) {
	// TODO: Implement export preferences
	return nil, nil
}

func (s *preferencesService) ImportPreferences(ctx context.Context, userID xid.ID, data PreferencesImport) (*UserPreferences, error) {
	// TODO: Implement import preferences
	return nil, nil
}
