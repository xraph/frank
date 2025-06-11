package user

import (
	"time"

	"github.com/rs/xid"
)

// UserPreferences represents all user preferences
type UserPreferences struct {
	UserID            xid.ID                   `json:"userId" example:"01FZS6TV7KP869DR7RXNEHXQKX" doc:"User ID"`
	Notification      NotificationPreferences  `json:"notification" doc:"Notification preferences"`
	Privacy           PrivacyPreferences       `json:"privacy" doc:"Privacy preferences"`
	Security          SecurityPreferences      `json:"security" doc:"Security preferences"`
	Appearance        AppearancePreferences    `json:"appearance" doc:"Appearance preferences"`
	Communication     CommunicationPreferences `json:"communication" doc:"Communication preferences"`
	Accessibility     AccessibilityPreferences `json:"accessibility" doc:"Accessibility preferences"`
	CustomPreferences map[string]interface{}   `json:"customPreferences,omitempty" doc:"Custom preferences"`
	LastUpdated       time.Time                `json:"lastUpdated" example:"2023-01-01T12:00:00Z" doc:"Last update timestamp"`
	Version           int                      `json:"version" example:"1" doc:"Preferences version"`
}

// NotificationPreferences represents notification settings
type NotificationPreferences struct {
	Email      NotificationMethodSettings `json:"email" doc:"Email notification settings"`
	SMS        NotificationMethodSettings `json:"sms" doc:"SMS notification settings"`
	Push       NotificationMethodSettings `json:"push" doc:"Push notification settings"`
	InApp      NotificationMethodSettings `json:"inApp" doc:"In-app notification settings"`
	Desktop    NotificationMethodSettings `json:"desktop" doc:"Desktop notification settings"`
	Digest     DigestSettings             `json:"digest" doc:"Digest settings"`
	GlobalMute bool                       `json:"globalMute" example:"false" doc:"Global notification mute"`
	QuietHours QuietHoursSettings         `json:"quietHours" doc:"Quiet hours settings"`
	Frequency  string                     `json:"frequency" example:"immediate" doc:"Default notification frequency"`
}

// NotificationMethodSettings represents settings for a notification method
type NotificationMethodSettings struct {
	Enabled        bool                   `json:"enabled" example:"true" doc:"Whether method is enabled"`
	Categories     map[string]bool        `json:"categories" doc:"Enabled categories for this method"`
	Frequency      string                 `json:"frequency" example:"immediate" doc:"Notification frequency"`
	Format         string                 `json:"format" example:"html" doc:"Notification format"`
	CustomSettings map[string]interface{} `json:"customSettings,omitempty" doc:"Method-specific settings"`
}

// DigestSettings represents digest notification settings
type DigestSettings struct {
	Enabled   bool     `json:"enabled" example:"true" doc:"Whether digest is enabled"`
	Frequency string   `json:"frequency" example:"daily" doc:"Digest frequency (daily, weekly, monthly)"`
	Time      string   `json:"time" example:"09:00" doc:"Digest delivery time"`
	Days      []string `json:"days,omitempty" example:"[\"monday\", \"wednesday\", \"friday\"]" doc:"Days for weekly digest"`
	TimeZone  string   `json:"timeZone" example:"America/New_York" doc:"Timezone for digest delivery"`
}

// QuietHoursSettings represents quiet hours settings
type QuietHoursSettings struct {
	Enabled   bool     `json:"enabled" example:"true" doc:"Whether quiet hours are enabled"`
	StartTime string   `json:"startTime" example:"22:00" doc:"Quiet hours start time"`
	EndTime   string   `json:"endTime" example:"08:00" doc:"Quiet hours end time"`
	Days      []string `json:"days" example:"[\"monday\", \"tuesday\", \"wednesday\", \"thursday\", \"friday\"]" doc:"Days when quiet hours apply"`
	TimeZone  string   `json:"timeZone" example:"America/New_York" doc:"Timezone for quiet hours"`
}

// PrivacyPreferences represents privacy settings
type PrivacyPreferences struct {
	ProfileVisibility   string                 `json:"profileVisibility" example:"public" doc:"Profile visibility (public, organization, private)"`
	ShowEmail           bool                   `json:"showEmail" example:"false" doc:"Whether to show email in profile"`
	ShowPhoneNumber     bool                   `json:"showPhoneNumber" example:"false" doc:"Whether to show phone number"`
	ShowLastSeen        bool                   `json:"showLastSeen" example:"true" doc:"Whether to show last seen status"`
	ShowOnlineStatus    bool                   `json:"showOnlineStatus" example:"true" doc:"Whether to show online status"`
	AllowDirectMessages bool                   `json:"allowDirectMessages" example:"true" doc:"Whether to allow direct messages"`
	SearchableByEmail   bool                   `json:"searchableByEmail" example:"false" doc:"Whether discoverable by email"`
	SearchableByPhone   bool                   `json:"searchableByPhone" example:"false" doc:"Whether discoverable by phone"`
	DataSharing         DataSharingPreferences `json:"dataSharing" doc:"Data sharing preferences"`
	CookiePreferences   CookiePreferences      `json:"cookiePreferences" doc:"Cookie preferences"`
	MarketingConsent    bool                   `json:"marketingConsent" example:"false" doc:"Marketing communication consent"`
	AnalyticsConsent    bool                   `json:"analyticsConsent" example:"true" doc:"Analytics tracking consent"`
	ThirdPartySharing   bool                   `json:"thirdPartySharing" example:"false" doc:"Third-party data sharing consent"`
}

// DataSharingPreferences represents data sharing settings
type DataSharingPreferences struct {
	Analytics          bool `json:"analytics" example:"true" doc:"Share data for analytics"`
	ProductImprovement bool `json:"productImprovement" example:"true" doc:"Share data for product improvement"`
	Marketing          bool `json:"marketing" example:"false" doc:"Share data for marketing"`
	ThirdPartyPartners bool `json:"thirdPartyPartners" example:"false" doc:"Share data with third-party partners"`
}

// CookiePreferences represents cookie settings
type CookiePreferences struct {
	Essential       bool `json:"essential" example:"true" doc:"Essential cookies (cannot be disabled)"`
	Analytics       bool `json:"analytics" example:"true" doc:"Analytics cookies"`
	Marketing       bool `json:"marketing" example:"false" doc:"Marketing cookies"`
	Personalization bool `json:"personalization" example:"true" doc:"Personalization cookies"`
}

// SecurityPreferences represents security settings
type SecurityPreferences struct {
	MFARequired        bool                     `json:"mfaRequired" example:"true" doc:"Whether MFA is required"`
	MFAMethods         []string                 `json:"mfaMethods" example:"[\"totp\", \"sms\"]" doc:"Enabled MFA methods"`
	PasswordExpiry     int                      `json:"passwordExpiry" example:"90" doc:"Password expiry in days (0 = no expiry)"`
	SessionTimeout     int                      `json:"sessionTimeout" example:"3600" doc:"Session timeout in seconds"`
	LoginNotifications bool                     `json:"loginNotifications" example:"true" doc:"Send notifications on login"`
	SuspiciousActivity bool                     `json:"suspiciousActivity" example:"true" doc:"Monitor suspicious activity"`
	DeviceTracking     bool                     `json:"deviceTracking" example:"true" doc:"Track login devices"`
	LocationTracking   bool                     `json:"locationTracking" example:"true" doc:"Track login locations"`
	APIKeyAccess       bool                     `json:"apiKeyAccess" example:"false" doc:"Allow API key generation"`
	OAuthApplications  OAuthApplicationSettings `json:"oauthApplications" doc:"OAuth application settings"`
	SecurityAlerts     SecurityAlertSettings    `json:"securityAlerts" doc:"Security alert settings"`
	BackupCodes        BackupCodeSettings       `json:"backupCodes" doc:"Backup code settings"`
}

// OAuthApplicationSettings represents OAuth application preferences
type OAuthApplicationSettings struct {
	AutoApprove         bool     `json:"autoApprove" example:"false" doc:"Auto-approve trusted applications"`
	TrustedApplications []string `json:"trustedApplications,omitempty" doc:"List of trusted application IDs"`
	ScopeRestrictions   []string `json:"scopeRestrictions,omitempty" doc:"Restricted OAuth scopes"`
	ReviewReminders     bool     `json:"reviewReminders" example:"true" doc:"Send reminders to review app permissions"`
}

// SecurityAlertSettings represents security alert preferences
type SecurityAlertSettings struct {
	EmailAlerts    bool     `json:"emailAlerts" example:"true" doc:"Send security alerts via email"`
	SMSAlerts      bool     `json:"smsAlerts" example:"false" doc:"Send security alerts via SMS"`
	AlertTypes     []string `json:"alertTypes" example:"[\"login\", \"password_change\", \"mfa_change\"]" doc:"Types of alerts to send"`
	AlertFrequency string   `json:"alertFrequency" example:"immediate" doc:"Alert frequency"`
	AlertThreshold string   `json:"alertThreshold" example:"medium" doc:"Alert threshold (low, medium, high)"`
}

// BackupCodeSettings represents backup code preferences
type BackupCodeSettings struct {
	Enabled        bool       `json:"enabled" example:"true" doc:"Whether backup codes are enabled"`
	AutoGenerate   bool       `json:"autoGenerate" example:"true" doc:"Auto-generate new codes when running low"`
	NotifyLowCount bool       `json:"notifyLowCount" example:"true" doc:"Notify when backup code count is low"`
	NotifyUsage    bool       `json:"notifyUsage" example:"true" doc:"Notify when backup codes are used"`
	LastGenerated  *time.Time `json:"lastGenerated,omitempty" example:"2023-01-01T12:00:00Z" doc:"Last generation timestamp"`
	RemainingCount int        `json:"remainingCount" example:"8" doc:"Number of remaining backup codes"`
}

// AppearancePreferences represents appearance settings
type AppearancePreferences struct {
	Theme         string               `json:"theme" example:"auto" doc:"Theme preference (light, dark, auto)"`
	ColorScheme   string               `json:"colorScheme" example:"blue" doc:"Color scheme preference"`
	FontSize      string               `json:"fontSize" example:"medium" doc:"Font size preference"`
	FontFamily    string               `json:"fontFamily" example:"system" doc:"Font family preference"`
	CompactMode   bool                 `json:"compactMode" example:"false" doc:"Enable compact mode"`
	HighContrast  bool                 `json:"highContrast" example:"false" doc:"Enable high contrast mode"`
	ReducedMotion bool                 `json:"reducedMotion" example:"false" doc:"Reduce animations and motion"`
	CustomCSS     string               `json:"customCss,omitempty" doc:"Custom CSS overrides"`
	Layout        LayoutPreferences    `json:"layout" doc:"Layout preferences"`
	Dashboard     DashboardPreferences `json:"dashboard" doc:"Dashboard preferences"`
}

// LayoutPreferences represents layout settings
type LayoutPreferences struct {
	SidebarCollapsed   bool   `json:"sidebarCollapsed" example:"false" doc:"Whether sidebar is collapsed"`
	SidebarPosition    string `json:"sidebarPosition" example:"left" doc:"Sidebar position (left, right)"`
	HeaderFixed        bool   `json:"headerFixed" example:"true" doc:"Whether header is fixed"`
	FooterVisible      bool   `json:"footerVisible" example:"true" doc:"Whether footer is visible"`
	BreadcrumbsVisible bool   `json:"breadcrumbsVisible" example:"true" doc:"Whether breadcrumbs are visible"`
	PageSize           int    `json:"pageSize" example:"25" doc:"Default page size for lists"`
	GridView           bool   `json:"gridView" example:"false" doc:"Prefer grid view over list view"`
}

// DashboardPreferences represents dashboard settings
type DashboardPreferences struct {
	Widgets         []string               `json:"widgets" example:"[\"recent_activity\", \"quick_stats\"]" doc:"Enabled dashboard widgets"`
	WidgetOrder     []string               `json:"widgetOrder" doc:"Widget display order"`
	DefaultView     string                 `json:"defaultView" example:"overview" doc:"Default dashboard view"`
	RefreshInterval int                    `json:"refreshInterval" example:"300" doc:"Auto-refresh interval in seconds"`
	ShowWelcome     bool                   `json:"showWelcome" example:"true" doc:"Show welcome message"`
	CustomWidgets   map[string]interface{} `json:"customWidgets,omitempty" doc:"Custom widget configurations"`
}

// CommunicationPreferences represents communication settings
type CommunicationPreferences struct {
	Language         string            `json:"language" example:"en" doc:"Preferred language"`
	DateFormat       string            `json:"dateFormat" example:"YYYY-MM-DD" doc:"Date format preference"`
	TimeFormat       string            `json:"timeFormat" example:"24h" doc:"Time format preference (12h, 24h)"`
	NumberFormat     string            `json:"numberFormat" example:"1,234.56" doc:"Number format preference"`
	CurrencyFormat   string            `json:"currencyFormat" example:"USD" doc:"Currency format preference"`
	WeekStartsOn     string            `json:"weekStartsOn" example:"monday" doc:"First day of week"`
	AutoTranslate    bool              `json:"autoTranslate" example:"false" doc:"Auto-translate content"`
	ShowTranslations bool              `json:"showTranslations" example:"true" doc:"Show translation options"`
	EmailFormat      string            `json:"emailFormat" example:"html" doc:"Email format preference (html, text)"`
	EmailSignature   string            `json:"emailSignature,omitempty" doc:"Email signature"`
	SocialLinks      map[string]string `json:"socialLinks,omitempty" doc:"Social media links"`
}

// AccessibilityPreferences represents accessibility settings
type AccessibilityPreferences struct {
	ScreenReader       bool                      `json:"screenReader" example:"false" doc:"Screen reader support"`
	HighContrast       bool                      `json:"highContrast" example:"false" doc:"High contrast mode"`
	LargeText          bool                      `json:"largeText" example:"false" doc:"Large text mode"`
	ReducedMotion      bool                      `json:"reducedMotion" example:"false" doc:"Reduced motion"`
	KeyboardNavigation bool                      `json:"keyboardNavigation" example:"true" doc:"Enhanced keyboard navigation"`
	FocusIndicators    bool                      `json:"focusIndicators" example:"true" doc:"Enhanced focus indicators"`
	SkipLinks          bool                      `json:"skipLinks" example:"true" doc:"Skip navigation links"`
	AltTextRequired    bool                      `json:"altTextRequired" example:"false" doc:"Require alt text for images"`
	AudioDescriptions  bool                      `json:"audioDescriptions" example:"false" doc:"Audio descriptions for videos"`
	CaptionsRequired   bool                      `json:"captionsRequired" example:"false" doc:"Require captions for videos"`
	ColorBlindSupport  ColorBlindSupportSettings `json:"colorBlindSupport" doc:"Color blind support settings"`
}

// ColorBlindSupportSettings represents color blind support settings
type ColorBlindSupportSettings struct {
	Enabled    bool   `json:"enabled" example:"false" doc:"Enable color blind support"`
	Type       string `json:"type" example:"deuteranopia" doc:"Type of color blindness"`
	Simulation bool   `json:"simulation" example:"false" doc:"Show color blind simulation"`
	Adjustment bool   `json:"adjustment" example:"false" doc:"Apply color adjustments"`
}

// NotificationMethod represents a notification delivery method
type NotificationMethod string

const (
	NotificationMethodEmail   NotificationMethod = "email"
	NotificationMethodSMS     NotificationMethod = "sms"
	NotificationMethodPush    NotificationMethod = "push"
	NotificationMethodInApp   NotificationMethod = "in_app"
	NotificationMethodDesktop NotificationMethod = "desktop"
)

// Request types for updating preferences
type UpdatePreferencesRequest struct {
	Notification      *UpdateNotificationPreferencesRequest  `json:"notification,omitempty"`
	Privacy           *UpdatePrivacyPreferencesRequest       `json:"privacy,omitempty"`
	Security          *UpdateSecurityPreferencesRequest      `json:"security,omitempty"`
	Appearance        *UpdateAppearancePreferencesRequest    `json:"appearance,omitempty"`
	Communication     *UpdateCommunicationPreferencesRequest `json:"communication,omitempty"`
	Accessibility     *UpdateAccessibilityPreferencesRequest `json:"accessibility,omitempty"`
	CustomPreferences map[string]interface{}                 `json:"customPreferences,omitempty"`
}

type UpdateNotificationPreferencesRequest struct {
	Email      *NotificationMethodSettings `json:"email,omitempty"`
	SMS        *NotificationMethodSettings `json:"sms,omitempty"`
	Push       *NotificationMethodSettings `json:"push,omitempty"`
	InApp      *NotificationMethodSettings `json:"inApp,omitempty"`
	Desktop    *NotificationMethodSettings `json:"desktop,omitempty"`
	Digest     *DigestSettings             `json:"digest,omitempty"`
	GlobalMute *bool                       `json:"globalMute,omitempty"`
	QuietHours *QuietHoursSettings         `json:"quietHours,omitempty"`
	Frequency  *string                     `json:"frequency,omitempty"`
}

type UpdatePrivacyPreferencesRequest struct {
	ProfileVisibility   *string                 `json:"profileVisibility,omitempty"`
	ShowEmail           *bool                   `json:"showEmail,omitempty"`
	ShowPhoneNumber     *bool                   `json:"showPhoneNumber,omitempty"`
	ShowLastSeen        *bool                   `json:"showLastSeen,omitempty"`
	ShowOnlineStatus    *bool                   `json:"showOnlineStatus,omitempty"`
	AllowDirectMessages *bool                   `json:"allowDirectMessages,omitempty"`
	SearchableByEmail   *bool                   `json:"searchableByEmail,omitempty"`
	SearchableByPhone   *bool                   `json:"searchableByPhone,omitempty"`
	DataSharing         *DataSharingPreferences `json:"dataSharing,omitempty"`
	CookiePreferences   *CookiePreferences      `json:"cookiePreferences,omitempty"`
	MarketingConsent    *bool                   `json:"marketingConsent,omitempty"`
	AnalyticsConsent    *bool                   `json:"analyticsConsent,omitempty"`
	ThirdPartySharing   *bool                   `json:"thirdPartySharing,omitempty"`
}

type UpdateSecurityPreferencesRequest struct {
	MFARequired        *bool                     `json:"mfaRequired,omitempty"`
	MFAMethods         []string                  `json:"mfaMethods,omitempty"`
	PasswordExpiry     *int                      `json:"passwordExpiry,omitempty"`
	SessionTimeout     *int                      `json:"sessionTimeout,omitempty"`
	LoginNotifications *bool                     `json:"loginNotifications,omitempty"`
	SuspiciousActivity *bool                     `json:"suspiciousActivity,omitempty"`
	DeviceTracking     *bool                     `json:"deviceTracking,omitempty"`
	LocationTracking   *bool                     `json:"locationTracking,omitempty"`
	APIKeyAccess       *bool                     `json:"apiKeyAccess,omitempty"`
	OAuthApplications  *OAuthApplicationSettings `json:"oauthApplications,omitempty"`
	SecurityAlerts     *SecurityAlertSettings    `json:"securityAlerts,omitempty"`
	BackupCodes        *BackupCodeSettings       `json:"backupCodes,omitempty"`
}

type UpdateAppearancePreferencesRequest struct {
	Theme         *string               `json:"theme,omitempty"`
	ColorScheme   *string               `json:"colorScheme,omitempty"`
	FontSize      *string               `json:"fontSize,omitempty"`
	FontFamily    *string               `json:"fontFamily,omitempty"`
	CompactMode   *bool                 `json:"compactMode,omitempty"`
	HighContrast  *bool                 `json:"highContrast,omitempty"`
	ReducedMotion *bool                 `json:"reducedMotion,omitempty"`
	CustomCSS     *string               `json:"customCss,omitempty"`
	Layout        *LayoutPreferences    `json:"layout,omitempty"`
	Dashboard     *DashboardPreferences `json:"dashboard,omitempty"`
}

type UpdateCommunicationPreferencesRequest struct {
	Language         *string           `json:"language,omitempty"`
	DateFormat       *string           `json:"dateFormat,omitempty"`
	TimeFormat       *string           `json:"timeFormat,omitempty"`
	NumberFormat     *string           `json:"numberFormat,omitempty"`
	CurrencyFormat   *string           `json:"currencyFormat,omitempty"`
	WeekStartsOn     *string           `json:"weekStartsOn,omitempty"`
	AutoTranslate    *bool             `json:"autoTranslate,omitempty"`
	ShowTranslations *bool             `json:"showTranslations,omitempty"`
	EmailFormat      *string           `json:"emailFormat,omitempty"`
	EmailSignature   *string           `json:"emailSignature,omitempty"`
	SocialLinks      map[string]string `json:"socialLinks,omitempty"`
}

type UpdateAccessibilityPreferencesRequest struct {
	ScreenReader       *bool                      `json:"screenReader,omitempty"`
	HighContrast       *bool                      `json:"highContrast,omitempty"`
	LargeText          *bool                      `json:"largeText,omitempty"`
	ReducedMotion      *bool                      `json:"reducedMotion,omitempty"`
	KeyboardNavigation *bool                      `json:"keyboardNavigation,omitempty"`
	FocusIndicators    *bool                      `json:"focusIndicators,omitempty"`
	SkipLinks          *bool                      `json:"skipLinks,omitempty"`
	AltTextRequired    *bool                      `json:"altTextRequired,omitempty"`
	AudioDescriptions  *bool                      `json:"audioDescriptions,omitempty"`
	CaptionsRequired   *bool                      `json:"captionsRequired,omitempty"`
	ColorBlindSupport  *ColorBlindSupportSettings `json:"colorBlindSupport,omitempty"`
}

// Additional types for preference management
type PreferenceCategory struct {
	ID            string   `json:"id" example:"notification" doc:"Category ID"`
	Name          string   `json:"name" example:"Notifications" doc:"Category name"`
	Description   string   `json:"description" example:"Manage your notification settings" doc:"Category description"`
	Icon          string   `json:"icon,omitempty" example:"bell" doc:"Category icon"`
	Order         int      `json:"order" example:"1" doc:"Display order"`
	SubCategories []string `json:"subCategories,omitempty" doc:"Sub-category IDs"`
}

type PreferenceTemplate struct {
	ID          string                 `json:"id" example:"developer" doc:"Template ID"`
	Name        string                 `json:"name" example:"Developer" doc:"Template name"`
	Description string                 `json:"description" example:"Optimized for developers" doc:"Template description"`
	UserType    string                 `json:"userType" example:"external" doc:"Target user type"`
	Preferences map[string]interface{} `json:"preferences" doc:"Template preferences"`
	Popular     bool                   `json:"popular" example:"true" doc:"Whether template is popular"`
}

type PreferencesExport struct {
	UserID      xid.ID                 `json:"userId" doc:"User ID"`
	ExportedAt  time.Time              `json:"exportedAt" doc:"Export timestamp"`
	Version     int                    `json:"version" doc:"Preferences version"`
	Preferences map[string]interface{} `json:"preferences" doc:"Exported preferences"`
	Checksum    string                 `json:"checksum" doc:"Data integrity checksum"`
}

type PreferencesImport struct {
	Preferences map[string]interface{} `json:"preferences" doc:"Preferences to import"`
	Overwrite   bool                   `json:"overwrite" example:"false" doc:"Whether to overwrite existing preferences"`
	Validate    bool                   `json:"validate" example:"true" doc:"Whether to validate before import"`
	Checksum    string                 `json:"checksum,omitempty" doc:"Data integrity checksum"`
}

// ProfileCompletion represents profile completion information
type ProfileCompletion struct {
	Score           float64  `json:"score" example:"75.5" doc:"Completion score percentage"`
	TotalFields     int      `json:"totalFields" example:"10" doc:"Total number of profile fields"`
	CompletedFields int      `json:"completedFields" example:"8" doc:"Number of completed fields"`
	MissingFields   []string `json:"missingFields" example:"[\"phone_number\", \"timezone\"]" doc:"List of missing required fields"`
	Suggestions     []string `json:"suggestions" example:"[\"Add a profile picture\", \"Set your timezone\"]" doc:"Completion suggestions"`
}

// ProfileActivity represents profile activity information
type ProfileActivity struct {
	LastUpdated      time.Time          `json:"lastUpdated" example:"2023-01-01T12:00:00Z" doc:"Last profile update"`
	UpdateCount      int                `json:"updateCount" example:"5" doc:"Number of updates in period"`
	RecentChanges    []ProfileChange    `json:"recentChanges" doc:"Recent profile changes"`
	LoginActivity    LoginActivity      `json:"loginActivity" doc:"Login activity summary"`
	DeviceActivity   []DeviceActivity   `json:"deviceActivity" doc:"Device usage activity"`
	LocationActivity []LocationActivity `json:"locationActivity" doc:"Location-based activity"`
}

// ProfileChange represents a profile change event
type ProfileChange struct {
	Field     string      `json:"field" example:"first_name" doc:"Changed field"`
	OldValue  interface{} `json:"oldValue,omitempty" doc:"Previous value"`
	NewValue  interface{} `json:"newValue" doc:"New value"`
	Timestamp time.Time   `json:"timestamp" example:"2023-01-01T12:00:00Z" doc:"Change timestamp"`
	Source    string      `json:"source" example:"web" doc:"Change source"`
}

// LoginActivity represents login activity summary
type LoginActivity struct {
	TotalLogins     int       `json:"totalLogins" example:"25" doc:"Total logins in period"`
	LastLogin       time.Time `json:"lastLogin" example:"2023-01-01T12:00:00Z" doc:"Last login timestamp"`
	AveragePerDay   float64   `json:"averagePerDay" example:"1.2" doc:"Average logins per day"`
	UniqueDevices   int       `json:"uniqueDevices" example:"3" doc:"Number of unique devices"`
	UniqueLocations int       `json:"uniqueLocations" example:"2" doc:"Number of unique locations"`
}

// DeviceActivity represents device usage activity
type DeviceActivity struct {
	DeviceType string    `json:"deviceType" example:"desktop" doc:"Device type"`
	DeviceID   string    `json:"deviceId" example:"device-123" doc:"Device identifier"`
	LoginCount int       `json:"loginCount" example:"15" doc:"Number of logins from device"`
	LastUsed   time.Time `json:"lastUsed" example:"2023-01-01T12:00:00Z" doc:"Last used timestamp"`
	UserAgent  string    `json:"userAgent" example:"Mozilla/5.0..." doc:"User agent string"`
	IsActive   bool      `json:"isActive" example:"true" doc:"Whether device is currently active"`
}

// LocationActivity represents location-based activity
type LocationActivity struct {
	Location     string    `json:"location" example:"New York, NY" doc:"Location name"`
	IPAddress    string    `json:"ipAddress" example:"192.168.1.1" doc:"IP address"`
	LoginCount   int       `json:"loginCount" example:"20" doc:"Number of logins from location"`
	LastUsed     time.Time `json:"lastUsed" example:"2023-01-01T12:00:00Z" doc:"Last used timestamp"`
	IsSuspicious bool      `json:"isSuspicious" example:"false" doc:"Whether location is flagged as suspicious"`
}

// ProfileSuggestion represents a profile improvement suggestion
type ProfileSuggestion struct {
	Type        string      `json:"type" example:"completion" doc:"Suggestion type"`
	Title       string      `json:"title" example:"Add Profile Picture" doc:"Suggestion title"`
	Description string      `json:"description" example:"Adding a profile picture helps others recognize you" doc:"Suggestion description"`
	Priority    string      `json:"priority" example:"medium" doc:"Suggestion priority (low, medium, high)"`
	Action      string      `json:"action" example:"upload_image" doc:"Required action"`
	Data        interface{} `json:"data,omitempty" doc:"Additional suggestion data"`
}
