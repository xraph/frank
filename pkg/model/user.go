package model

import (
	"time"

	"github.com/rs/xid"
)

// User represents a user in the system
type User struct {
	Base
	Email                 string                 `json:"email" example:"user@example.com" doc:"User email address"`
	PhoneNumber           string                 `json:"phoneNumber,omitempty" example:"+1234567890" doc:"User phone number"`
	FirstName             string                 `json:"firstName,omitempty" example:"John" doc:"User first name"`
	LastName              string                 `json:"lastName,omitempty" example:"Doe" doc:"User last name"`
	Username              string                 `json:"username,omitempty" example:"johndoe" doc:"Username"`
	EmailVerified         bool                   `json:"emailVerified" example:"true" doc:"Whether email is verified"`
	PhoneVerified         bool                   `json:"phoneVerified" example:"false" doc:"Whether phone is verified"`
	Active                bool                   `json:"active" example:"true" doc:"Whether user is active"`
	Blocked               bool                   `json:"blocked" example:"false" doc:"Whether user is blocked"`
	LastLogin             *time.Time             `json:"lastLogin,omitempty" example:"2023-01-01T12:00:00Z" doc:"Last login timestamp"`
	LastPasswordChange    *time.Time             `json:"lastPasswordChange,omitempty" example:"2023-01-01T10:00:00Z" doc:"Last password change timestamp"`
	Metadata              map[string]interface{} `json:"metadata,omitempty" doc:"Additional user metadata"`
	ProfileImageURL       string                 `json:"profileImageUrl,omitempty" example:"https://example.com/avatar.jpg" doc:"Profile image URL"`
	Locale                string                 `json:"locale" example:"en" doc:"User locale"`
	Timezone              string                 `json:"timezone,omitempty" example:"America/New_York" doc:"User timezone"`
	UserType              UserType               `json:"userType" example:"external" doc:"User type (internal, external, end_user)" enum:"internal,external,end_user"`
	OrganizationID        *xid.ID                `json:"organizationId,omitempty" example:"01FZS6TV7KP869DR7RXNEHXQKX" doc:"Primary organization ID"`
	PrimaryOrganizationID *xid.ID                `json:"primaryOrganizationId,omitempty" example:"01FZS6TV7KP869DR7RXNEHXQKX" doc:"Primary organization for multi-org users"`
	IsPlatformAdmin       bool                   `json:"isPlatformAdmin" example:"false" doc:"Whether user is a platform administrator"`
	AuthProvider          string                 `json:"authProvider" example:"internal" doc:"Authentication provider"`
	ExternalID            string                 `json:"externalId,omitempty" example:"google_123456" doc:"External provider user ID"`
	CustomerID            string                 `json:"customerId,omitempty" example:"cus_123456" doc:"Customer management system ID"`
	CustomAttributes      map[string]interface{} `json:"customAttributes,omitempty" doc:"Custom user attributes"`
	CreatedBy             string                 `json:"createdBy,omitempty" example:"01FZS6TV7KP869DR7RXNEHXQKX" doc:"User who created this user"`
	LoginCount            int                    `json:"loginCount" example:"42" doc:"Number of logins"`
	LastLoginIP           string                 `json:"lastLoginIp,omitempty" example:"192.168.1.1" doc:"Last login IP address"`
	PasswordHash          string                 `json:"-"`

	// Relationships
	MFAEnabled    bool                       `json:"mfaEnabled,omitempty" doc:"Whether MFA is enabled for this user"`
	Organizations []OrganizationSummary      `json:"organizations,omitempty" doc:"Organizations this user belongs to"`
	Roles         []UserRoleAssignment       `json:"roles,omitempty" doc:"User role assignments"`
	Permissions   []UserPermissionAssignment `json:"permissions,omitempty" doc:"Direct permission assignments"`
	MFAMethods    []MFAMethod                `json:"mfaMethods,omitempty" doc:"MFA methods configured for this user"`
	Sessions      []SessionInfo              `json:"sessions,omitempty" doc:"Active sessions for this user"`
}

// UserSummary represents a simplified user for listings
type UserSummary struct {
	ID              xid.ID     `json:"id" example:"01FZS6TV7KP869DR7RXNEHXQKX" doc:"User ID"`
	Email           string     `json:"email" example:"user@example.com" doc:"User email"`
	PhoneNumber     string     `json:"phoneNumber" example:"+555555555555" doc:"Phone number"`
	FirstName       string     `json:"firstName,omitempty" example:"John" doc:"First name"`
	LastName        string     `json:"lastName,omitempty" example:"Doe" doc:"Last name"`
	Username        string     `json:"username,omitempty" example:"johndoe" doc:"Username"`
	ProfileImageURL string     `json:"profileImageUrl,omitempty" example:"https://example.com/avatar.jpg" doc:"Profile image URL"`
	UserType        UserType   `json:"userType" example:"external" doc:"User type"`
	Active          bool       `json:"active" example:"true" doc:"Whether user is active"`
	LastLogin       *time.Time `json:"lastLogin,omitempty" example:"2023-01-01T12:00:00Z" doc:"Last login"`
	CreatedAt       time.Time  `json:"createdAt" example:"2023-01-01T10:00:00Z" doc:"Creation timestamp"`
}

// CreateUserRequest represents a request to create a new user
type CreateUserRequest struct {
	Email                  string                 `json:"email" example:"newuser@example.com" doc:"User email address"`
	PhoneNumber            *string                `json:"phoneNumber,omitempty" example:"+1234567890" doc:"User phone number"`
	FirstName              *string                `json:"firstName,omitempty" example:"John" doc:"User first name"`
	LastName               *string                `json:"lastName,omitempty" example:"Doe" doc:"User last name"`
	Username               *string                `json:"username,omitempty" example:"johndoe" doc:"Username"`
	Password               string                 `json:"password,omitempty" example:"password123" doc:"User password (optional for passwordless)"`
	PasswordHash           string                 `json:"password_hash" example:"password123" doc:"Password hash (optional for passwordless)"`
	UserType               UserType               `json:"userType" example:"external" doc:"User type (internal, external, end_user)"`
	OrganizationID         *xid.ID                `json:"organizationId,omitempty" example:"01FZS6TV7KP869DR7RXNEHXQKX" doc:"Organization ID"`
	Locale                 string                 `json:"locale" example:"en" doc:"User locale"`
	Timezone               string                 `json:"timezone,omitempty" example:"America/New_York" doc:"User timezone"`
	AuthProvider           string                 `json:"authProvider" example:"internal" doc:"Authentication provider"`
	ExternalID             *string                `json:"externalId,omitempty" example:"google_123456" doc:"External provider ID"`
	CustomAttributes       map[string]interface{} `json:"customAttributes,omitempty" doc:"Custom user attributes"`
	EmailVerified          bool                   `json:"emailVerified" example:"false" doc:"Whether email is pre-verified"`
	PhoneVerified          bool                   `json:"phoneVerified" example:"false" doc:"Whether phone is pre-verified"`
	SendVerificationEmail  bool                   `json:"sendVerificationEmail" example:"true" doc:"Whether to send verification email"`
	SkipPasswordValidation bool                   `json:"skipPasswordValidation" example:"false" doc:"Skip password strength validation"`
	Active                 bool                   `json:"active" example:"true" doc:"Whether user is active"`
	CreatedByIP            string                 `json:"createdByIp" example:"10.0.0.1" doc:"User created by IP"`
	CreatedByUserAgent     string                 `json:"createdByUserAgent" example="Mozilla" doc:"User created by agent"`
}

// UpdateUserRequest represents a request to update a user
type UpdateUserRequest struct {
	Email            *string                `json:"email,omitempty" example:"updated@example.com" doc:"Updated email address"`
	PhoneNumber      *string                `json:"phoneNumber,omitempty" example:"+1234567890" doc:"Updated phone number"`
	FirstName        *string                `json:"firstName,omitempty" example:"John" doc:"Updated first name"`
	LastName         *string                `json:"lastName,omitempty" example:"Doe" doc:"Updated last name"`
	Username         *string                `json:"username,omitempty" example:"johndoe" doc:"Updated username"`
	ProfileImageURL  *string                `json:"profileImageUrl,omitempty" example:"https://example.com/avatar.jpg" doc:"Updated profile image URL"`
	Locale           *string                `json:"locale,omitempty" example:"en" doc:"Updated locale"`
	Timezone         *string                `json:"timezone,omitempty" example:"America/New_York" doc:"Updated timezone"`
	CustomAttributes map[string]interface{} `json:"customAttributes,omitempty" doc:"Updated custom attributes"`
	Active           *bool                  `json:"active,omitempty" example:"true" doc:"Updated active status"`
	Blocked          *bool                  `json:"blocked,omitempty" example:"false" doc:"Updated blocked status"`
}

// ChangePasswordRequest represents a password change request
type ChangePasswordRequest struct {
	CurrentPassword string `json:"currentPassword" example:"oldpassword123" doc:"Current password"`
	NewPassword     string `json:"newPassword" example:"newpassword456" doc:"New password"`
}

// SetPasswordRequest represents a request to set a password (admin only)
type SetPasswordRequest struct {
	Password  string `json:"password" example:"newpassword123" doc:"New password"`
	Temporary bool   `json:"temporary" example:"false" doc:"Whether password is temporary and must be changed on next login"`
}

// UserRoleAssignment represents a user's role assignment
type UserRoleAssignment struct {
	ID          xid.ID     `json:"id" example:"01FZS6TV7KP869DR7RXNEHXQKX" doc:"Assignment ID"`
	RoleID      xid.ID     `json:"roleId" example:"01FZS6TV7KP869DR7RXNEHXQKX" doc:"Role ID"`
	RoleName    string     `json:"roleName" example:"admin" doc:"Role name"`
	DisplayName string     `json:"displayName" example:"Administrator" doc:"Role display name"`
	ContextType string     `json:"contextType" example:"organization" doc:"Assignment context type"`
	ContextID   *xid.ID    `json:"contextId,omitempty" example:"01FZS6TV7KP869DR7RXNEHXQKX" doc:"Context ID"`
	AssignedBy  *xid.ID    `json:"assignedBy,omitempty" example:"01FZS6TV7KP869DR7RXNEHXQKX" doc:"Who assigned this role"`
	AssignedAt  time.Time  `json:"assignedAt" example:"2023-01-01T12:00:00Z" doc:"When role was assigned"`
	ExpiresAt   *time.Time `json:"expiresAt,omitempty" example:"2023-12-31T23:59:59Z" doc:"When assignment expires"`
	Active      bool       `json:"active" example:"true" doc:"Whether assignment is active"`
}

// UserPermissionAssignment represents a user's direct permission assignment
type UserPermissionAssignment struct {
	ID             xid.ID                 `json:"id" example:"01FZS6TV7KP869DR7RXNEHXQKX" doc:"Assignment ID"`
	PermissionID   xid.ID                 `json:"permissionId" example:"01FZS6TV7KP869DR7RXNEHXQKX" doc:"Permission ID"`
	PermissionName string                 `json:"permissionName" example:"read:users" doc:"Permission name"`
	DisplayName    string                 `json:"displayName" example:"Read Users" doc:"Permission display name"`
	ContextType    string                 `json:"contextType" example:"organization" doc:"Assignment context type"`
	ContextID      *xid.ID                `json:"contextId,omitempty" example:"01FZS6TV7KP869DR7RXNEHXQKX" doc:"Context ID"`
	ResourceType   string                 `json:"resourceType,omitempty" example:"user" doc:"Specific resource type"`
	ResourceID     *xid.ID                `json:"resourceId,omitempty" example:"01FZS6TV7KP869DR7RXNEHXQKX" doc:"Specific resource ID"`
	PermissionType string                 `json:"permissionType" example:"grant" doc:"Permission type (grant, deny)"`
	AssignedBy     *xid.ID                `json:"assignedBy,omitempty" example:"01FZS6TV7KP869DR7RXNEHXQKX" doc:"Who assigned this permission"`
	AssignedAt     time.Time              `json:"assignedAt" example:"2023-01-01T12:00:00Z" doc:"When permission was assigned"`
	ExpiresAt      *time.Time             `json:"expiresAt,omitempty" example:"2023-12-31T23:59:59Z" doc:"When assignment expires"`
	Active         bool                   `json:"active" example:"true" doc:"Whether assignment is active"`
	Conditions     map[string]interface{} `json:"conditions,omitempty" doc:"Optional conditions for permission"`
	Reason         string                 `json:"reason,omitempty" example:"Special project access" doc:"Reason for assignment"`
}

// AssignRoleRequest represents a request to assign a role to a user
type AssignRoleRequest struct {
	RoleID      xid.ID                 `json:"roleId" example:"01FZS6TV7KP869DR7RXNEHXQKX" doc:"Role ID to assign"`
	ContextType string                 `json:"contextType" example:"organization" doc:"Assignment context type"`
	ContextID   *xid.ID                `json:"contextId,omitempty" example:"01FZS6TV7KP869DR7RXNEHXQKX" doc:"Context ID"`
	ExpiresAt   *time.Time             `json:"expiresAt,omitempty" example:"2023-12-31T23:59:59Z" doc:"When assignment expires"`
	Conditions  map[string]interface{} `json:"conditions,omitempty" doc:"Optional conditions for role"`
}

// AssignPermissionRequest represents a request to assign a permission to a user
type AssignPermissionRequest struct {
	PermissionID   xid.ID                 `json:"permissionId" example:"01FZS6TV7KP869DR7RXNEHXQKX" doc:"Permission ID to assign"`
	ContextType    string                 `json:"contextType" example:"organization" doc:"Assignment context type"`
	ContextID      *xid.ID                `json:"contextId,omitempty" example:"01FZS6TV7KP869DR7RXNEHXQKX" doc:"Context ID"`
	ResourceType   string                 `json:"resourceType,omitempty" example:"user" doc:"Specific resource type"`
	ResourceID     *xid.ID                `json:"resourceId,omitempty" example:"01FZS6TV7KP869DR7RXNEHXQKX" doc:"Specific resource ID"`
	PermissionType string                 `json:"permissionType" example:"grant" doc:"Permission type (grant, deny)"`
	ExpiresAt      *time.Time             `json:"expiresAt,omitempty" example:"2023-12-31T23:59:59Z" doc:"When assignment expires"`
	Conditions     map[string]interface{} `json:"conditions,omitempty" doc:"Optional conditions for permission"`
	Reason         string                 `json:"reason,omitempty" example:"Special project access" doc:"Reason for assignment"`
}

// UserListRequest represents a request to list users
type UserListRequest struct {
	PaginationParams
	OrganizationID *xid.ID             `json:"organizationId,omitempty" example:"01FZS6TV7KP869DR7RXNEHXQKX" doc:"Filter by organization"`
	UserType       UserType            `json:"userType,omitempty" example:"external" doc:"Filter by user type"`
	Active         OptionalParam[bool] `json:"active,omitempty" example:"true" doc:"Filter by active status"`
	Blocked        OptionalParam[bool] `json:"blocked,omitempty" example:"false" doc:"Filter by blocked status"`
	Search         string              `json:"search,omitempty" example:"john" doc:"Search in name, email, username"`
	AuthProvider   string              `json:"authProvider,omitempty" example:"google" doc:"Filter by auth provider"`
}

// UserListResponse represents a list of users
type UserListResponse = PaginatedOutput[UserSummary]

// UserProfileUpdateRequest represents a user profile update by the user themselves
type UserProfileUpdateRequest struct {
	FirstName        string                 `json:"firstName,omitempty" example:"John" doc:"Updated first name"`
	LastName         string                 `json:"lastName,omitempty" example:"Doe" doc:"Updated last name"`
	Username         string                 `json:"username,omitempty" example:"johndoe" doc:"Updated username"`
	ProfileImageURL  string                 `json:"profileImageUrl,omitempty" example:"https://example.com/avatar.jpg" doc:"Updated profile image URL"`
	Locale           string                 `json:"locale,omitempty" example:"en" doc:"Updated locale"`
	Timezone         string                 `json:"timezone,omitempty" example:"America/New_York" doc:"Updated timezone"`
	CustomAttributes map[string]interface{} `json:"customAttributes,omitempty" doc:"Updated custom attributes"`
}

// UserStats represents user statistics
type UserStats struct {
	TotalUsers     int `json:"totalUsers" example:"1000" doc:"Total number of users"`
	ActiveUsers    int `json:"activeUsers" example:"950" doc:"Number of active users"`
	InternalUsers  int `json:"internalUsers" example:"10" doc:"Number of internal users"`
	ExternalUsers  int `json:"externalUsers" example:"800" doc:"Number of external users"`
	EndUsers       int `json:"endUsers" example:"190" doc:"Number of end users"`
	VerifiedEmails int `json:"verifiedEmails" example:"900" doc:"Number of users with verified emails"`
	VerifiedPhones int `json:"verifiedPhones" example:"400" doc:"Number of users with verified phones"`
	MFAEnabled     int `json:"mfaEnabled" example:"300" doc:"Number of users with MFA enabled"`
	RecentLogins   int `json:"recentLogins" example:"150" doc:"Number of users logged in recently"`
}

// DeleteUserRequest represents a request to delete a user
type DeleteUserRequest struct {
	TransferDataTo *xid.ID `json:"transferDataTo,omitempty" example:"01FZS6TV7KP869DR7RXNEHXQKX" doc:"User ID to transfer data to"`
	Reason         string  `json:"reason,omitempty" example:"User requested account deletion" doc:"Reason for deletion"`
}

// BulkUserOperation represents a bulk operation on users
type BulkUserOperation struct {
	UserIDs        []xid.ID `json:"userIds" example:"[\"01FZS6TV7KP869DR7RXNEHXQKX\"]" doc:"List of user IDs"`
	OrganizationID *xid.ID  `json:"organizationId,omitempty" example:"01FZS6TV7KP869DR7RXNEHXQKX" doc:"Organization ID"`
	Operation      string   `json:"operation" example:"activate" doc:"Operation to perform (activate, deactivate, block, unblock)"`
	Reason         string   `json:"reason,omitempty" example:"Bulk activation" doc:"Reason for operation"`
}

// BulkUserOperationResponse represents the response to a bulk operation
type BulkUserOperationResponse struct {
	Success      []xid.ID `json:"success" example:"[\"01FZS6TV7KP869DR7RXNEHXQKX\"]" doc:"Successfully processed user IDs"`
	Failed       []xid.ID `json:"failed" example:"[]" doc:"Failed user IDs"`
	SuccessCount int      `json:"successCount" example:"1" doc:"Number of successful operations"`
	FailureCount int      `json:"failureCount" example:"0" doc:"Number of failed operations"`
	Errors       []string `json:"errors,omitempty" example:"[]" doc:"Error messages for failed operations"`
}

// UserActivityRequest represents a request for user activity
type UserActivityRequest struct {
	StartDate *time.Time `json:"startDate,omitempty" example:"2023-01-01T00:00:00Z" doc:"OnStart date for activity"`
	EndDate   *time.Time `json:"endDate,omitempty" example:"2023-01-31T23:59:59Z" doc:"End date for activity"`
	Limit     int        `json:"limit,omitempty" example:"50" doc:"Maximum number of results"`
	Offset    int        `json:"offset,omitempty" example:"0" doc:"Number of results to skip"`
}

// UserActivity represents user activity information
type UserActivity struct {
	Event     string                 `json:"event" example:"login" doc:"Activity event type"`
	Timestamp time.Time              `json:"timestamp" example:"2023-01-01T12:00:00Z" doc:"Activity timestamp"`
	IPAddress string                 `json:"ipAddress,omitempty" example:"192.168.1.1" doc:"IP address"`
	UserAgent string                 `json:"userAgent,omitempty" example:"Mozilla/5.0..." doc:"User agent"`
	Location  string                 `json:"location,omitempty" example:"New York, NY" doc:"Location"`
	Details   map[string]interface{} `json:"details,omitempty" doc:"Additional activity details"`
	Success   bool                   `json:"success" example:"true" doc:"Whether activity was successful"`
	Error     string                 `json:"error,omitempty" example:"Invalid credentials" doc:"Error message if failed"`
}

// UserActivityResponse represents user activity response
type UserActivityResponse = PaginatedOutput[UserActivity]
