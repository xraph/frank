package model

import (
	"time"

	"github.com/rs/xid"
)

// Membership represents a user's membership in an organization
type Membership struct {
	Base
	AuditBase
	UserID           xid.ID                 `json:"userId" example:"01FZS6TV7KP869DR7RXNEHXQKX" doc:"User ID"`
	OrganizationID   xid.ID                 `json:"organizationId" example:"01FZS6TV7KP869DR7RXNEHXQKX" doc:"Organization ID"`
	RoleID           xid.ID                 `json:"roleId" example:"01FZS6TV7KP869DR7RXNEHXQKX" doc:"Role ID"`
	Status           MembershipStatus       `json:"status" example:"active" doc:"Membership status (pending, active, inactive, suspended)" enum:"active,inactive,suspended,pending"`
	InvitedBy        *xid.ID                `json:"invitedBy,omitempty" example:"01FZS6TV7KP869DR7RXNEHXQKX" doc:"User who sent the invitation"`
	InvitedAt        time.Time              `json:"invitedAt" example:"2023-01-01T12:00:00Z" doc:"Invitation timestamp"`
	JoinedAt         *time.Time             `json:"joinedAt,omitempty" example:"2023-01-01T12:30:00Z" doc:"When user accepted invitation"`
	IsOwner          bool                   `json:"isOwner" example:"false" doc:"Whether member is organization owner"`
	ExpiresAt        *time.Time             `json:"expiresAt,omitempty" example:"2023-01-31T23:59:59Z" doc:"When invitation expires"`
	InvitationToken  string                 `json:"invitationToken,omitempty" example:"inv_token_123" doc:"Invitation token"`
	IsBillingContact bool                   `json:"isBillingContact" example:"false" doc:"Whether member receives billing notifications"`
	IsPrimaryContact bool                   `json:"isPrimaryContact" example:"false" doc:"Whether member is primary contact"`
	LeftAt           *time.Time             `json:"leftAt,omitempty" example:"2023-12-31T12:00:00Z" doc:"When user left the organization"`
	Metadata         map[string]interface{} `json:"metadata,omitempty" doc:"Additional membership metadata"`
	CustomFields     map[string]interface{} `json:"customFields,omitempty" doc:"Custom membership fields"`
	Notes            string                 `json:"notes,omitempty" example:"Senior developer with admin access" doc:"Internal notes about membership"`

	// Relationships
	User         *UserSummary         `json:"user,omitempty" doc:"User information"`
	Organization *OrganizationSummary `json:"organization,omitempty" doc:"Organization information"`
	Role         *RoleSummary         `json:"role,omitempty" doc:"Role information"`
	Inviter      *UserSummary         `json:"inviter,omitempty" doc:"User who sent invitation"`
}

// MembershipSummary represents a simplified membership for listings
type MembershipSummary struct {
	ID               xid.ID           `json:"id" example:"01FZS6TV7KP869DR7RXNEHXQKX" doc:"Membership ID"`
	UserID           xid.ID           `json:"userId" example:"01FZS6TV7KP869DR7RXNEHXQKX" doc:"User ID"`
	OrganizationID   xid.ID           `json:"organizationId" example:"01FZS6TV7KP869DR7RXNEHXQKX" doc:"Organization ID"`
	UserEmail        string           `json:"userEmail" example:"member@acme.com" doc:"User email"`
	UserName         string           `json:"userName" example:"John Doe" doc:"User full name"`
	OrganizationName string           `json:"organizationName" example:"Acme Corp" doc:"Organization name"`
	RoleName         string           `json:"roleName" example:"admin" doc:"Role name"`
	Status           MembershipStatus `json:"status" example:"active" doc:"Membership status"`
	JoinedAt         *time.Time       `json:"joinedAt,omitempty" example:"2023-01-01T12:00:00Z" doc:"Join timestamp"`
	IsBillingContact bool             `json:"isBillingContact" example:"false" doc:"Billing contact status"`
	IsPrimaryContact bool             `json:"isPrimaryContact" example:"false" doc:"Primary contact status"`
	CreatedAt        time.Time        `json:"createdAt" example:"2023-01-01T10:00:00Z" doc:"Creation timestamp"`
}

// CreateMembershipRequest represents a request to create a membership (invite user)
type CreateMembershipRequest struct {
	UserID              *xid.ID                `json:"userId,omitempty" example:"01FZS6TV7KP869DR7RXNEHXQKX" doc:"Existing user ID"`
	Email               string                 `json:"email,omitempty" example:"newmember@acme.com" doc:"Email address (for new users)"`
	FirstName           string                 `json:"firstName,omitempty" example:"John" doc:"First name (for new users)"`
	LastName            string                 `json:"lastName,omitempty" example:"Doe" doc:"Last name (for new users)"`
	RoleID              xid.ID                 `json:"roleId" example:"01FZS6TV7KP869DR7RXNEHXQKX" doc:"Role ID to assign"`
	SendInvitationEmail bool                   `json:"sendInvitationEmail" example:"true" doc:"Whether to send invitation email"`
	InvitationMessage   string                 `json:"invitationMessage,omitempty" example:"Welcome to our team!" doc:"Custom invitation message"`
	ExpiresAt           *time.Time             `json:"expiresAt,omitempty" example:"2023-01-31T23:59:59Z" doc:"Invitation expiration"`
	IsBillingContact    bool                   `json:"isBillingContact" example:"false" doc:"Set as billing contact"`
	IsPrimaryContact    bool                   `json:"isPrimaryContact" example:"false" doc:"Set as primary contact"`
	Metadata            map[string]interface{} `json:"metadata,omitempty" doc:"Additional metadata"`
}

// CreateMembershipResponse represents the response to membership creation
type CreateMembershipResponse struct {
	Membership      Membership `json:"membership" doc:"Created membership"`
	InvitationSent  bool       `json:"invitationSent" example:"true" doc:"Whether invitation email was sent"`
	InvitationToken string     `json:"invitationToken,omitempty" example:"inv_token_123" doc:"Invitation token (for testing)"`
	UserCreated     bool       `json:"userCreated" example:"false" doc:"Whether a new user was created"`
}

// UpdateMembershipRequest represents a request to update a membership
type UpdateMembershipRequest struct {
	RoleID           OptionalParam[xid.ID]                 `json:"roleId,omitempty" example:"01FZS6TV7KP869DR7RXNEHXQKX" doc:"Updated role ID"`
	Status           OptionalParam[string]                 `json:"status,omitempty" example:"active" doc:"Updated status"`
	IsBillingContact OptionalParam[bool]                   `json:"isBillingContact,omitempty" example:"true" doc:"Updated billing contact status"`
	IsPrimaryContact OptionalParam[bool]                   `json:"isPrimaryContact,omitempty" example:"true" doc:"Updated primary contact status"`
	ExpiresAt        OptionalParam[*time.Time]             `json:"expiresAt,omitempty" example:"2023-12-31T23:59:59Z" doc:"Updated expiration"`
	Metadata         OptionalParam[map[string]interface{}] `json:"metadata,omitempty" doc:"Updated metadata"`
}

// InviteUserRequest represents a request to invite a user to an organization
type InviteUserRequest struct {
	Email            string                 `json:"email" example:"newuser@example.com" doc:"Email address of user to invite"`
	FirstName        string                 `json:"firstName,omitempty" example:"John" doc:"First name"`
	LastName         string                 `json:"lastName,omitempty" example:"Doe" doc:"Last name"`
	RoleID           xid.ID                 `json:"roleId" example:"01FZS6TV7KP869DR7RXNEHXQKX" doc:"Role to assign"`
	Message          string                 `json:"message,omitempty" example:"Join our team!" doc:"Custom invitation message"`
	ExpiresInHours   int                    `json:"expiresInHours" example:"168" doc:"Invitation expiration in hours (default 168 = 7 days)"`
	IsBillingContact bool                   `json:"isBillingContact" example:"false" doc:"Set as billing contact"`
	IsPrimaryContact bool                   `json:"isPrimaryContact" example:"false" doc:"Set as primary contact"`
	SendEmail        bool                   `json:"sendEmail" example:"true" doc:"Whether to send invitation email"`
	Metadata         map[string]interface{} `json:"metadata,omitempty" doc:"Additional metadata"`
}

// InviteUserResponse represents the response to user invitation
type InviteUserResponse struct {
	InvitationID    xid.ID    `json:"invitationId" example:"01FZS6TV7KP869DR7RXNEHXQKX" doc:"Invitation ID"`
	InvitationToken string    `json:"invitationToken" example:"inv_token_123" doc:"Invitation token"`
	InvitationURL   string    `json:"invitationUrl" example:"https://app.example.com/invite/inv_token_123" doc:"Invitation URL"`
	EmailSent       bool      `json:"emailSent" example:"true" doc:"Whether invitation email was sent"`
	ExpiresAt       time.Time `json:"expiresAt" example:"2023-01-08T12:00:00Z" doc:"Invitation expiration"`
}

// BulkInviteRequest represents a request to invite multiple users
type BulkInviteRequest struct {
	Invitations []InviteUserRequest `json:"invitations" doc:"List of invitations to send"`
}

// BulkInviteResponse represents the response to bulk invitations
type BulkInviteResponse struct {
	Success      []InviteUserResponse `json:"success" doc:"Successfully sent invitations"`
	Failed       []BulkInviteError    `json:"failed,omitempty" doc:"Failed invitations"`
	SuccessCount int                  `json:"successCount" example:"8" doc:"Number of successful invitations"`
	FailureCount int                  `json:"failureCount" example:"2" doc:"Number of failed invitations"`
}

// BulkInviteError represents a failed invitation in bulk invite
type BulkInviteError struct {
	Email string `json:"email" example:"invalid@email" doc:"Email that failed"`
	Error string `json:"error" example:"Invalid email address" doc:"Error message"`
	Index int    `json:"index" example:"5" doc:"Index in original request"`
}

// ListMembershipsParams represents parameters for listing memberships
type ListMembershipsParams struct {
	PaginationParams
	OrganizationID   OptionalParam[xid.ID]           `json:"organizationId,omitempty" example:"01FZS6TV7KP869DR7RXNEHXQKX" doc:"Filter by organization"`
	Status           OptionalParam[MembershipStatus] `json:"status,omitempty"`
	RoleID           OptionalParam[xid.ID]           `json:"role_id,omitempty"`
	IsBillingContact OptionalParam[bool]             `json:"is_billing_contact,omitempty"`
	IsPrimaryContact OptionalParam[bool]             `json:"is_primary_contact,omitempty"`
	InvitedBy        OptionalParam[xid.ID]           `json:"invited_by,omitempty"`
	Search           string                          `json:"search,omitempty" example:"john" doc:"Search in user name/email"`
}

// MembershipListResponse represents a list of memberships
type MembershipListResponse = PaginatedOutput[MembershipSummary]

// MemberListResponse represents a list of memberships
type MemberListResponse = PaginatedOutput[MemberSummary]

// PendingInvitation represents a pending invitation
type PendingInvitation struct {
	ID              xid.ID     `json:"id" example:"01FZS6TV7KP869DR7RXNEHXQKX" doc:"Invitation ID"`
	Email           string     `json:"email" example:"pending@example.com" doc:"Invited email"`
	FirstName       string     `json:"firstName,omitempty" example:"John" doc:"First name"`
	LastName        string     `json:"lastName,omitempty" example:"Doe" doc:"Last name"`
	RoleName        string     `json:"roleName" example:"member" doc:"Role name"`
	InvitedBy       string     `json:"invitedBy" example:"admin@example.com" doc:"Who sent invitation"`
	InvitedAt       time.Time  `json:"invitedAt" example:"2023-01-01T12:00:00Z" doc:"Invitation timestamp"`
	ExpiresAt       *time.Time `json:"expiresAt,omitempty" example:"2023-01-08T12:00:00Z" doc:"Expiration timestamp"`
	IsExpired       bool       `json:"isExpired" example:"false" doc:"Whether invitation is expired"`
	InvitationToken string     `json:"invitationToken,omitempty" example:"inv_token_123" doc:"Invitation token"`
	Status          string     `json:"status" example:"pending" doc:"Invitation status"`
}

// RemoveMemberRequest represents a request to remove a member
type RemoveMemberRequest struct {
	Reason         string  `json:"reason,omitempty" example:"User left company" doc:"Reason for removal"`
	TransferDataTo *xid.ID `json:"transferDataTo,omitempty" example:"01FZS6TV7KP869DR7RXNEHXQKX" doc:"User to transfer data to"`
	NotifyUser     bool    `json:"notifyUser" example:"true" doc:"Whether to notify the user"`
}

// TransferOwnershipRequest represents a request to transfer organization ownership
type TransferOwnershipRequest struct {
	NewOwnerMembershipID xid.ID `json:"newOwnerMembershipId" example:"01FZS6TV7KP869DR7RXNEHXQKX" doc:"Membership ID of new owner"`
	Reason               string `json:"reason,omitempty" example:"Ownership transfer" doc:"Reason for transfer"`
	NotifyNewOwner       bool   `json:"notifyNewOwner" example:"true" doc:"Whether to notify new owner"`
}

// MembershipStats represents membership statistics
type MembershipStats struct {
	TotalMembers       int            `json:"totalMembers" example:"25" doc:"Total members"`
	ActiveMembers      int            `json:"activeMembers" example:"23" doc:"Active members"`
	PendingInvitations int            `json:"pendingInvitations" example:"3" doc:"Pending invitations"`
	ExpiredInvitations int            `json:"expiredInvitations" example:"1" doc:"Expired invitations"`
	SuspendedMembers   int            `json:"suspendedMembers" example:"1" doc:"Suspended members"`
	InactiveMembers    int            `json:"inactiveMembers" example:"1" doc:"Inactive members"`
	BillingContacts    int            `json:"billingContacts" example:"2" doc:"Billing contacts"`
	PrimaryContacts    int            `json:"primaryContacts" example:"1" doc:"Primary contacts"`
	MembersByRole      map[string]int `json:"membersByRole" example:"{\"admin\": 3, \"member\": 20}" doc:"Members by role"`
	RecentJoins        int            `json:"recentJoins" example:"5" doc:"Members joined in last 30 days"`
	RecentInvites      int            `json:"recentInvites" example:"8" doc:"Invitations sent in last 30 days"`
	GrowthRate         float64        `json:"growthRate" example:"0.5" doc:"Growth rate"`
}

// MembershipActivity represents membership activity
type MembershipActivity struct {
	ID           xid.ID                 `json:"id" example:"01FZS6TV7KP869DR7RXNEHXQKX" doc:"Activity ID"`
	MembershipID xid.ID                 `json:"membershipId" example:"01FZS6TV7KP869DR7RXNEHXQKX" doc:"Membership ID"`
	UserID       xid.ID                 `json:"userId" example:"01FZS6TV7KP869DR7RXNEHXQKX" doc:"Member ID"`
	UserEmail    string                 `json:"userEmail" example:"member@example.com" doc:"User email"`
	Action       string                 `json:"action" example:"role_changed" doc:"Action performed"`
	Description  string                 `json:"description" example:"Role changed from member to admin" doc:"Action description"`
	ActorEmail   string                 `json:"actorEmail" example:"admin@example.com" doc:"Who performed the action"`
	Timestamp    time.Time              `json:"timestamp" example:"2023-01-01T12:00:00Z" doc:"Activity timestamp"`
	Metadata     map[string]interface{} `json:"metadata,omitempty" doc:"Additional metadata"`
}

// MembershipActivityRequest represents a request for membership activity
type MembershipActivityRequest struct {
	PaginationParams
	MembershipID OptionalParam[xid.ID]    `json:"membershipId,omitempty" example:"01FZS6TV7KP869DR7RXNEHXQKX" doc:"Filter by membership" query:"membershipId"`
	UserID       OptionalParam[xid.ID]    `json:"userId,omitempty" example:"01FZS6TV7KP869DR7RXNEHXQKX" doc:"Filter by user" query:"userId"`
	Actions      []string                 `json:"actions,omitempty" example:"[\"invited\", \"joined\", \"role_changed\"]" doc:"Filter by actions" query:"actions"`
	StartDate    OptionalParam[time.Time] `json:"startDate,omitempty" example:"2023-01-01T00:00:00Z" doc:"Start date" query:"startDate"`
	EndDate      OptionalParam[time.Time] `json:"endDate,omitempty" example:"2023-01-31T23:59:59Z" doc:"End date" query:"endDate"`
}

// MembershipActivityResponse represents membership activity response
type MembershipActivityResponse = PaginatedOutput[MembershipActivity]

// RoleSummary represents role summary information
type RoleSummary struct {
	ID          xid.ID   `json:"id" example:"01FZS6TV7KP869DR7RXNEHXQKX" doc:"Role ID"`
	Name        string   `json:"name" example:"admin" doc:"Role name"`
	DisplayName string   `json:"displayName" example:"Administrator" doc:"Role display name"`
	Description string   `json:"description,omitempty" example:"Full administrative access" doc:"Role description"`
	Priority    int      `json:"priority" example:"100" doc:"Role priority"`
	RoleType    RoleType `json:"roleType" example:"admin" doc:"Role type"`
	Active      bool     `json:"active" example:"true" doc:"Active role"`
}

// BulkMembershipOperation represents a bulk operation on memberships
type BulkMembershipOperation struct {
	MembershipIDs []xid.ID `json:"membershipIds" example:"[\"01FZS6TV7KP869DR7RXNEHXQKX\"]" doc:"Membership IDs"`
	Operation     string   `json:"operation" example:"suspend" doc:"Operation (suspend, activate, remove, change_role)"`
	RoleID        *xid.ID  `json:"roleId,omitempty" example:"01FZS6TV7KP869DR7RXNEHXQKX" doc:"New role ID (for change_role)"`
	Reason        string   `json:"reason,omitempty" example:"Bulk operation" doc:"Reason for operation"`
	NotifyUsers   bool     `json:"notifyUsers" example:"false" doc:"Whether to notify affected users"`
}

// BulkMembershipOperationResponse represents bulk operation response
type BulkMembershipOperationResponse struct {
	Success      []xid.ID `json:"success" example:"[\"01FZS6TV7KP869DR7RXNEHXQKX\"]" doc:"Successful membership IDs"`
	Failed       []xid.ID `json:"failed" example:"[]" doc:"Failed membership IDs"`
	SuccessCount int      `json:"successCount" example:"5" doc:"Number of successful operations"`
	FailureCount int      `json:"failureCount" example:"0" doc:"Number of failed operations"`
	Errors       []string `json:"errors,omitempty" example:"[]" doc:"Error messages"`
}

// BulkMemberRoleUpdate represents a bulk operation on memberships
type BulkMemberRoleUpdate struct {
	UserID      xid.ID `json:"userId" example:"01FZS6TV7KP869DR7RXNEHXQKX" doc:"User ID" required:"true"`
	RoleID      xid.ID `json:"roleId,omitempty" example:"01FZS6TV7KP869DR7RXNEHXQKX" doc:"New role ID (for change_role)" required:"true"`
	Reason      string `json:"reason,omitempty" example:"Bulk operation" doc:"Reason for operation"`
	NotifyUsers bool   `json:"notifyUsers" example:"false" doc:"Whether to notify affected users"`
}

// BulkMemberStatusUpdate represents a bulk operation on memberships
type BulkMemberStatusUpdate struct {
	UserID      xid.ID           `json:"userId" example:"01FZS6TV7KP869DR7RXNEHXQKX" doc:"User ID" required:"true"`
	Status      MembershipStatus `json:"status,omitempty" example:"active" doc:"Status of the membership" required:"true"`
	Reason      string           `json:"reason,omitempty" example:"Bulk operation" doc:"Reason for operation"`
	NotifyUsers bool             `json:"notifyUsers" example:"false" doc:"Whether to notify affected users"`
}

// BulkUpdateResponse represents bulk operation response
type BulkUpdateResponse struct {
	Success      []xid.ID `json:"success" example:"[\"01FZS6TV7KP869DR7RXNEHXQKX\"]" doc:"Successful membership IDs"`
	Failed       []xid.ID `json:"failed" example:"[]" doc:"Failed membership IDs"`
	SuccessCount int      `json:"successCount" example:"5" doc:"Number of successful operations"`
	FailureCount int      `json:"failureCount" example:"0" doc:"Number of failed operations"`
	Errors       []string `json:"errors,omitempty" example:"[]" doc:"Error messages"`
}

// MembershipChange represents a change to a membership
type MembershipChange struct {
	Type        string                 `json:"type" example:"role_change" doc:"Type of change" enum:"role_change,status_change,contact_change"`
	NewRoleID   *xid.ID                `json:"newRoleId,omitempty" example:"01FZS6TV7KP869DR7RXNEHXQKX" doc:"New role ID (for role changes)"`
	NewStatus   *MembershipStatus      `json:"newStatus,omitempty" example:"active" doc:"New status (for status changes)"`
	IsBilling   OptionalParam[bool]    `json:"isBilling,omitempty" doc:"New billing contact status"`
	IsPrimary   OptionalParam[bool]    `json:"isPrimary,omitempty" doc:"New primary contact status"`
	Reason      string                 `json:"reason,omitempty" example:"Promotion to admin" doc:"Reason for change"`
	Metadata    map[string]interface{} `json:"metadata,omitempty" doc:"Additional change metadata"`
	ScheduledAt *time.Time             `json:"scheduledAt,omitempty" example:"2023-01-15T12:00:00Z" doc:"When change should take effect"`
	ActorID     *xid.ID                `json:"actorId,omitempty" example:"01FZS6TV7KP869DR7RXNEHXQKX" doc:"User making the change"`
}

// MemberTrendPoint represents a point in member trend data
type MemberTrendPoint struct {
	Date          time.Time `json:"date" example:"2023-01-15T00:00:00Z" doc:"Date point"`
	TotalMembers  int       `json:"totalMembers" example:"145" doc:"Total members at this date"`
	ActiveMembers int       `json:"activeMembers" example:"138" doc:"Active members at this date"`
	NewMembers    int       `json:"newMembers" example:"5" doc:"New members on this date"`
	LeftMembers   int       `json:"leftMembers" example:"1" doc:"Members who left on this date"`
}

// MemberCohort represents member cohort analysis data
type MemberCohort struct {
	CohortMonth    string             `json:"cohortMonth" example:"2023-01" doc:"Cohort month (YYYY-MM)"`
	TotalMembers   int                `json:"totalMembers" example:"25" doc:"Total members in cohort"`
	RetentionRates map[string]float64 `json:"retentionRates" example:"{\"month_1\":95.0,\"month_6\":80.0}" doc:"Retention rates by month"`
	AvgLifetime    float64            `json:"avgLifetime" example:"18.5" doc:"Average lifetime in months"`
	ChurnedMembers int                `json:"churnedMembers" example:"5" doc:"Members who have churned"`
}

// MemberMetrics represents member metrics for a specific period
type MemberMetrics struct {
	Period        string    `json:"period" example:"30d" doc:"Metrics period"`
	StartDate     time.Time `json:"startDate" example:"2023-01-01T00:00:00Z" doc:"Period start date"`
	EndDate       time.Time `json:"endDate" example:"2023-01-31T23:59:59Z" doc:"Period end date"`
	TotalMembers  int       `json:"totalMembers" example:"150" doc:"Total members at end of period"`
	ActiveMembers int       `json:"activeMembers" example:"142" doc:"Active members at end of period"`
	NewMembers    int       `json:"newMembers" example:"15" doc:"New members added in period"`
	LeftMembers   int       `json:"leftMembers" example:"3" doc:"Members who left in period"`
	NetGrowth     int       `json:"netGrowth" example:"12" doc:"Net member growth in period"`
	GrowthRate    float64   `json:"growthRate" example:"8.7" doc:"Growth rate percentage"`
	ChurnRate     float64   `json:"churnRate" example:"2.1" doc:"Churn rate percentage"`
	RetentionRate float64   `json:"retentionRate" example:"97.9" doc:"Retention rate percentage"`

	// Activity metrics
	AverageEngagement  float64 `json:"averageEngagement" example:"75.5" doc:"Average member engagement score"`
	LoginRate          float64 `json:"loginRate" example:"89.2" doc:"Percentage of members who logged in"`
	DailyActiveUsers   int     `json:"dailyActiveUsers" example:"45" doc:"Average daily active users"`
	WeeklyActiveUsers  int     `json:"weeklyActiveUsers" example:"98" doc:"Average weekly active users"`
	MonthlyActiveUsers int     `json:"monthlyActiveUsers" example:"135" doc:"Average monthly active users"`

	// Breakdown by status
	StatusBreakdown map[string]int `json:"statusBreakdown" example:"{\"active\":142,\"inactive\":5}" doc:"Members by status"`

	// Breakdown by role
	RoleBreakdown map[string]MemberRoleMetrics `json:"roleBreakdown" doc:"Members by role"`

	// Geographic breakdown (if available)
	GeographicBreakdown map[string]int `json:"geographicBreakdown,omitempty" example:"{\"US\":120,\"EU\":20}" doc:"Members by region"`

	// Department breakdown (if available)
	DepartmentBreakdown map[string]int `json:"departmentBreakdown,omitempty" example:"{\"Engineering\":80,\"Sales\":30}" doc:"Members by department"`

	// Trend data
	TrendData []MemberTrendPoint `json:"trendData,omitempty" doc:"Historical trend data points"`

	// Cohort analysis
	CohortData []MemberCohort `json:"cohortData,omitempty" doc:"Member cohort analysis"`

	// Top performers
	TopActiveMembers      []MemberActivitySummary `json:"topActiveMembers,omitempty" doc:"Most active members"`
	TopInviters           []MemberInviterSummary  `json:"topInviters,omitempty" doc:"Top member inviters"`
	RecentJoins           []MemberSummary         `json:"recentJoins,omitempty" doc:"Recently joined members"`
	UpcomingAnniversaries []MemberAnniversary     `json:"upcomingAnniversaries,omitempty" doc:"Upcoming member anniversaries"`
}

// MemberActivitySummary represents a summary of member activity
type MemberActivitySummary struct {
	UserID           xid.ID    `json:"userId" example:"01FZS6TV7KP869DR7RXNEHXQKX" doc:"User ID"`
	Email            string    `json:"email" example:"active@example.com" doc:"User email"`
	FullName         string    `json:"fullName" example:"John Doe" doc:"User full name"`
	ActivityScore    float64   `json:"activityScore" example:"95.5" doc:"Activity score (0-100)"`
	LastActiveAt     time.Time `json:"lastActiveAt" example:"2023-01-15T14:30:00Z" doc:"Last activity timestamp"`
	TotalSessions    int       `json:"totalSessions" example:"145" doc:"Total sessions in period"`
	AvgSessionLength float64   `json:"avgSessionLength" example:"25.5" doc:"Average session length in minutes"`
	ActionsPerformed int       `json:"actionsPerformed" example:"1250" doc:"Total actions performed"`
}

// MemberInviterSummary represents a summary of member invitation activity
type MemberInviterSummary struct {
	UserID           xid.ID    `json:"userId" example:"01FZS6TV7KP869DR7RXNEHXQKX" doc:"User ID"`
	Email            string    `json:"email" example:"inviter@example.com" doc:"User email"`
	FullName         string    `json:"fullName" example:"Jane Smith" doc:"User full name"`
	TotalInvitations int       `json:"totalInvitations" example:"12" doc:"Total invitations sent"`
	AcceptedInvites  int       `json:"acceptedInvites" example:"10" doc:"Invitations accepted"`
	AcceptanceRate   float64   `json:"acceptanceRate" example:"83.3" doc:"Acceptance rate percentage"`
	LastInviteSent   time.Time `json:"lastInviteSent" example:"2023-01-10T12:00:00Z" doc:"Last invitation sent"`
	AvgResponseTime  float64   `json:"avgResponseTime" example:"2.5" doc:"Average response time in days"`
}

// MemberAnniversary represents a member anniversary
type MemberAnniversary struct {
	UserID         xid.ID    `json:"userId" example:"01FZS6TV7KP869DR7RXNEHXQKX" doc:"User ID"`
	Email          string    `json:"email" example:"anniversary@example.com" doc:"User email"`
	FullName       string    `json:"fullName" example:"Bob Wilson" doc:"User full name"`
	JoinedAt       time.Time `json:"joinedAt" example:"2022-01-20T12:00:00Z" doc:"Join date"`
	Anniversary    time.Time `json:"anniversary" example:"2023-01-20T12:00:00Z" doc:"Upcoming anniversary date"`
	YearsOfService int       `json:"yearsOfService" example:"1" doc:"Years of service"`
	RoleName       string    `json:"roleName" example:"developer" doc:"Current role name"`
	DaysUntil      int       `json:"daysUntil" example:"15" doc:"Days until anniversary"`
}

// MembershipChangeLog represents a log of membership changes
type MembershipChangeLog struct {
	ID             xid.ID                 `json:"id" example:"01FZS6TV7KP869DR7RXNEHXQKX" doc:"Change log ID"`
	MembershipID   xid.ID                 `json:"membershipId" example:"01FZS6TV7KP869DR7RXNEHXQKX" doc:"Membership ID"`
	UserID         xid.ID                 `json:"userId" example:"01FZS6TV7KP869DR7RXNEHXQKX" doc:"User ID"`
	OrganizationID xid.ID                 `json:"organizationId" example:"01FZS6TV7KP869DR7RXNEHXQKX" doc:"Organization ID"`
	ChangeType     string                 `json:"changeType" example:"role_change" doc:"Type of change"`
	OldValue       string                 `json:"oldValue,omitempty" example:"member" doc:"Old value"`
	NewValue       string                 `json:"newValue,omitempty" example:"admin" doc:"New value"`
	ChangedBy      xid.ID                 `json:"changedBy" example:"01FZS6TV7KP869DR7RXNEHXQKX" doc:"User who made the change"`
	ChangedAt      time.Time              `json:"changedAt" example:"2023-01-15T12:00:00Z" doc:"When change was made"`
	Reason         string                 `json:"reason,omitempty" example:"Promotion" doc:"Reason for change"`
	Metadata       map[string]interface{} `json:"metadata,omitempty" doc:"Additional change metadata"`
	IPAddress      string                 `json:"ipAddress,omitempty" example:"192.168.1.1" doc:"IP address of change"`
	UserAgent      string                 `json:"userAgent,omitempty" example:"Mozilla/5.0..." doc:"User agent of change"`
}

// MembershipChangeLogResponse represents a list of membership change logs
type MembershipChangeLogResponse = PaginatedOutput[MembershipChangeLog]

// MembershipChangeLogParams represents parameters for querying change logs
type MembershipChangeLogParams struct {
	PaginationParams
	MembershipID   OptionalParam[xid.ID]    `json:"membershipId,omitempty" query:"membershipId"`
	UserID         OptionalParam[xid.ID]    `json:"userId,omitempty" query:"userId"`
	OrganizationID OptionalParam[xid.ID]    `json:"organizationId,omitempty" query:"organizationId"`
	ChangeType     OptionalParam[string]    `json:"changeType,omitempty" query:"changeType"`
	ChangedBy      OptionalParam[xid.ID]    `json:"changedBy,omitempty" query:"changedBy"`
	StartDate      OptionalParam[time.Time] `json:"startDate,omitempty" query:"startDate"`
	EndDate        OptionalParam[time.Time] `json:"endDate,omitempty" query:"endDate"`
}

// MemberRoleMetrics represents metrics for a specific role
type MemberRoleMetrics struct {
	RoleID       xid.ID  `json:"roleId" example:"01FZS6TV7KP869DR7RXNEHXQKX" doc:"Role ID"`
	RoleName     string  `json:"roleName" example:"developer" doc:"Role name"`
	TotalMembers int     `json:"totalMembers" example:"80" doc:"Total members with this role"`
	NewMembers   int     `json:"newMembers" example:"8" doc:"New members with this role in period"`
	LeftMembers  int     `json:"leftMembers" example:"2" doc:"Members who left with this role in period"`
	GrowthRate   float64 `json:"growthRate" example:"7.5" doc:"Growth rate for this role"`
	ChurnRate    float64 `json:"churnRate" example:"2.5" doc:"Churn rate for this role"`
}
