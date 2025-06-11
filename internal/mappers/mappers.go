package mappers

import (
	"time"

	"github.com/juicycleff/frank/ent"
	"github.com/juicycleff/frank/internal/model"
	"github.com/rs/xid"
)

// Base mappers for common fields

// mapBase converts common base fields from ent entity
func mapBase(id xid.ID, createdAt, updatedAt time.Time) model.Base {
	return model.Base{
		ID:        id,
		CreatedAt: createdAt,
		UpdatedAt: updatedAt,
	}
}

// mapAuditBase converts audit fields if they exist
func mapAuditBase(createdBy, updatedBy *xid.ID) model.AuditBase {
	auditBase := model.AuditBase{}
	if createdBy != nil {
		auditBase.CreatedBy = *createdBy
	}
	if updatedBy != nil {
		auditBase.UpdatedBy = *updatedBy
	}
	return auditBase
}

// User mappers

// MapUser converts ent.User to model.User
func MapUser(u *ent.User) model.User {
	if u == nil {
		return model.User{}
	}

	user := model.User{
		Base:                  mapBase(u.ID, u.CreatedAt, u.UpdatedAt),
		Email:                 u.Email,
		PhoneNumber:           ptrToString(u.PhoneNumber),
		FirstName:             ptrToString(u.FirstName),
		LastName:              ptrToString(u.LastName),
		Username:              ptrToString(u.Username),
		EmailVerified:         u.EmailVerified,
		PhoneVerified:         u.PhoneVerified,
		Active:                u.Active,
		Blocked:               u.Blocked,
		LastLogin:             u.LastLogin,
		LastPasswordChange:    u.LastPasswordChange,
		Metadata:              u.Metadata,
		ProfileImageURL:       ptrToString(u.ProfileImageURL),
		Locale:                u.Locale,
		Timezone:              ptrToString(u.Timezone),
		UserType:              string(u.UserType),
		OrganizationID:        u.OrganizationID,
		PrimaryOrganizationID: u.PrimaryOrganizationID,
		IsPlatformAdmin:       u.IsPlatformAdmin,
		AuthProvider:          u.AuthProvider,
		ExternalID:            ptrToString(u.ExternalID),
		CustomerID:            ptrToString(u.CustomerID),
		CustomAttributes:      u.CustomAttributes,
		CreatedBy:             ptrToString(u.CreatedBy),
		LoginCount:            u.LoginCount,
		LastLoginIP:           ptrToString(u.LastLoginIP),
	}

	// Map relationships if loaded
	if u.Edges.Organization != nil {
		orgSummary := MapOrganizationSummary(u.Edges.Organization)
		user.Organizations = []model.OrganizationSummary{orgSummary}
	}

	if len(u.Edges.UserRoles) > 0 {
		user.Roles = make([]model.UserRoleAssignment, len(u.Edges.UserRoles))
		for i, role := range u.Edges.UserRoles {
			user.Roles[i] = MapUserRoleAssignment(role)
		}
	}

	if len(u.Edges.UserPermissions) > 0 {
		user.Permissions = make([]model.UserPermissionAssignment, len(u.Edges.UserPermissions))
		for i, perm := range u.Edges.UserPermissions {
			user.Permissions[i] = MapUserPermissionAssignment(perm)
		}
	}

	if len(u.Edges.MfaMethods) > 0 {
		user.MFAMethods = make([]model.MFAMethod, len(u.Edges.MfaMethods))
		for i, mfa := range u.Edges.MfaMethods {
			user.MFAMethods[i] = MapMFAMethod(mfa)
		}
	}

	if len(u.Edges.Sessions) > 0 {
		user.Sessions = make([]model.SessionInfo, len(u.Edges.Sessions))
		for i, session := range u.Edges.Sessions {
			user.Sessions[i] = MapSessionInfo(session)
		}
	}

	return user
}

// MapUserSummary converts ent.User to model.UserSummary
func MapUserSummary(u *ent.User) model.UserSummary {
	if u == nil {
		return model.UserSummary{}
	}

	return model.UserSummary{
		ID:              u.ID,
		Email:           u.Email,
		FirstName:       ptrToString(u.FirstName),
		LastName:        ptrToString(u.LastName),
		Username:        ptrToString(u.Username),
		ProfileImageURL: ptrToString(u.ProfileImageURL),
		UserType:        string(u.UserType),
		Active:          u.Active,
		LastLogin:       u.LastLogin,
		CreatedAt:       u.CreatedAt,
	}
}

// Session mappers

// MapSession converts ent.Session to model.Session
func MapSession(s *ent.Session) model.Session {
	if s == nil {
		return model.Session{}
	}

	session := model.Session{
		Base:           mapBase(s.ID, s.CreatedAt, s.UpdatedAt),
		UserID:         s.UserID,
		Token:          s.Token,
		IPAddress:      ptrToString(s.IPAddress),
		UserAgent:      ptrToString(s.UserAgent),
		DeviceID:       ptrToString(s.DeviceID),
		Location:       ptrToString(s.Location),
		OrganizationID: s.OrganizationID,
		Active:         s.Active,
		ExpiresAt:      s.ExpiresAt,
		LastActiveAt:   s.LastActiveAt,
		Metadata:       s.Metadata,
	}

	return session
}

// MapSessionInfo converts ent.Session to model.SessionInfo
func MapSessionInfo(s *ent.Session) model.SessionInfo {
	if s == nil {
		return model.SessionInfo{}
	}

	return model.SessionInfo{
		ID:           s.ID,
		UserID:       s.UserID,
		IPAddress:    ptrToString(s.IPAddress),
		UserAgent:    ptrToString(s.UserAgent),
		DeviceID:     ptrToString(s.DeviceID),
		Location:     ptrToString(s.Location),
		Active:       s.Active,
		ExpiresAt:    s.ExpiresAt,
		LastActiveAt: s.LastActiveAt,
		CreatedAt:    s.CreatedAt,
	}
}

// Organization mappers

// MapOrganization converts ent.Organization to model.Organization
func MapOrganization(o *ent.Organization) model.Organization {
	if o == nil {
		return model.Organization{}
	}

	org := model.Organization{
		Base:                   mapBase(o.ID, o.CreatedAt, o.UpdatedAt),
		Name:                   o.Name,
		Slug:                   o.Slug,
		Domains:                o.Domains,
		VerifiedDomains:        o.VerifiedDomains,
		Domain:                 ptrToString(o.Domain),
		LogoURL:                ptrToString(o.LogoURL),
		Plan:                   o.Plan,
		Active:                 o.Active,
		Metadata:               o.Metadata,
		TrialEndsAt:            o.TrialEndsAt,
		TrialUsed:              o.TrialUsed,
		OwnerID:                o.OwnerID,
		OrgType:                string(o.OrgType),
		IsPlatformOrganization: o.IsPlatformOrganization,
		ExternalUserLimit:      o.ExternalUserLimit,
		EndUserLimit:           o.EndUserLimit,
		SSOEnabled:             o.SSOEnabled,
		SSODomain:              ptrToString(o.SSODomain),
		SubscriptionID:         ptrToString(o.SubscriptionID),
		CustomerID:             ptrToString(o.CustomerID),
		SubscriptionStatus:     string(o.SubscriptionStatus),
		AuthServiceEnabled:     o.AuthServiceEnabled,
		AuthConfig:             o.AuthConfig,
		AuthDomain:             ptrToString(o.AuthDomain),
		APIRequestLimit:        o.APIRequestLimit,
		APIRequestsUsed:        o.APIRequestsUsed,
		CurrentExternalUsers:   o.CurrentExternalUsers,
		CurrentEndUsers:        o.CurrentEndUsers,
	}

	// Map relationships if loaded
	if len(o.Edges.Memberships) > 0 {
		org.Members = make([]model.MemberSummary, len(o.Edges.Memberships))
		for i, membership := range o.Edges.Memberships {
			org.Members[i] = MapMemberSummary(membership)
		}
	}

	if len(o.Edges.FeatureFlags) > 0 {
		org.Features = make([]model.FeatureSummary, len(o.Edges.FeatureFlags))
		for i, feature := range o.Edges.FeatureFlags {
			org.Features[i] = MapFeatureSummary(feature)
		}
	}

	return org
}

// MapOrganizationSummary converts ent.Organization to model.OrganizationSummary
func MapOrganizationSummary(o *ent.Organization) model.OrganizationSummary {
	if o == nil {
		return model.OrganizationSummary{}
	}

	memberCount := 0
	if len(o.Edges.Memberships) > 0 {
		memberCount = len(o.Edges.Memberships)
	}

	return model.OrganizationSummary{
		ID:          o.ID,
		Name:        o.Name,
		Slug:        o.Slug,
		LogoURL:     ptrToString(o.LogoURL),
		Plan:        o.Plan,
		Active:      o.Active,
		OrgType:     string(o.OrgType),
		MemberCount: memberCount,
	}
}

// Membership mappers

// MapMembership converts ent.Membership to model.Membership
func MapMembership(m *ent.Membership) model.Membership {
	if m == nil {
		return model.Membership{}
	}

	membership := model.Membership{
		Base:             mapBase(m.ID, m.CreatedAt, m.UpdatedAt),
		AuditBase:        model.AuditBase{}, // Map if audit fields exist
		UserID:           m.UserID,
		OrganizationID:   m.OrganizationID,
		RoleID:           m.RoleID,
		Status:           string(m.Status),
		InvitedBy:        m.InvitedBy,
		InvitedAt:        m.InvitedAt,
		JoinedAt:         m.JoinedAt,
		ExpiresAt:        m.ExpiresAt,
		InvitationToken:  ptrToString(m.InvitationToken),
		IsBillingContact: m.IsBillingContact,
		IsPrimaryContact: m.IsPrimaryContact,
		Metadata:         m.Metadata,
	}

	// Map relationships if loaded
	if m.Edges.User != nil {
		userSummary := MapUserSummary(m.Edges.User)
		membership.User = &userSummary
	}

	if m.Edges.Organization != nil {
		orgSummary := MapOrganizationSummary(m.Edges.Organization)
		membership.Organization = &orgSummary
	}

	if m.Edges.Role != nil {
		roleSummary := MapRoleSummary(m.Edges.Role)
		membership.Role = &roleSummary
	}

	if m.Edges.Inviter != nil {
		inviterSummary := MapUserSummary(m.Edges.Inviter)
		membership.Inviter = &inviterSummary
	}

	return membership
}

// MapMemberSummary converts ent.Membership to model.MemberSummary
func MapMemberSummary(m *ent.Membership) model.MemberSummary {
	if m == nil {
		return model.MemberSummary{}
	}

	summary := model.MemberSummary{
		UserID:   m.UserID,
		Status:   string(m.Status),
		JoinedAt: m.JoinedAt,
		// IsBillingContact: m.IsBillingContact,
		// IsPrimaryContact: m.IsPrimaryContact,
		// CreatedAt:        m.CreatedAt,
	}

	// Get user info if loaded
	if m.Edges.User != nil {
		summary.Email = m.Edges.User.Email
		summary.FirstName = ptrToString(m.Edges.User.FirstName)
		summary.LastName = ptrToString(m.Edges.User.LastName)
		summary.LastActive = m.Edges.User.LastLogin
	}

	// Get role info if loaded
	if m.Edges.Role != nil {
		summary.RoleName = m.Edges.Role.Name
	}

	return summary
}

// Role and Permission mappers

// MapRole converts ent.Role to model.Role
func MapRole(r *ent.Role) model.Role {
	if r == nil {
		return model.Role{}
	}

	role := model.Role{
		Base:                mapBase(r.ID, r.CreatedAt, r.UpdatedAt),
		AuditBase:           mapAuditBase(r.CreatedBy, r.UpdatedBy),
		Name:                r.Name,
		DisplayName:         ptrToString(r.DisplayName),
		Description:         ptrToString(r.Description),
		RoleType:            string(r.RoleType),
		OrganizationID:      r.OrganizationID,
		ApplicationID:       r.ApplicationID,
		System:              r.System,
		IsDefault:           r.IsDefault,
		Priority:            r.Priority,
		Color:               ptrToString(r.Color),
		ApplicableUserTypes: r.ApplicableUserTypes,
		Active:              r.Active,
		ParentID:            r.ParentID,
	}

	// Map relationships if loaded
	if len(r.Edges.Permissions) > 0 {
		role.Permissions = make([]model.Permission, len(r.Edges.Permissions))
		for i, perm := range r.Edges.Permissions {
			role.Permissions[i] = MapPermission(perm)
		}
	}

	if len(r.Edges.Children) > 0 {
		role.Children = make([]model.RoleSummary, len(r.Edges.Children))
		for i, child := range r.Edges.Children {
			role.Children[i] = MapRoleSummary(child)
		}
	}

	if r.Edges.Parent != nil {
		parentSummary := MapRoleSummary(r.Edges.Parent)
		role.Parent = &parentSummary
	}

	if r.Edges.Organization != nil {
		orgSummary := MapOrganizationSummary(r.Edges.Organization)
		role.Organization = &orgSummary
	}

	return role
}

// MapRoleSummary converts ent.Role to model.RoleSummary
func MapRoleSummary(r *ent.Role) model.RoleSummary {
	if r == nil {
		return model.RoleSummary{}
	}

	return model.RoleSummary{
		ID:          r.ID,
		Name:        r.Name,
		DisplayName: ptrToString(r.DisplayName),
		Description: ptrToString(r.Description),
		Priority:    r.Priority,
	}
}

// MapPermission converts ent.Permission to model.Permission
func MapPermission(p *ent.Permission) model.Permission {
	if p == nil {
		return model.Permission{}
	}

	permission := model.Permission{
		Base:                mapBase(p.ID, p.CreatedAt, p.UpdatedAt),
		AuditBase:           mapAuditBase(p.CreatedBy, p.UpdatedBy),
		Name:                p.Name,
		DisplayName:         ptrToString(p.DisplayName),
		Description:         p.Description,
		Resource:            p.Resource,
		Action:              p.Action,
		Category:            string(p.Category),
		ApplicableUserTypes: p.ApplicableUserTypes,
		ApplicableContexts:  p.ApplicableContexts,
		Conditions:          ptrToString(p.Conditions),
		System:              p.System,
		Dangerous:           p.Dangerous,
		RiskLevel:           p.RiskLevel,
		Active:              p.Active,
		PermissionGroup:     ptrToString(p.PermissionGroup),
	}

	// Map roles relationship if loaded
	if len(p.Edges.Roles) > 0 {
		permission.Roles = make([]model.RoleSummary, len(p.Edges.Roles))
		for i, role := range p.Edges.Roles {
			permission.Roles[i] = MapRoleSummary(role)
		}
	}

	return permission
}

// MapUserRoleAssignment converts ent.UserRole to model.UserRoleAssignment
func MapUserRoleAssignment(ur *ent.UserRole) model.UserRoleAssignment {
	if ur == nil {
		return model.UserRoleAssignment{}
	}

	assignment := model.UserRoleAssignment{
		ID:          ur.ID,
		RoleID:      ur.RoleID,
		ContextType: string(ur.ContextType),
		ContextID:   ur.ContextID,
		AssignedBy:  ur.AssignedBy,
		AssignedAt:  ur.AssignedAt,
		ExpiresAt:   ur.ExpiresAt,
		Active:      ur.Active,
	}

	// Map role info if loaded
	if ur.Edges.Role != nil {
		assignment.RoleName = ur.Edges.Role.Name
		assignment.DisplayName = ptrToString(ur.Edges.Role.DisplayName)
	}

	return assignment
}

// MapUserPermissionAssignment converts ent.UserPermission to model.UserPermissionAssignment
func MapUserPermissionAssignment(up *ent.UserPermission) model.UserPermissionAssignment {
	if up == nil {
		return model.UserPermissionAssignment{}
	}

	assignment := model.UserPermissionAssignment{
		ID:             up.ID,
		PermissionID:   up.PermissionID,
		ContextType:    string(up.ContextType),
		ContextID:      up.ContextID,
		ResourceType:   ptrToString(up.ResourceType),
		ResourceID:     up.ResourceID,
		PermissionType: string(up.PermissionType),
		AssignedBy:     up.AssignedBy,
		AssignedAt:     up.AssignedAt,
		ExpiresAt:      up.ExpiresAt,
		Active:         up.Active,
		Conditions:     up.Conditions,
		Reason:         ptrToString(up.Reason),
	}

	// Map permission info if loaded
	if up.Edges.Permission != nil {
		assignment.PermissionName = up.Edges.Permission.Name
		assignment.DisplayName = ptrToString(up.Edges.Permission.DisplayName)
	}

	return assignment
}

// OAuth mappers

// MapOAuthClient converts ent.OAuthClient to model.OAuthClient
func MapOAuthClient(c *ent.OAuthClient) model.OAuthClient {
	if c == nil {
		return model.OAuthClient{}
	}

	client := model.OAuthClient{
		Base:                      mapBase(c.ID, c.CreatedAt, c.UpdatedAt),
		AuditBase:                 mapAuditBase(c.CreatedBy, c.UpdatedBy),
		ClientID:                  c.ClientID,
		ClientName:                c.ClientName,
		ClientDescription:         ptrToString(c.ClientDescription),
		ClientURI:                 ptrToString(c.ClientURI),
		LogoURI:                   ptrToString(c.LogoURI),
		RedirectURIs:              c.RedirectUris,
		PostLogoutRedirectURIs:    c.PostLogoutRedirectUris,
		OrganizationID:            c.OrganizationID,
		Public:                    c.Public,
		Active:                    c.Active,
		AllowedCORSOrigins:        c.AllowedCorsOrigins,
		AllowedGrantTypes:         c.AllowedGrantTypes,
		TokenExpirySeconds:        c.TokenExpirySeconds,
		RefreshTokenExpirySeconds: c.RefreshTokenExpirySeconds,
		AuthCodeExpirySeconds:     c.AuthCodeExpirySeconds,
		RequiresPKCE:              c.RequiresPkce,
		RequiresConsent:           c.RequiresConsent,
	}

	// Map relationships if loaded
	if c.Edges.Organization != nil {
		orgSummary := MapOrganizationSummary(c.Edges.Organization)
		client.Organization = &orgSummary
	}

	if len(c.Edges.Scopes) > 0 {
		client.Scopes = make([]model.OAuthScope, len(c.Edges.Scopes))
		for i, scope := range c.Edges.Scopes {
			client.Scopes[i] = MapOAuthScope(scope)
		}
	}

	return client
}

// MapOAuthScope converts ent.OAuthScope to model.OAuthScope
func MapOAuthScope(s *ent.OAuthScope) model.OAuthScope {
	if s == nil {
		return model.OAuthScope{}
	}

	return model.OAuthScope{
		Base:         mapBase(s.ID, s.CreatedAt, s.UpdatedAt),
		Name:         s.Name,
		Description:  s.Description,
		DefaultScope: s.DefaultScope,
		Public:       s.Public,
	}
}

// MapOAuthToken converts ent.OAuthToken to model.OAuthToken
func MapOAuthToken(t *ent.OAuthToken) model.OAuthToken {
	if t == nil {
		return model.OAuthToken{}
	}

	token := model.OAuthToken{
		Base:                  mapBase(t.ID, t.CreatedAt, t.UpdatedAt),
		TokenType:             t.TokenType,
		ClientID:              t.ClientID,
		UserID:                t.UserID,
		OrganizationID:        t.OrganizationID,
		ScopeNames:            t.ScopeNames,
		ExpiresIn:             t.ExpiresIn,
		ExpiresAt:             t.ExpiresAt,
		RefreshTokenExpiresAt: t.RefreshTokenExpiresAt,
		Revoked:               t.Revoked,
		RevokedAt:             t.RevokedAt,
		IPAddress:             ptrToString(t.IPAddress),
		UserAgent:             ptrToString(t.UserAgent),
	}

	// Map relationships if loaded
	if t.Edges.Client != nil {
		client := MapOAuthClientSummary(t.Edges.Client)
		token.Client = &client
	}

	if t.Edges.User != nil {
		user := MapUserSummary(t.Edges.User)
		token.User = &user
	}

	if t.Edges.Organization != nil {
		org := MapOrganizationSummary(t.Edges.Organization)
		token.Organization = &org
	}

	if len(t.Edges.Scopes) > 0 {
		token.Scopes = make([]model.OAuthScope, len(t.Edges.Scopes))
		for i, scope := range t.Edges.Scopes {
			token.Scopes[i] = MapOAuthScope(scope)
		}
	}

	return token
}

// MapOAuthClientSummary converts ent.OAuthClient to model.OAuthClientSummary
func MapOAuthClientSummary(c *ent.OAuthClient) model.OAuthClientSummary {
	if c == nil {
		return model.OAuthClientSummary{}
	}

	tokenCount := 0
	var lastUsed *time.Time
	if len(c.Edges.Tokens) > 0 {
		tokenCount = len(c.Edges.Tokens)
		// Find most recent token usage
		for _, token := range c.Edges.Tokens {
			if lastUsed == nil || (token.CreatedAt.After(*lastUsed)) {
				lastUsed = &token.CreatedAt
			}
		}
	}

	return model.OAuthClientSummary{
		ID:         c.ID,
		ClientID:   c.ClientID,
		ClientName: c.ClientName,
		LogoURI:    ptrToString(c.LogoURI),
		Public:     c.Public,
		Active:     c.Active,
		TokenCount: tokenCount,
		LastUsed:   lastUsed,
		CreatedAt:  c.CreatedAt,
	}
}

// MFA mappers

// MapMFAMethod converts ent.MFA to model.MFAMethod
func MapMFAMethod(m *ent.MFA) model.MFAMethod {
	if m == nil {
		return model.MFAMethod{}
	}

	method := model.MFAMethod{
		Base:        mapBase(m.ID, m.CreatedAt, m.UpdatedAt),
		UserID:      m.UserID,
		Method:      m.Method,
		Verified:    m.Verified,
		Active:      m.Active,
		BackupCodes: m.BackupCodes,
		PhoneNumber: ptrToString(m.PhoneNumber),
		Email:       ptrToString(m.Email),
		LastUsed:    m.LastUsed,
		Metadata:    m.Metadata,
	}

	// Map user relationship if loaded
	if m.Edges.User != nil {
		user := MapUserSummary(m.Edges.User)
		method.User = &user
	}

	return method
}

// Passkey mappers

// MapPasskey converts ent.Passkey to model.Passkey
func MapPasskey(p *ent.Passkey) model.Passkey {
	if p == nil {
		return model.Passkey{}
	}

	passkey := model.Passkey{
		Base:         mapBase(p.ID, p.CreatedAt, p.UpdatedAt),
		UserID:       p.UserID,
		Name:         p.Name,
		CredentialID: p.CredentialID,
		PublicKey:    p.PublicKey,
		SignCount:    p.SignCount,
		Active:       p.Active,
		DeviceType:   ptrToString(p.DeviceType),
		AAGUID:       ptrToString(p.Aaguid),
		LastUsed:     p.LastUsed,
		Transports:   p.Transports,
		Attestation:  p.Attestation,
	}

	// Map user relationship if loaded
	if p.Edges.User != nil {
		user := MapUserSummary(p.Edges.User)
		passkey.User = &user
	}

	return passkey
}

// API Key mappers

// MapAPIKey converts ent.ApiKey to model.APIKey
func MapAPIKey(k *ent.ApiKey) model.APIKey {
	if k == nil {
		return model.APIKey{}
	}

	apiKey := model.APIKey{
		Base:           mapBase(k.ID, k.CreatedAt, k.UpdatedAt),
		Name:           k.Name,
		HashedKey:      k.HashedKey,
		UserID:         k.UserID,
		OrganizationID: k.OrganizationID,
		Type:           k.Type,
		Active:         k.Active,
		Permissions:    k.Permissions,
		Scopes:         k.Scopes,
		Metadata:       k.Metadata,
		LastUsed:       k.LastUsed,
		ExpiresAt:      k.ExpiresAt,
	}

	// Map relationships if loaded
	if k.Edges.User != nil {
		user := MapUserSummary(k.Edges.User)
		apiKey.User = &user
	}

	if k.Edges.Organization != nil {
		org := MapOrganizationSummary(k.Edges.Organization)
		apiKey.Organization = &org
	}

	return apiKey
}

// Audit mappers

// MapAuditLog converts ent.Audit to model.AuditLog
func MapAuditLog(a *ent.Audit) model.AuditLog {
	if a == nil {
		return model.AuditLog{}
	}

	audit := model.AuditLog{
		Base:           mapBase(a.ID, a.CreatedAt, a.UpdatedAt),
		OrganizationID: a.OrganizationID,
		UserID:         a.UserID,
		SessionID:      a.SessionID,
		Action:         a.Action,
		Resource:       a.ResourceType,
		ResourceID:     a.ResourceID,
		Status:         a.Status,
		IPAddress:      ptrToString(a.IPAddress),
		UserAgent:      ptrToString(a.UserAgent),
		Location:       ptrToString(a.Location),
		Details:        a.Metadata,
		Changes:        combineOldNewValues(a.OldValues, a.NewValues),
		Error:          ptrToString(a.ErrorMessage),
		Timestamp:      a.Timestamp,
	}

	// Map relationships if loaded
	if a.Edges.User != nil {
		user := MapUserSummary(a.Edges.User)
		audit.User = &user
	}

	if a.Edges.Organization != nil {
		org := MapOrganizationSummary(a.Edges.Organization)
		audit.Organization = &org
	}

	return audit
}

// EmailTemplate mappers

// MapEmailTemplate converts ent.EmailTemplate to model.EmailTemplate
func MapEmailTemplate(t *ent.EmailTemplate) model.EmailTemplate {
	if t == nil {
		return model.EmailTemplate{}
	}

	template := model.EmailTemplate{
		Base:           mapBase(t.ID, t.CreatedAt, t.UpdatedAt),
		AuditBase:      model.AuditBase{}, // Map if audit fields exist
		Name:           t.Name,
		Subject:        t.Subject,
		Type:           t.Type,
		HTMLContent:    t.HtmlContent,
		TextContent:    ptrToString(t.TextContent),
		OrganizationID: t.OrganizationID,
		Active:         t.Active,
		System:         t.System,
		Locale:         t.Locale,
		Metadata:       t.Metadata,
	}

	return template
}

// Webhook mappers

// MapWebhook converts ent.Webhook to model.Webhook
func MapWebhook(w *ent.Webhook) model.Webhook {
	if w == nil {
		return model.Webhook{}
	}

	webhook := model.Webhook{
		Base:           mapBase(w.ID, w.CreatedAt, w.UpdatedAt),
		AuditBase:      mapAuditBase(w.CreatedBy, w.UpdatedBy),
		Name:           w.Name,
		URL:            w.URL,
		OrganizationID: w.OrganizationID,
		Active:         w.Active,
		EventTypes:     w.EventTypes,
		Version:        w.Version,
		RetryCount:     w.RetryCount,
		TimeoutMs:      w.TimeoutMS,
		Format:         string(w.Format),
		Metadata:       w.Metadata,
	}

	// Map relationships if loaded
	if w.Edges.Organization != nil {
		org := MapOrganizationSummary(w.Edges.Organization)
		webhook.Organization = &org
	}

	if len(w.Edges.Events) > 0 {
		webhook.Events = make([]model.WebhookEvent, len(w.Edges.Events))
		for i, event := range w.Edges.Events {
			webhook.Events[i] = MapWebhookEvent(event)
		}
	}

	return webhook
}

// MapWebhookEvent converts ent.WebhookEvent to model.WebhookEvent
func MapWebhookEvent(e *ent.WebhookEvent) model.WebhookEvent {
	if e == nil {
		return model.WebhookEvent{}
	}

	event := model.WebhookEvent{
		Base:         mapBase(e.ID, e.CreatedAt, e.UpdatedAt),
		WebhookID:    e.WebhookID,
		EventType:    e.EventType,
		Headers:      e.Headers,
		Payload:      e.Payload,
		Delivered:    e.Delivered,
		DeliveredAt:  e.DeliveredAt,
		Attempts:     e.Attempts,
		NextRetry:    e.NextRetry,
		StatusCode:   e.StatusCode,
		ResponseBody: ptrToString(e.ResponseBody),
		Error:        ptrToString(e.Error),
	}

	return event
}

// SSO mappers

// MapIdentityProvider converts ent.IdentityProvider to model.IdentityProvider
func MapIdentityProvider(p *ent.IdentityProvider) model.IdentityProvider {
	if p == nil {
		return model.IdentityProvider{}
	}

	provider := model.IdentityProvider{
		Base:             mapBase(p.ID, p.CreatedAt, p.UpdatedAt),
		AuditBase:        mapAuditBase(p.CreatedBy, p.UpdatedBy),
		Name:             p.Name,
		Type:             p.ProviderType,
		Protocol:         determineProtocol(p.ProviderType),
		OrganizationID:   p.OrganizationID,
		Domain:           getFirstDomain(p.Domains),
		Enabled:          p.Active,
		AttributeMapping: p.AttributesMapping,
		Config:           buildProviderConfig(p),
	}

	// Map organization relationship if loaded
	if p.Edges.Organization != nil {
		org := MapOrganizationSummary(p.Edges.Organization)
		provider.Organization = &org
	}

	return provider
}

// Verification mappers

// MapVerification converts ent.Verification to model verification structures
func MapVerification(v *ent.Verification) interface{} {
	if v == nil {
		return nil
	}

	// Return appropriate verification response based on type
	switch v.Type {
	case "email":
		return model.VerificationResponse{
			Success:  !v.Used,
			Message:  "Email verification processed",
			Verified: v.Used,
		}
	case "phone":
		return model.VerificationResponse{
			Success:  !v.Used,
			Message:  "Phone verification processed",
			Verified: v.Used,
		}
	default:
		return model.VerificationResponse{
			Success:  !v.Used,
			Message:  "Verification processed",
			Verified: v.Used,
		}
	}
}

// Feature Flag mappers

// MapFeatureSummary converts ent.OrganizationFeature to model.FeatureSummary
func MapFeatureSummary(f *ent.OrganizationFeature) model.FeatureSummary {
	if f == nil {
		return model.FeatureSummary{}
	}

	summary := model.FeatureSummary{
		Enabled:   f.Enabled,
		Config:    f.Settings,
		UpdatedAt: f.UpdatedAt,
	}

	// Get feature details if loaded
	if f.Edges.Feature != nil {
		summary.Name = f.Edges.Feature.Key
		summary.DisplayName = f.Edges.Feature.Name
	}

	return summary
}

// Utility functions

// ptrToString converts *string to string, returning empty string if nil
func ptrToString(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

// combineOldNewValues combines old and new values for audit changes
func combineOldNewValues(oldValues, newValues map[string]interface{}) map[string]interface{} {
	if oldValues == nil && newValues == nil {
		return nil
	}

	changes := make(map[string]interface{})

	if oldValues != nil {
		changes["before"] = oldValues
	}

	if newValues != nil {
		changes["after"] = newValues
	}

	return changes
}

// determineProtocol determines the protocol based on provider type
func determineProtocol(providerType string) string {
	switch providerType {
	case "oidc":
		return "openid_connect"
	case "oauth2":
		return "oauth2"
	case "saml":
		return "saml2"
	default:
		return providerType
	}
}

// getFirstDomain gets the first domain from domains slice
func getFirstDomain(domains []string) string {
	if len(domains) > 0 {
		return domains[0]
	}
	return ""
}

// buildProviderConfig builds provider config from ent.IdentityProvider
func buildProviderConfig(p *ent.IdentityProvider) map[string]interface{} {
	config := make(map[string]interface{})

	if p.ClientID != nil {
		config["clientId"] = *p.ClientID
	}
	if p.Issuer != nil {
		config["issuer"] = *p.Issuer
	}
	if p.AuthorizationEndpoint != nil {
		config["authUrl"] = *p.AuthorizationEndpoint
	}
	if p.TokenEndpoint != nil {
		config["tokenUrl"] = *p.TokenEndpoint
	}
	if p.UserinfoEndpoint != nil {
		config["userInfoUrl"] = *p.UserinfoEndpoint
	}
	if p.JwksURI != nil {
		config["jwksUrl"] = *p.JwksURI
	}
	if p.MetadataURL != nil {
		config["metadataUrl"] = *p.MetadataURL
	}

	return config
}
