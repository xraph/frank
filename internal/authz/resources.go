package authz

import (
	"context"
	"fmt"
	"reflect"

	"github.com/juicycleff/frank/ent"
	"github.com/juicycleff/frank/pkg/data"
	"github.com/rs/xid"
)

// ResourceType represents the type of resource that permissions apply to
type ResourceType string

// Define all resource types based on your ent schemas
const (
	// Core organizational resources
	ResourceOrganization ResourceType = "organization"
	ResourceUser         ResourceType = "user"
	ResourceRole         ResourceType = "role"
	ResourcePermission   ResourceType = "permission"

	// Authentication and security resources
	ResourceSession      ResourceType = "session"
	ResourceMFA          ResourceType = "mfa"
	ResourceAPIKey       ResourceType = "api_key"
	ResourceVerification ResourceType = "verification"

	// Communication resources
	ResourceWebhook       ResourceType = "webhook"
	ResourceWebhookEvent  ResourceType = "webhook_event"
	ResourceEmailTemplate ResourceType = "email_template"

	// System resources
	ResourceGlobal ResourceType = "global"
	ResourceSystem ResourceType = "system"
)

// Resource represents a specific resource instance
type Resource struct {
	Type ResourceType
	ID   string
}

// NewResource creates a new resource instance
func NewResource(resourceType ResourceType, id string) Resource {
	return Resource{
		Type: resourceType,
		ID:   id,
	}
}

// String returns a string representation of the resource
func (r Resource) String() string {
	return string(r.Type) + ":" + r.ID
}

// ResourceOwnershipChecker defines the interface for checking resource ownership
type ResourceOwnershipChecker interface {
	// IsResourceOwner checks if the user is the owner of the resource
	IsResourceOwner(ctx context.Context, userID xid.ID, resourceType ResourceType, resourceID xid.ID) (bool, error)

	// IsResourceCreator checks if the user is the creator of the resource
	IsResourceCreator(ctx context.Context, userID xid.ID, resourceType ResourceType, resourceID xid.ID) (bool, error)

	// GetResourceOrganization gets the organization ID associated with a resource
	GetResourceOrganization(ctx context.Context, resourceType ResourceType, resourceID xid.ID) (xid.ID, error)
}

// DefaultResourceOwnershipChecker Default implementation of ResourceOwnershipChecker
type DefaultResourceOwnershipChecker struct {
	client *data.Clients
}

// NewResourceOwnershipChecker creates a new resource ownership checker
func NewResourceOwnershipChecker(client *data.Clients) *DefaultResourceOwnershipChecker {
	return &DefaultResourceOwnershipChecker{
		client: client,
	}
}

// IsResourceOwner checks if the user is the owner of the resource
func (c *DefaultResourceOwnershipChecker) IsResourceOwner(ctx context.Context, userID xid.ID, resourceType ResourceType, resourceID xid.ID) (bool, error) {
	switch resourceType {
	case ResourceOrganization:
		// For organizations, check ownership from relationship or if owner field exists
		_, err := c.client.DB.Organization.Get(ctx, resourceID)
		if err != nil {
			if ent.IsNotFound(err) {
				return false, nil
			}
			return false, err
		}
		// If you have an owner field, use it. Otherwise, might need to check membership with owner role
		// This depends on your exact schema - assuming there's an ownership relationship
		return true, nil // You'll need to implement based on your org ownership logic

	case ResourceUser:
		// Users own themselves
		return resourceID == userID, nil

	case ResourceAPIKey:
		apiKey, err := c.client.DB.ApiKey.Get(ctx, resourceID)
		if err != nil {
			if ent.IsNotFound(err) {
				return false, nil
			}
			return false, err
		}
		// Check if user owns the API key directly or through organization
		if !apiKey.UserID.IsNil() && apiKey.UserID == userID {
			return true, nil
		}
		if !apiKey.OrganizationID.IsNil() {
			return c.IsResourceOwner(ctx, userID, ResourceOrganization, apiKey.OrganizationID)
		}
		return false, nil

	case ResourceSession:
		session, err := c.client.DB.Session.Get(ctx, resourceID)
		if err != nil {
			if ent.IsNotFound(err) {
				return false, nil
			}
			return false, err
		}
		return session.UserID == userID, nil

	case ResourceMFA:
		mfa, err := c.client.DB.MFA.Get(ctx, resourceID)
		if err != nil {
			if ent.IsNotFound(err) {
				return false, nil
			}
			return false, err
		}
		return mfa.UserID == userID, nil

	case ResourceVerification:
		verification, err := c.client.DB.Verification.Get(ctx, resourceID)
		if err != nil {
			if ent.IsNotFound(err) {
				return false, nil
			}
			return false, err
		}
		return verification.UserID == userID, nil

	case ResourceWebhook:
		webhook, err := c.client.DB.Webhook.Get(ctx, resourceID)
		if err != nil {
			if ent.IsNotFound(err) {
				return false, nil
			}
			return false, err
		}
		return c.IsResourceOwner(ctx, userID, ResourceOrganization, webhook.OrganizationID)

	case ResourceWebhookEvent:
		// Webhook events belong to webhooks, which belong to organizations
		orgID, err := c.GetResourceOrganization(ctx, resourceType, resourceID)
		if err != nil {
			return false, err
		}
		return c.IsResourceOwner(ctx, userID, ResourceOrganization, orgID)

	case ResourceEmailTemplate:
		template, err := c.client.DB.EmailTemplate.Get(ctx, resourceID)
		if err != nil {
			if ent.IsNotFound(err) {
				return false, nil
			}
			return false, err
		}
		if !template.OrganizationID.IsNil() {
			return c.IsResourceOwner(ctx, userID, ResourceOrganization, template.OrganizationID)
		}
		// Global templates - check if system admin or creator
		return c.IsResourceCreator(ctx, userID, resourceType, resourceID)

	case ResourceRole:
		role, err := c.client.DB.Role.Get(ctx, resourceID)
		if err != nil {
			if ent.IsNotFound(err) {
				return false, nil
			}
			return false, err
		}
		if !role.OrganizationID.IsNil() {
			return c.IsResourceOwner(ctx, userID, ResourceOrganization, role.OrganizationID)
		}
		// System roles - only system admins
		return false, nil

	case ResourcePermission:
		// Permissions are typically system-level, only admins can manage
		return false, nil

	default:
		// For unknown resource types, default to not an owner
		return false, nil
	}
}

// IsResourceCreator checks if the user is the creator of the resource
func (c *DefaultResourceOwnershipChecker) IsResourceCreator(ctx context.Context, userID xid.ID, resourceType ResourceType, resourceID xid.ID) (bool, error) {
	// Helper function to check created_by field using reflection
	checkCreator := func(entity interface{}) (bool, error) {
		val := reflect.ValueOf(entity)
		if val.Kind() == reflect.Ptr {
			val = val.Elem()
		}

		createdByField := val.FieldByName("CreatedBy")
		if !createdByField.IsValid() {
			return false, fmt.Errorf("entity does not have CreatedBy field")
		}

		return createdByField.String() == userID.String(), nil
	}

	switch resourceType {
	case ResourceOrganization:
		// Organizations might not have CreatedBy, use ownership instead
		return c.IsResourceOwner(ctx, userID, resourceType, resourceID)

	case ResourceUser:
		// Users create themselves
		return resourceID == userID, nil

	case ResourceAPIKey:
		apiKey, err := c.client.DB.ApiKey.Get(ctx, resourceID)
		if err != nil {
			if ent.IsNotFound(err) {
				return false, nil
			}
			return false, err
		}
		return checkCreator(apiKey)

	case ResourceWebhook:
		webhook, err := c.client.DB.Webhook.Get(ctx, resourceID)
		if err != nil {
			if ent.IsNotFound(err) {
				return false, nil
			}
			return false, err
		}
		return checkCreator(webhook)

	case ResourceEmailTemplate:
		template, err := c.client.DB.EmailTemplate.Get(ctx, resourceID)
		if err != nil {
			if ent.IsNotFound(err) {
				return false, nil
			}
			return false, err
		}
		return checkCreator(template)

	case ResourceRole:
		role, err := c.client.DB.Role.Get(ctx, resourceID)
		if err != nil {
			if ent.IsNotFound(err) {
				return false, nil
			}
			return false, err
		}
		return checkCreator(role)

	case ResourceSession, ResourceMFA, ResourceVerification:
		// These are typically created by the system, not users
		return false, nil

	default:
		// For unknown resource types, default to not a creator
		return false, nil
	}
}

// GetResourceOrganization gets the organization ID associated with a resource
func (c *DefaultResourceOwnershipChecker) GetResourceOrganization(ctx context.Context, resourceType ResourceType, resourceID xid.ID) (xid.ID, error) {
	switch resourceType {
	case ResourceOrganization:
		// The resource is an organization itself
		return resourceID, nil

	case ResourceAPIKey:
		apiKey, err := c.client.DB.ApiKey.Get(ctx, resourceID)
		if err != nil {
			return xid.NilID(), err
		}
		if !apiKey.OrganizationID.IsNil() {
			return apiKey.OrganizationID, nil
		}
		// If it's a user API key, get user's primary organization
		if !apiKey.UserID.IsNil() {
			user, err := c.client.DB.User.Get(ctx, apiKey.UserID)
			if err != nil {
				return xid.NilID(), err
			}
			if !user.PrimaryOrganizationID.IsNil() {
				return user.PrimaryOrganizationID, nil
			}
		}
		return xid.NilID(), fmt.Errorf("API key not associated with an organization")

	case ResourceWebhook:
		webhook, err := c.client.DB.Webhook.Get(ctx, resourceID)
		if err != nil {
			return xid.NilID(), err
		}
		return webhook.OrganizationID, nil

	case ResourceWebhookEvent:
		// Get webhook first, then organization
		webhookEvent, err := c.client.DB.WebhookEvent.Get(ctx, resourceID)
		if err != nil {
			return xid.NilID(), err
		}
		return c.GetResourceOrganization(ctx, ResourceWebhook, webhookEvent.WebhookID)

	case ResourceEmailTemplate:
		template, err := c.client.DB.EmailTemplate.Get(ctx, resourceID)
		if err != nil {
			return xid.NilID(), err
		}
		if !template.OrganizationID.IsNil() {
			return template.OrganizationID, nil
		}
		return xid.NilID(), fmt.Errorf("email template is global and not associated with an organization")

	case ResourceRole:
		role, err := c.client.DB.Role.Get(ctx, resourceID)
		if err != nil {
			return xid.NilID(), err
		}
		if !role.OrganizationID.IsNil() {
			return role.OrganizationID, nil
		}
		return xid.NilID(), fmt.Errorf("role is system-level and not associated with an organization")

	case ResourceUser:
		user, err := c.client.DB.User.Get(ctx, resourceID)
		if err != nil {
			return xid.NilID(), err
		}
		if !user.PrimaryOrganizationID.IsNil() {
			return user.PrimaryOrganizationID, nil
		}
		return xid.NilID(), fmt.Errorf("user not associated with an organization")

	case ResourceSession:
		session, err := c.client.DB.Session.Get(ctx, resourceID)
		if err != nil {
			return xid.NilID(), err
		}
		// Get user's organization
		return c.GetResourceOrganization(ctx, ResourceUser, session.UserID)

	case ResourceMFA, ResourceVerification:
		// Get user's organization through user
		var userID xid.ID
		if resourceType == ResourceMFA {
			mfa, err := c.client.DB.MFA.Get(ctx, resourceID)
			if err != nil {
				return xid.NilID(), err
			}
			userID = mfa.UserID
		} else {
			verification, err := c.client.DB.Verification.Get(ctx, resourceID)
			if err != nil {
				return xid.NilID(), err
			}
			userID = verification.UserID
		}
		return c.GetResourceOrganization(ctx, ResourceUser, userID)

	default:
		// For unknown resource types, return an error
		return xid.NilID(), fmt.Errorf("unknown resource type for organization association: %s", resourceType)
	}
}
