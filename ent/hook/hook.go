// Copyright 2023-present XRaph LLC. All rights reserved.
// This source code is licensed under the XRaph LLC license found
// in the LICENSE file in the root directory of this source tree.
// Code generated by ent, DO NOT EDIT.

package hook

import (
	"context"
	"fmt"

	"github.com/xraph/frank/ent"
)

// The ActivityFunc type is an adapter to allow the use of ordinary
// function as Activity mutator.
type ActivityFunc func(context.Context, *ent.ActivityMutation) (ent.Value, error)

// Mutate calls f(ctx, m).
func (f ActivityFunc) Mutate(ctx context.Context, m ent.Mutation) (ent.Value, error) {
	if mv, ok := m.(*ent.ActivityMutation); ok {
		return f(ctx, mv)
	}
	return nil, fmt.Errorf("unexpected mutation type %T. expect *ent.ActivityMutation", m)
}

// The ApiKeyFunc type is an adapter to allow the use of ordinary
// function as ApiKey mutator.
type ApiKeyFunc func(context.Context, *ent.ApiKeyMutation) (ent.Value, error)

// Mutate calls f(ctx, m).
func (f ApiKeyFunc) Mutate(ctx context.Context, m ent.Mutation) (ent.Value, error) {
	if mv, ok := m.(*ent.ApiKeyMutation); ok {
		return f(ctx, mv)
	}
	return nil, fmt.Errorf("unexpected mutation type %T. expect *ent.ApiKeyMutation", m)
}

// The ApiKeyActivityFunc type is an adapter to allow the use of ordinary
// function as ApiKeyActivity mutator.
type ApiKeyActivityFunc func(context.Context, *ent.ApiKeyActivityMutation) (ent.Value, error)

// Mutate calls f(ctx, m).
func (f ApiKeyActivityFunc) Mutate(ctx context.Context, m ent.Mutation) (ent.Value, error) {
	if mv, ok := m.(*ent.ApiKeyActivityMutation); ok {
		return f(ctx, mv)
	}
	return nil, fmt.Errorf("unexpected mutation type %T. expect *ent.ApiKeyActivityMutation", m)
}

// The AuditFunc type is an adapter to allow the use of ordinary
// function as Audit mutator.
type AuditFunc func(context.Context, *ent.AuditMutation) (ent.Value, error)

// Mutate calls f(ctx, m).
func (f AuditFunc) Mutate(ctx context.Context, m ent.Mutation) (ent.Value, error) {
	if mv, ok := m.(*ent.AuditMutation); ok {
		return f(ctx, mv)
	}
	return nil, fmt.Errorf("unexpected mutation type %T. expect *ent.AuditMutation", m)
}

// The EmailTemplateFunc type is an adapter to allow the use of ordinary
// function as EmailTemplate mutator.
type EmailTemplateFunc func(context.Context, *ent.EmailTemplateMutation) (ent.Value, error)

// Mutate calls f(ctx, m).
func (f EmailTemplateFunc) Mutate(ctx context.Context, m ent.Mutation) (ent.Value, error) {
	if mv, ok := m.(*ent.EmailTemplateMutation); ok {
		return f(ctx, mv)
	}
	return nil, fmt.Errorf("unexpected mutation type %T. expect *ent.EmailTemplateMutation", m)
}

// The FeatureFlagFunc type is an adapter to allow the use of ordinary
// function as FeatureFlag mutator.
type FeatureFlagFunc func(context.Context, *ent.FeatureFlagMutation) (ent.Value, error)

// Mutate calls f(ctx, m).
func (f FeatureFlagFunc) Mutate(ctx context.Context, m ent.Mutation) (ent.Value, error) {
	if mv, ok := m.(*ent.FeatureFlagMutation); ok {
		return f(ctx, mv)
	}
	return nil, fmt.Errorf("unexpected mutation type %T. expect *ent.FeatureFlagMutation", m)
}

// The IdentityProviderFunc type is an adapter to allow the use of ordinary
// function as IdentityProvider mutator.
type IdentityProviderFunc func(context.Context, *ent.IdentityProviderMutation) (ent.Value, error)

// Mutate calls f(ctx, m).
func (f IdentityProviderFunc) Mutate(ctx context.Context, m ent.Mutation) (ent.Value, error) {
	if mv, ok := m.(*ent.IdentityProviderMutation); ok {
		return f(ctx, mv)
	}
	return nil, fmt.Errorf("unexpected mutation type %T. expect *ent.IdentityProviderMutation", m)
}

// The MFAFunc type is an adapter to allow the use of ordinary
// function as MFA mutator.
type MFAFunc func(context.Context, *ent.MFAMutation) (ent.Value, error)

// Mutate calls f(ctx, m).
func (f MFAFunc) Mutate(ctx context.Context, m ent.Mutation) (ent.Value, error) {
	if mv, ok := m.(*ent.MFAMutation); ok {
		return f(ctx, mv)
	}
	return nil, fmt.Errorf("unexpected mutation type %T. expect *ent.MFAMutation", m)
}

// The MembershipFunc type is an adapter to allow the use of ordinary
// function as Membership mutator.
type MembershipFunc func(context.Context, *ent.MembershipMutation) (ent.Value, error)

// Mutate calls f(ctx, m).
func (f MembershipFunc) Mutate(ctx context.Context, m ent.Mutation) (ent.Value, error) {
	if mv, ok := m.(*ent.MembershipMutation); ok {
		return f(ctx, mv)
	}
	return nil, fmt.Errorf("unexpected mutation type %T. expect *ent.MembershipMutation", m)
}

// The OAuthAuthorizationFunc type is an adapter to allow the use of ordinary
// function as OAuthAuthorization mutator.
type OAuthAuthorizationFunc func(context.Context, *ent.OAuthAuthorizationMutation) (ent.Value, error)

// Mutate calls f(ctx, m).
func (f OAuthAuthorizationFunc) Mutate(ctx context.Context, m ent.Mutation) (ent.Value, error) {
	if mv, ok := m.(*ent.OAuthAuthorizationMutation); ok {
		return f(ctx, mv)
	}
	return nil, fmt.Errorf("unexpected mutation type %T. expect *ent.OAuthAuthorizationMutation", m)
}

// The OAuthClientFunc type is an adapter to allow the use of ordinary
// function as OAuthClient mutator.
type OAuthClientFunc func(context.Context, *ent.OAuthClientMutation) (ent.Value, error)

// Mutate calls f(ctx, m).
func (f OAuthClientFunc) Mutate(ctx context.Context, m ent.Mutation) (ent.Value, error) {
	if mv, ok := m.(*ent.OAuthClientMutation); ok {
		return f(ctx, mv)
	}
	return nil, fmt.Errorf("unexpected mutation type %T. expect *ent.OAuthClientMutation", m)
}

// The OAuthScopeFunc type is an adapter to allow the use of ordinary
// function as OAuthScope mutator.
type OAuthScopeFunc func(context.Context, *ent.OAuthScopeMutation) (ent.Value, error)

// Mutate calls f(ctx, m).
func (f OAuthScopeFunc) Mutate(ctx context.Context, m ent.Mutation) (ent.Value, error) {
	if mv, ok := m.(*ent.OAuthScopeMutation); ok {
		return f(ctx, mv)
	}
	return nil, fmt.Errorf("unexpected mutation type %T. expect *ent.OAuthScopeMutation", m)
}

// The OAuthTokenFunc type is an adapter to allow the use of ordinary
// function as OAuthToken mutator.
type OAuthTokenFunc func(context.Context, *ent.OAuthTokenMutation) (ent.Value, error)

// Mutate calls f(ctx, m).
func (f OAuthTokenFunc) Mutate(ctx context.Context, m ent.Mutation) (ent.Value, error) {
	if mv, ok := m.(*ent.OAuthTokenMutation); ok {
		return f(ctx, mv)
	}
	return nil, fmt.Errorf("unexpected mutation type %T. expect *ent.OAuthTokenMutation", m)
}

// The OrganizationFunc type is an adapter to allow the use of ordinary
// function as Organization mutator.
type OrganizationFunc func(context.Context, *ent.OrganizationMutation) (ent.Value, error)

// Mutate calls f(ctx, m).
func (f OrganizationFunc) Mutate(ctx context.Context, m ent.Mutation) (ent.Value, error) {
	if mv, ok := m.(*ent.OrganizationMutation); ok {
		return f(ctx, mv)
	}
	return nil, fmt.Errorf("unexpected mutation type %T. expect *ent.OrganizationMutation", m)
}

// The OrganizationFeatureFunc type is an adapter to allow the use of ordinary
// function as OrganizationFeature mutator.
type OrganizationFeatureFunc func(context.Context, *ent.OrganizationFeatureMutation) (ent.Value, error)

// Mutate calls f(ctx, m).
func (f OrganizationFeatureFunc) Mutate(ctx context.Context, m ent.Mutation) (ent.Value, error) {
	if mv, ok := m.(*ent.OrganizationFeatureMutation); ok {
		return f(ctx, mv)
	}
	return nil, fmt.Errorf("unexpected mutation type %T. expect *ent.OrganizationFeatureMutation", m)
}

// The OrganizationProviderFunc type is an adapter to allow the use of ordinary
// function as OrganizationProvider mutator.
type OrganizationProviderFunc func(context.Context, *ent.OrganizationProviderMutation) (ent.Value, error)

// Mutate calls f(ctx, m).
func (f OrganizationProviderFunc) Mutate(ctx context.Context, m ent.Mutation) (ent.Value, error) {
	if mv, ok := m.(*ent.OrganizationProviderMutation); ok {
		return f(ctx, mv)
	}
	return nil, fmt.Errorf("unexpected mutation type %T. expect *ent.OrganizationProviderMutation", m)
}

// The PasskeyFunc type is an adapter to allow the use of ordinary
// function as Passkey mutator.
type PasskeyFunc func(context.Context, *ent.PasskeyMutation) (ent.Value, error)

// Mutate calls f(ctx, m).
func (f PasskeyFunc) Mutate(ctx context.Context, m ent.Mutation) (ent.Value, error) {
	if mv, ok := m.(*ent.PasskeyMutation); ok {
		return f(ctx, mv)
	}
	return nil, fmt.Errorf("unexpected mutation type %T. expect *ent.PasskeyMutation", m)
}

// The PermissionFunc type is an adapter to allow the use of ordinary
// function as Permission mutator.
type PermissionFunc func(context.Context, *ent.PermissionMutation) (ent.Value, error)

// Mutate calls f(ctx, m).
func (f PermissionFunc) Mutate(ctx context.Context, m ent.Mutation) (ent.Value, error) {
	if mv, ok := m.(*ent.PermissionMutation); ok {
		return f(ctx, mv)
	}
	return nil, fmt.Errorf("unexpected mutation type %T. expect *ent.PermissionMutation", m)
}

// The PermissionDependencyFunc type is an adapter to allow the use of ordinary
// function as PermissionDependency mutator.
type PermissionDependencyFunc func(context.Context, *ent.PermissionDependencyMutation) (ent.Value, error)

// Mutate calls f(ctx, m).
func (f PermissionDependencyFunc) Mutate(ctx context.Context, m ent.Mutation) (ent.Value, error) {
	if mv, ok := m.(*ent.PermissionDependencyMutation); ok {
		return f(ctx, mv)
	}
	return nil, fmt.Errorf("unexpected mutation type %T. expect *ent.PermissionDependencyMutation", m)
}

// The ProviderTemplateFunc type is an adapter to allow the use of ordinary
// function as ProviderTemplate mutator.
type ProviderTemplateFunc func(context.Context, *ent.ProviderTemplateMutation) (ent.Value, error)

// Mutate calls f(ctx, m).
func (f ProviderTemplateFunc) Mutate(ctx context.Context, m ent.Mutation) (ent.Value, error) {
	if mv, ok := m.(*ent.ProviderTemplateMutation); ok {
		return f(ctx, mv)
	}
	return nil, fmt.Errorf("unexpected mutation type %T. expect *ent.ProviderTemplateMutation", m)
}

// The RoleFunc type is an adapter to allow the use of ordinary
// function as Role mutator.
type RoleFunc func(context.Context, *ent.RoleMutation) (ent.Value, error)

// Mutate calls f(ctx, m).
func (f RoleFunc) Mutate(ctx context.Context, m ent.Mutation) (ent.Value, error) {
	if mv, ok := m.(*ent.RoleMutation); ok {
		return f(ctx, mv)
	}
	return nil, fmt.Errorf("unexpected mutation type %T. expect *ent.RoleMutation", m)
}

// The SMSTemplateFunc type is an adapter to allow the use of ordinary
// function as SMSTemplate mutator.
type SMSTemplateFunc func(context.Context, *ent.SMSTemplateMutation) (ent.Value, error)

// Mutate calls f(ctx, m).
func (f SMSTemplateFunc) Mutate(ctx context.Context, m ent.Mutation) (ent.Value, error) {
	if mv, ok := m.(*ent.SMSTemplateMutation); ok {
		return f(ctx, mv)
	}
	return nil, fmt.Errorf("unexpected mutation type %T. expect *ent.SMSTemplateMutation", m)
}

// The SSOStateFunc type is an adapter to allow the use of ordinary
// function as SSOState mutator.
type SSOStateFunc func(context.Context, *ent.SSOStateMutation) (ent.Value, error)

// Mutate calls f(ctx, m).
func (f SSOStateFunc) Mutate(ctx context.Context, m ent.Mutation) (ent.Value, error) {
	if mv, ok := m.(*ent.SSOStateMutation); ok {
		return f(ctx, mv)
	}
	return nil, fmt.Errorf("unexpected mutation type %T. expect *ent.SSOStateMutation", m)
}

// The SessionFunc type is an adapter to allow the use of ordinary
// function as Session mutator.
type SessionFunc func(context.Context, *ent.SessionMutation) (ent.Value, error)

// Mutate calls f(ctx, m).
func (f SessionFunc) Mutate(ctx context.Context, m ent.Mutation) (ent.Value, error) {
	if mv, ok := m.(*ent.SessionMutation); ok {
		return f(ctx, mv)
	}
	return nil, fmt.Errorf("unexpected mutation type %T. expect *ent.SessionMutation", m)
}

// The UserFunc type is an adapter to allow the use of ordinary
// function as User mutator.
type UserFunc func(context.Context, *ent.UserMutation) (ent.Value, error)

// Mutate calls f(ctx, m).
func (f UserFunc) Mutate(ctx context.Context, m ent.Mutation) (ent.Value, error) {
	if mv, ok := m.(*ent.UserMutation); ok {
		return f(ctx, mv)
	}
	return nil, fmt.Errorf("unexpected mutation type %T. expect *ent.UserMutation", m)
}

// The UserPermissionFunc type is an adapter to allow the use of ordinary
// function as UserPermission mutator.
type UserPermissionFunc func(context.Context, *ent.UserPermissionMutation) (ent.Value, error)

// Mutate calls f(ctx, m).
func (f UserPermissionFunc) Mutate(ctx context.Context, m ent.Mutation) (ent.Value, error) {
	if mv, ok := m.(*ent.UserPermissionMutation); ok {
		return f(ctx, mv)
	}
	return nil, fmt.Errorf("unexpected mutation type %T. expect *ent.UserPermissionMutation", m)
}

// The UserRoleFunc type is an adapter to allow the use of ordinary
// function as UserRole mutator.
type UserRoleFunc func(context.Context, *ent.UserRoleMutation) (ent.Value, error)

// Mutate calls f(ctx, m).
func (f UserRoleFunc) Mutate(ctx context.Context, m ent.Mutation) (ent.Value, error) {
	if mv, ok := m.(*ent.UserRoleMutation); ok {
		return f(ctx, mv)
	}
	return nil, fmt.Errorf("unexpected mutation type %T. expect *ent.UserRoleMutation", m)
}

// The VerificationFunc type is an adapter to allow the use of ordinary
// function as Verification mutator.
type VerificationFunc func(context.Context, *ent.VerificationMutation) (ent.Value, error)

// Mutate calls f(ctx, m).
func (f VerificationFunc) Mutate(ctx context.Context, m ent.Mutation) (ent.Value, error) {
	if mv, ok := m.(*ent.VerificationMutation); ok {
		return f(ctx, mv)
	}
	return nil, fmt.Errorf("unexpected mutation type %T. expect *ent.VerificationMutation", m)
}

// The WebhookFunc type is an adapter to allow the use of ordinary
// function as Webhook mutator.
type WebhookFunc func(context.Context, *ent.WebhookMutation) (ent.Value, error)

// Mutate calls f(ctx, m).
func (f WebhookFunc) Mutate(ctx context.Context, m ent.Mutation) (ent.Value, error) {
	if mv, ok := m.(*ent.WebhookMutation); ok {
		return f(ctx, mv)
	}
	return nil, fmt.Errorf("unexpected mutation type %T. expect *ent.WebhookMutation", m)
}

// The WebhookEventFunc type is an adapter to allow the use of ordinary
// function as WebhookEvent mutator.
type WebhookEventFunc func(context.Context, *ent.WebhookEventMutation) (ent.Value, error)

// Mutate calls f(ctx, m).
func (f WebhookEventFunc) Mutate(ctx context.Context, m ent.Mutation) (ent.Value, error) {
	if mv, ok := m.(*ent.WebhookEventMutation); ok {
		return f(ctx, mv)
	}
	return nil, fmt.Errorf("unexpected mutation type %T. expect *ent.WebhookEventMutation", m)
}

// Condition is a hook condition function.
type Condition func(context.Context, ent.Mutation) bool

// And groups conditions with the AND operator.
func And(first, second Condition, rest ...Condition) Condition {
	return func(ctx context.Context, m ent.Mutation) bool {
		if !first(ctx, m) || !second(ctx, m) {
			return false
		}
		for _, cond := range rest {
			if !cond(ctx, m) {
				return false
			}
		}
		return true
	}
}

// Or groups conditions with the OR operator.
func Or(first, second Condition, rest ...Condition) Condition {
	return func(ctx context.Context, m ent.Mutation) bool {
		if first(ctx, m) || second(ctx, m) {
			return true
		}
		for _, cond := range rest {
			if cond(ctx, m) {
				return true
			}
		}
		return false
	}
}

// Not negates a given condition.
func Not(cond Condition) Condition {
	return func(ctx context.Context, m ent.Mutation) bool {
		return !cond(ctx, m)
	}
}

// HasOp is a condition testing mutation operation.
func HasOp(op ent.Op) Condition {
	return func(_ context.Context, m ent.Mutation) bool {
		return m.Op().Is(op)
	}
}

// HasAddedFields is a condition validating `.AddedField` on fields.
func HasAddedFields(field string, fields ...string) Condition {
	return func(_ context.Context, m ent.Mutation) bool {
		if _, exists := m.AddedField(field); !exists {
			return false
		}
		for _, field := range fields {
			if _, exists := m.AddedField(field); !exists {
				return false
			}
		}
		return true
	}
}

// HasClearedFields is a condition validating `.FieldCleared` on fields.
func HasClearedFields(field string, fields ...string) Condition {
	return func(_ context.Context, m ent.Mutation) bool {
		if exists := m.FieldCleared(field); !exists {
			return false
		}
		for _, field := range fields {
			if exists := m.FieldCleared(field); !exists {
				return false
			}
		}
		return true
	}
}

// HasFields is a condition validating `.Field` on fields.
func HasFields(field string, fields ...string) Condition {
	return func(_ context.Context, m ent.Mutation) bool {
		if _, exists := m.Field(field); !exists {
			return false
		}
		for _, field := range fields {
			if _, exists := m.Field(field); !exists {
				return false
			}
		}
		return true
	}
}

// If executes the given hook under condition.
//
//	hook.If(ComputeAverage, And(HasFields(...), HasAddedFields(...)))
func If(hk ent.Hook, cond Condition) ent.Hook {
	return func(next ent.Mutator) ent.Mutator {
		return ent.MutateFunc(func(ctx context.Context, m ent.Mutation) (ent.Value, error) {
			if cond(ctx, m) {
				return hk(next).Mutate(ctx, m)
			}
			return next.Mutate(ctx, m)
		})
	}
}

// On executes the given hook only for the given operation.
//
//	hook.On(Log, ent.Delete|ent.Create)
func On(hk ent.Hook, op ent.Op) ent.Hook {
	return If(hk, HasOp(op))
}

// Unless skips the given hook only for the given operation.
//
//	hook.Unless(Log, ent.Update|ent.UpdateOne)
func Unless(hk ent.Hook, op ent.Op) ent.Hook {
	return If(hk, Not(HasOp(op)))
}

// FixedError is a hook returning a fixed error.
func FixedError(err error) ent.Hook {
	return func(ent.Mutator) ent.Mutator {
		return ent.MutateFunc(func(context.Context, ent.Mutation) (ent.Value, error) {
			return nil, err
		})
	}
}

// Reject returns a hook that rejects all operations that match op.
//
//	func (T) Hooks() []ent.Hook {
//		return []ent.Hook{
//			Reject(ent.Delete|ent.Update),
//		}
//	}
func Reject(op ent.Op) ent.Hook {
	hk := FixedError(fmt.Errorf("%s operation is not allowed", op))
	return On(hk, op)
}

// Chain acts as a list of hooks and is effectively immutable.
// Once created, it will always hold the same set of hooks in the same order.
type Chain struct {
	hooks []ent.Hook
}

// NewChain creates a new chain of hooks.
func NewChain(hooks ...ent.Hook) Chain {
	return Chain{append([]ent.Hook(nil), hooks...)}
}

// Hook chains the list of hooks and returns the final hook.
func (c Chain) Hook() ent.Hook {
	return func(mutator ent.Mutator) ent.Mutator {
		for i := len(c.hooks) - 1; i >= 0; i-- {
			mutator = c.hooks[i](mutator)
		}
		return mutator
	}
}

// Append extends a chain, adding the specified hook
// as the last ones in the mutation flow.
func (c Chain) Append(hooks ...ent.Hook) Chain {
	newHooks := make([]ent.Hook, 0, len(c.hooks)+len(hooks))
	newHooks = append(newHooks, c.hooks...)
	newHooks = append(newHooks, hooks...)
	return Chain{newHooks}
}

// Extend extends a chain, adding the specified chain
// as the last ones in the mutation flow.
func (c Chain) Extend(chain Chain) Chain {
	return c.Append(chain.hooks...)
}
