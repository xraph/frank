// Copyright 2023-present XRaph LLC. All rights reserved.
// This source code is licensed under the XRaph LLC license found
// in the LICENSE file in the root directory of this source tree.
// Code generated by ent, DO NOT EDIT.

package membership

import (
	"fmt"
	"time"

	"entgo.io/ent/dialect/sql"
	"entgo.io/ent/dialect/sql/sqlgraph"
	"github.com/rs/xid"
	"github.com/xraph/frank/pkg/model"
)

const (
	// Label holds the string label denoting the membership type in the database.
	Label = "membership"
	// FieldID holds the string denoting the id field in the database.
	FieldID = "id"
	// FieldCreatedAt holds the string denoting the created_at field in the database.
	FieldCreatedAt = "created_at"
	// FieldUpdatedAt holds the string denoting the updated_at field in the database.
	FieldUpdatedAt = "updated_at"
	// FieldDeletedAt holds the string denoting the deleted_at field in the database.
	FieldDeletedAt = "deleted_at"
	// FieldUserID holds the string denoting the user_id field in the database.
	FieldUserID = "user_id"
	// FieldOrganizationID holds the string denoting the organization_id field in the database.
	FieldOrganizationID = "organization_id"
	// FieldRoleID holds the string denoting the role_id field in the database.
	FieldRoleID = "role_id"
	// FieldEmail holds the string denoting the email field in the database.
	FieldEmail = "email"
	// FieldStatus holds the string denoting the status field in the database.
	FieldStatus = "status"
	// FieldInvitedBy holds the string denoting the invited_by field in the database.
	FieldInvitedBy = "invited_by"
	// FieldInvitedAt holds the string denoting the invited_at field in the database.
	FieldInvitedAt = "invited_at"
	// FieldJoinedAt holds the string denoting the joined_at field in the database.
	FieldJoinedAt = "joined_at"
	// FieldExpiresAt holds the string denoting the expires_at field in the database.
	FieldExpiresAt = "expires_at"
	// FieldInvitationToken holds the string denoting the invitation_token field in the database.
	FieldInvitationToken = "invitation_token"
	// FieldIsBillingContact holds the string denoting the is_billing_contact field in the database.
	FieldIsBillingContact = "is_billing_contact"
	// FieldIsPrimaryContact holds the string denoting the is_primary_contact field in the database.
	FieldIsPrimaryContact = "is_primary_contact"
	// FieldLeftAt holds the string denoting the left_at field in the database.
	FieldLeftAt = "left_at"
	// FieldMetadata holds the string denoting the metadata field in the database.
	FieldMetadata = "metadata"
	// FieldCustomFields holds the string denoting the custom_fields field in the database.
	FieldCustomFields = "custom_fields"
	// EdgeUser holds the string denoting the user edge name in mutations.
	EdgeUser = "user"
	// EdgeOrganization holds the string denoting the organization edge name in mutations.
	EdgeOrganization = "organization"
	// EdgeRole holds the string denoting the role edge name in mutations.
	EdgeRole = "role"
	// EdgeInviter holds the string denoting the inviter edge name in mutations.
	EdgeInviter = "inviter"
	// Table holds the table name of the membership in the database.
	Table = "memberships"
	// UserTable is the table that holds the user relation/edge.
	UserTable = "memberships"
	// UserInverseTable is the table name for the User entity.
	// It exists in this package in order to avoid circular dependency with the "user" package.
	UserInverseTable = "users"
	// UserColumn is the table column denoting the user relation/edge.
	UserColumn = "user_id"
	// OrganizationTable is the table that holds the organization relation/edge.
	OrganizationTable = "memberships"
	// OrganizationInverseTable is the table name for the Organization entity.
	// It exists in this package in order to avoid circular dependency with the "organization" package.
	OrganizationInverseTable = "organizations"
	// OrganizationColumn is the table column denoting the organization relation/edge.
	OrganizationColumn = "organization_id"
	// RoleTable is the table that holds the role relation/edge.
	RoleTable = "memberships"
	// RoleInverseTable is the table name for the Role entity.
	// It exists in this package in order to avoid circular dependency with the "role" package.
	RoleInverseTable = "roles"
	// RoleColumn is the table column denoting the role relation/edge.
	RoleColumn = "role_id"
	// InviterTable is the table that holds the inviter relation/edge.
	InviterTable = "memberships"
	// InviterInverseTable is the table name for the User entity.
	// It exists in this package in order to avoid circular dependency with the "user" package.
	InviterInverseTable = "users"
	// InviterColumn is the table column denoting the inviter relation/edge.
	InviterColumn = "invited_by"
)

// Columns holds all SQL columns for membership fields.
var Columns = []string{
	FieldID,
	FieldCreatedAt,
	FieldUpdatedAt,
	FieldDeletedAt,
	FieldUserID,
	FieldOrganizationID,
	FieldRoleID,
	FieldEmail,
	FieldStatus,
	FieldInvitedBy,
	FieldInvitedAt,
	FieldJoinedAt,
	FieldExpiresAt,
	FieldInvitationToken,
	FieldIsBillingContact,
	FieldIsPrimaryContact,
	FieldLeftAt,
	FieldMetadata,
	FieldCustomFields,
}

// ValidColumn reports if the column name is valid (part of the table columns).
func ValidColumn(column string) bool {
	for i := range Columns {
		if column == Columns[i] {
			return true
		}
	}
	return false
}

var (
	// DefaultCreatedAt holds the default value on creation for the "created_at" field.
	DefaultCreatedAt func() time.Time
	// DefaultUpdatedAt holds the default value on creation for the "updated_at" field.
	DefaultUpdatedAt func() time.Time
	// UpdateDefaultUpdatedAt holds the default value on update for the "updated_at" field.
	UpdateDefaultUpdatedAt func() time.Time
	// UserIDValidator is a validator for the "user_id" field. It is called by the builders before save.
	UserIDValidator func(string) error
	// OrganizationIDValidator is a validator for the "organization_id" field. It is called by the builders before save.
	OrganizationIDValidator func(string) error
	// RoleIDValidator is a validator for the "role_id" field. It is called by the builders before save.
	RoleIDValidator func(string) error
	// EmailValidator is a validator for the "email" field. It is called by the builders before save.
	EmailValidator func(string) error
	// DefaultInvitedAt holds the default value on creation for the "invited_at" field.
	DefaultInvitedAt func() time.Time
	// DefaultIsBillingContact holds the default value on creation for the "is_billing_contact" field.
	DefaultIsBillingContact bool
	// DefaultIsPrimaryContact holds the default value on creation for the "is_primary_contact" field.
	DefaultIsPrimaryContact bool
	// DefaultID holds the default value on creation for the "id" field.
	DefaultID func() xid.ID
)

const DefaultStatus model.MembershipStatus = "pending"

// StatusValidator is a validator for the "status" field enum values. It is called by the builders before save.
func StatusValidator(s model.MembershipStatus) error {
	switch s.String() {
	case "pending", "active", "inactive", "suspended":
		return nil
	default:
		return fmt.Errorf("membership: invalid enum value for status field: %q", s)
	}
}

// OrderOption defines the ordering options for the Membership queries.
type OrderOption func(*sql.Selector)

// ByID orders the results by the id field.
func ByID(opts ...sql.OrderTermOption) OrderOption {
	return sql.OrderByField(FieldID, opts...).ToFunc()
}

// ByCreatedAt orders the results by the created_at field.
func ByCreatedAt(opts ...sql.OrderTermOption) OrderOption {
	return sql.OrderByField(FieldCreatedAt, opts...).ToFunc()
}

// ByUpdatedAt orders the results by the updated_at field.
func ByUpdatedAt(opts ...sql.OrderTermOption) OrderOption {
	return sql.OrderByField(FieldUpdatedAt, opts...).ToFunc()
}

// ByDeletedAt orders the results by the deleted_at field.
func ByDeletedAt(opts ...sql.OrderTermOption) OrderOption {
	return sql.OrderByField(FieldDeletedAt, opts...).ToFunc()
}

// ByUserID orders the results by the user_id field.
func ByUserID(opts ...sql.OrderTermOption) OrderOption {
	return sql.OrderByField(FieldUserID, opts...).ToFunc()
}

// ByOrganizationID orders the results by the organization_id field.
func ByOrganizationID(opts ...sql.OrderTermOption) OrderOption {
	return sql.OrderByField(FieldOrganizationID, opts...).ToFunc()
}

// ByRoleID orders the results by the role_id field.
func ByRoleID(opts ...sql.OrderTermOption) OrderOption {
	return sql.OrderByField(FieldRoleID, opts...).ToFunc()
}

// ByEmail orders the results by the email field.
func ByEmail(opts ...sql.OrderTermOption) OrderOption {
	return sql.OrderByField(FieldEmail, opts...).ToFunc()
}

// ByStatus orders the results by the status field.
func ByStatus(opts ...sql.OrderTermOption) OrderOption {
	return sql.OrderByField(FieldStatus, opts...).ToFunc()
}

// ByInvitedBy orders the results by the invited_by field.
func ByInvitedBy(opts ...sql.OrderTermOption) OrderOption {
	return sql.OrderByField(FieldInvitedBy, opts...).ToFunc()
}

// ByInvitedAt orders the results by the invited_at field.
func ByInvitedAt(opts ...sql.OrderTermOption) OrderOption {
	return sql.OrderByField(FieldInvitedAt, opts...).ToFunc()
}

// ByJoinedAt orders the results by the joined_at field.
func ByJoinedAt(opts ...sql.OrderTermOption) OrderOption {
	return sql.OrderByField(FieldJoinedAt, opts...).ToFunc()
}

// ByExpiresAt orders the results by the expires_at field.
func ByExpiresAt(opts ...sql.OrderTermOption) OrderOption {
	return sql.OrderByField(FieldExpiresAt, opts...).ToFunc()
}

// ByInvitationToken orders the results by the invitation_token field.
func ByInvitationToken(opts ...sql.OrderTermOption) OrderOption {
	return sql.OrderByField(FieldInvitationToken, opts...).ToFunc()
}

// ByIsBillingContact orders the results by the is_billing_contact field.
func ByIsBillingContact(opts ...sql.OrderTermOption) OrderOption {
	return sql.OrderByField(FieldIsBillingContact, opts...).ToFunc()
}

// ByIsPrimaryContact orders the results by the is_primary_contact field.
func ByIsPrimaryContact(opts ...sql.OrderTermOption) OrderOption {
	return sql.OrderByField(FieldIsPrimaryContact, opts...).ToFunc()
}

// ByLeftAt orders the results by the left_at field.
func ByLeftAt(opts ...sql.OrderTermOption) OrderOption {
	return sql.OrderByField(FieldLeftAt, opts...).ToFunc()
}

// ByUserField orders the results by user field.
func ByUserField(field string, opts ...sql.OrderTermOption) OrderOption {
	return func(s *sql.Selector) {
		sqlgraph.OrderByNeighborTerms(s, newUserStep(), sql.OrderByField(field, opts...))
	}
}

// ByOrganizationField orders the results by organization field.
func ByOrganizationField(field string, opts ...sql.OrderTermOption) OrderOption {
	return func(s *sql.Selector) {
		sqlgraph.OrderByNeighborTerms(s, newOrganizationStep(), sql.OrderByField(field, opts...))
	}
}

// ByRoleField orders the results by role field.
func ByRoleField(field string, opts ...sql.OrderTermOption) OrderOption {
	return func(s *sql.Selector) {
		sqlgraph.OrderByNeighborTerms(s, newRoleStep(), sql.OrderByField(field, opts...))
	}
}

// ByInviterField orders the results by inviter field.
func ByInviterField(field string, opts ...sql.OrderTermOption) OrderOption {
	return func(s *sql.Selector) {
		sqlgraph.OrderByNeighborTerms(s, newInviterStep(), sql.OrderByField(field, opts...))
	}
}
func newUserStep() *sqlgraph.Step {
	return sqlgraph.NewStep(
		sqlgraph.From(Table, FieldID),
		sqlgraph.To(UserInverseTable, FieldID),
		sqlgraph.Edge(sqlgraph.M2O, true, UserTable, UserColumn),
	)
}
func newOrganizationStep() *sqlgraph.Step {
	return sqlgraph.NewStep(
		sqlgraph.From(Table, FieldID),
		sqlgraph.To(OrganizationInverseTable, FieldID),
		sqlgraph.Edge(sqlgraph.M2O, true, OrganizationTable, OrganizationColumn),
	)
}
func newRoleStep() *sqlgraph.Step {
	return sqlgraph.NewStep(
		sqlgraph.From(Table, FieldID),
		sqlgraph.To(RoleInverseTable, FieldID),
		sqlgraph.Edge(sqlgraph.M2O, true, RoleTable, RoleColumn),
	)
}
func newInviterStep() *sqlgraph.Step {
	return sqlgraph.NewStep(
		sqlgraph.From(Table, FieldID),
		sqlgraph.To(InviterInverseTable, FieldID),
		sqlgraph.Edge(sqlgraph.M2O, true, InviterTable, InviterColumn),
	)
}
