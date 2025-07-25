// Copyright 2023-present XRaph LLC. All rights reserved.
// This source code is licensed under the XRaph LLC license found
// in the LICENSE file in the root directory of this source tree.
// Code generated by ent, DO NOT EDIT.

package userrole

import (
	"fmt"
	"time"

	"entgo.io/ent/dialect/sql"
	"entgo.io/ent/dialect/sql/sqlgraph"
	"github.com/rs/xid"
	"github.com/xraph/frank/pkg/model"
)

const (
	// Label holds the string label denoting the userrole type in the database.
	Label = "user_role"
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
	// FieldRoleID holds the string denoting the role_id field in the database.
	FieldRoleID = "role_id"
	// FieldContextType holds the string denoting the context_type field in the database.
	FieldContextType = "context_type"
	// FieldContextID holds the string denoting the context_id field in the database.
	FieldContextID = "context_id"
	// FieldAssignedBy holds the string denoting the assigned_by field in the database.
	FieldAssignedBy = "assigned_by"
	// FieldAssignedAt holds the string denoting the assigned_at field in the database.
	FieldAssignedAt = "assigned_at"
	// FieldExpiresAt holds the string denoting the expires_at field in the database.
	FieldExpiresAt = "expires_at"
	// FieldActive holds the string denoting the active field in the database.
	FieldActive = "active"
	// FieldConditions holds the string denoting the conditions field in the database.
	FieldConditions = "conditions"
	// EdgeUser holds the string denoting the user edge name in mutations.
	EdgeUser = "user"
	// EdgeRole holds the string denoting the role edge name in mutations.
	EdgeRole = "role"
	// EdgeOrganizationContext holds the string denoting the organization_context edge name in mutations.
	EdgeOrganizationContext = "organization_context"
	// EdgeAssignedByUser holds the string denoting the assigned_by_user edge name in mutations.
	EdgeAssignedByUser = "assigned_by_user"
	// Table holds the table name of the userrole in the database.
	Table = "user_roles"
	// UserTable is the table that holds the user relation/edge.
	UserTable = "user_roles"
	// UserInverseTable is the table name for the User entity.
	// It exists in this package in order to avoid circular dependency with the "user" package.
	UserInverseTable = "users"
	// UserColumn is the table column denoting the user relation/edge.
	UserColumn = "user_id"
	// RoleTable is the table that holds the role relation/edge.
	RoleTable = "user_roles"
	// RoleInverseTable is the table name for the Role entity.
	// It exists in this package in order to avoid circular dependency with the "role" package.
	RoleInverseTable = "roles"
	// RoleColumn is the table column denoting the role relation/edge.
	RoleColumn = "role_id"
	// OrganizationContextTable is the table that holds the organization_context relation/edge.
	OrganizationContextTable = "user_roles"
	// OrganizationContextInverseTable is the table name for the Organization entity.
	// It exists in this package in order to avoid circular dependency with the "organization" package.
	OrganizationContextInverseTable = "organizations"
	// OrganizationContextColumn is the table column denoting the organization_context relation/edge.
	OrganizationContextColumn = "context_id"
	// AssignedByUserTable is the table that holds the assigned_by_user relation/edge.
	AssignedByUserTable = "user_roles"
	// AssignedByUserInverseTable is the table name for the User entity.
	// It exists in this package in order to avoid circular dependency with the "user" package.
	AssignedByUserInverseTable = "users"
	// AssignedByUserColumn is the table column denoting the assigned_by_user relation/edge.
	AssignedByUserColumn = "assigned_by"
)

// Columns holds all SQL columns for userrole fields.
var Columns = []string{
	FieldID,
	FieldCreatedAt,
	FieldUpdatedAt,
	FieldDeletedAt,
	FieldUserID,
	FieldRoleID,
	FieldContextType,
	FieldContextID,
	FieldAssignedBy,
	FieldAssignedAt,
	FieldExpiresAt,
	FieldActive,
	FieldConditions,
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
	// RoleIDValidator is a validator for the "role_id" field. It is called by the builders before save.
	RoleIDValidator func(string) error
	// DefaultAssignedAt holds the default value on creation for the "assigned_at" field.
	DefaultAssignedAt func() time.Time
	// DefaultActive holds the default value on creation for the "active" field.
	DefaultActive bool
	// DefaultID holds the default value on creation for the "id" field.
	DefaultID func() xid.ID
)

// ContextTypeValidator is a validator for the "context_type" field enum values. It is called by the builders before save.
func ContextTypeValidator(ct model.ContextType) error {
	switch ct.String() {
	case "platform", "organization", "application", "resource", "self", "global":
		return nil
	default:
		return fmt.Errorf("userrole: invalid enum value for context_type field: %q", ct)
	}
}

// OrderOption defines the ordering options for the UserRole queries.
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

// ByRoleID orders the results by the role_id field.
func ByRoleID(opts ...sql.OrderTermOption) OrderOption {
	return sql.OrderByField(FieldRoleID, opts...).ToFunc()
}

// ByContextType orders the results by the context_type field.
func ByContextType(opts ...sql.OrderTermOption) OrderOption {
	return sql.OrderByField(FieldContextType, opts...).ToFunc()
}

// ByContextID orders the results by the context_id field.
func ByContextID(opts ...sql.OrderTermOption) OrderOption {
	return sql.OrderByField(FieldContextID, opts...).ToFunc()
}

// ByAssignedBy orders the results by the assigned_by field.
func ByAssignedBy(opts ...sql.OrderTermOption) OrderOption {
	return sql.OrderByField(FieldAssignedBy, opts...).ToFunc()
}

// ByAssignedAt orders the results by the assigned_at field.
func ByAssignedAt(opts ...sql.OrderTermOption) OrderOption {
	return sql.OrderByField(FieldAssignedAt, opts...).ToFunc()
}

// ByExpiresAt orders the results by the expires_at field.
func ByExpiresAt(opts ...sql.OrderTermOption) OrderOption {
	return sql.OrderByField(FieldExpiresAt, opts...).ToFunc()
}

// ByActive orders the results by the active field.
func ByActive(opts ...sql.OrderTermOption) OrderOption {
	return sql.OrderByField(FieldActive, opts...).ToFunc()
}

// ByUserField orders the results by user field.
func ByUserField(field string, opts ...sql.OrderTermOption) OrderOption {
	return func(s *sql.Selector) {
		sqlgraph.OrderByNeighborTerms(s, newUserStep(), sql.OrderByField(field, opts...))
	}
}

// ByRoleField orders the results by role field.
func ByRoleField(field string, opts ...sql.OrderTermOption) OrderOption {
	return func(s *sql.Selector) {
		sqlgraph.OrderByNeighborTerms(s, newRoleStep(), sql.OrderByField(field, opts...))
	}
}

// ByOrganizationContextField orders the results by organization_context field.
func ByOrganizationContextField(field string, opts ...sql.OrderTermOption) OrderOption {
	return func(s *sql.Selector) {
		sqlgraph.OrderByNeighborTerms(s, newOrganizationContextStep(), sql.OrderByField(field, opts...))
	}
}

// ByAssignedByUserField orders the results by assigned_by_user field.
func ByAssignedByUserField(field string, opts ...sql.OrderTermOption) OrderOption {
	return func(s *sql.Selector) {
		sqlgraph.OrderByNeighborTerms(s, newAssignedByUserStep(), sql.OrderByField(field, opts...))
	}
}
func newUserStep() *sqlgraph.Step {
	return sqlgraph.NewStep(
		sqlgraph.From(Table, FieldID),
		sqlgraph.To(UserInverseTable, FieldID),
		sqlgraph.Edge(sqlgraph.M2O, true, UserTable, UserColumn),
	)
}
func newRoleStep() *sqlgraph.Step {
	return sqlgraph.NewStep(
		sqlgraph.From(Table, FieldID),
		sqlgraph.To(RoleInverseTable, FieldID),
		sqlgraph.Edge(sqlgraph.M2O, true, RoleTable, RoleColumn),
	)
}
func newOrganizationContextStep() *sqlgraph.Step {
	return sqlgraph.NewStep(
		sqlgraph.From(Table, FieldID),
		sqlgraph.To(OrganizationContextInverseTable, FieldID),
		sqlgraph.Edge(sqlgraph.M2O, false, OrganizationContextTable, OrganizationContextColumn),
	)
}
func newAssignedByUserStep() *sqlgraph.Step {
	return sqlgraph.NewStep(
		sqlgraph.From(Table, FieldID),
		sqlgraph.To(AssignedByUserInverseTable, FieldID),
		sqlgraph.Edge(sqlgraph.M2O, true, AssignedByUserTable, AssignedByUserColumn),
	)
}
