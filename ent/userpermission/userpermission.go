// Copyright 2023-present XRaph LLC. All rights reserved.
// This source code is licensed under the XRaph LLC license found
// in the LICENSE file in the root directory of this source tree.
// Code generated by ent, DO NOT EDIT.

package userpermission

import (
	"fmt"
	"time"

	"entgo.io/ent/dialect/sql"
	"entgo.io/ent/dialect/sql/sqlgraph"
	"github.com/rs/xid"
	"github.com/xraph/frank/pkg/model"
)

const (
	// Label holds the string label denoting the userpermission type in the database.
	Label = "user_permission"
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
	// FieldPermissionID holds the string denoting the permission_id field in the database.
	FieldPermissionID = "permission_id"
	// FieldContextType holds the string denoting the context_type field in the database.
	FieldContextType = "context_type"
	// FieldContextID holds the string denoting the context_id field in the database.
	FieldContextID = "context_id"
	// FieldResourceType holds the string denoting the resource_type field in the database.
	FieldResourceType = "resource_type"
	// FieldResourceID holds the string denoting the resource_id field in the database.
	FieldResourceID = "resource_id"
	// FieldPermissionType holds the string denoting the permission_type field in the database.
	FieldPermissionType = "permission_type"
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
	// FieldReason holds the string denoting the reason field in the database.
	FieldReason = "reason"
	// EdgeUser holds the string denoting the user edge name in mutations.
	EdgeUser = "user"
	// EdgePermission holds the string denoting the permission edge name in mutations.
	EdgePermission = "permission"
	// EdgeAssignedByUser holds the string denoting the assigned_by_user edge name in mutations.
	EdgeAssignedByUser = "assigned_by_user"
	// EdgeOrganizationContext holds the string denoting the organization_context edge name in mutations.
	EdgeOrganizationContext = "organization_context"
	// Table holds the table name of the userpermission in the database.
	Table = "user_permissions"
	// UserTable is the table that holds the user relation/edge.
	UserTable = "user_permissions"
	// UserInverseTable is the table name for the User entity.
	// It exists in this package in order to avoid circular dependency with the "user" package.
	UserInverseTable = "users"
	// UserColumn is the table column denoting the user relation/edge.
	UserColumn = "user_id"
	// PermissionTable is the table that holds the permission relation/edge.
	PermissionTable = "user_permissions"
	// PermissionInverseTable is the table name for the Permission entity.
	// It exists in this package in order to avoid circular dependency with the "permission" package.
	PermissionInverseTable = "permissions"
	// PermissionColumn is the table column denoting the permission relation/edge.
	PermissionColumn = "permission_id"
	// AssignedByUserTable is the table that holds the assigned_by_user relation/edge.
	AssignedByUserTable = "user_permissions"
	// AssignedByUserInverseTable is the table name for the User entity.
	// It exists in this package in order to avoid circular dependency with the "user" package.
	AssignedByUserInverseTable = "users"
	// AssignedByUserColumn is the table column denoting the assigned_by_user relation/edge.
	AssignedByUserColumn = "assigned_by"
	// OrganizationContextTable is the table that holds the organization_context relation/edge.
	OrganizationContextTable = "user_permissions"
	// OrganizationContextInverseTable is the table name for the Organization entity.
	// It exists in this package in order to avoid circular dependency with the "organization" package.
	OrganizationContextInverseTable = "organizations"
	// OrganizationContextColumn is the table column denoting the organization_context relation/edge.
	OrganizationContextColumn = "context_id"
)

// Columns holds all SQL columns for userpermission fields.
var Columns = []string{
	FieldID,
	FieldCreatedAt,
	FieldUpdatedAt,
	FieldDeletedAt,
	FieldUserID,
	FieldPermissionID,
	FieldContextType,
	FieldContextID,
	FieldResourceType,
	FieldResourceID,
	FieldPermissionType,
	FieldAssignedBy,
	FieldAssignedAt,
	FieldExpiresAt,
	FieldActive,
	FieldConditions,
	FieldReason,
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
	// PermissionIDValidator is a validator for the "permission_id" field. It is called by the builders before save.
	PermissionIDValidator func(string) error
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
		return fmt.Errorf("userpermission: invalid enum value for context_type field: %q", ct)
	}
}

const DefaultPermissionType model.PermissionType = "grant"

// PermissionTypeValidator is a validator for the "permission_type" field enum values. It is called by the builders before save.
func PermissionTypeValidator(pt model.PermissionType) error {
	switch pt.String() {
	case "grant", "deny":
		return nil
	default:
		return fmt.Errorf("userpermission: invalid enum value for permission_type field: %q", pt)
	}
}

// OrderOption defines the ordering options for the UserPermission queries.
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

// ByPermissionID orders the results by the permission_id field.
func ByPermissionID(opts ...sql.OrderTermOption) OrderOption {
	return sql.OrderByField(FieldPermissionID, opts...).ToFunc()
}

// ByContextType orders the results by the context_type field.
func ByContextType(opts ...sql.OrderTermOption) OrderOption {
	return sql.OrderByField(FieldContextType, opts...).ToFunc()
}

// ByContextID orders the results by the context_id field.
func ByContextID(opts ...sql.OrderTermOption) OrderOption {
	return sql.OrderByField(FieldContextID, opts...).ToFunc()
}

// ByResourceType orders the results by the resource_type field.
func ByResourceType(opts ...sql.OrderTermOption) OrderOption {
	return sql.OrderByField(FieldResourceType, opts...).ToFunc()
}

// ByResourceID orders the results by the resource_id field.
func ByResourceID(opts ...sql.OrderTermOption) OrderOption {
	return sql.OrderByField(FieldResourceID, opts...).ToFunc()
}

// ByPermissionType orders the results by the permission_type field.
func ByPermissionType(opts ...sql.OrderTermOption) OrderOption {
	return sql.OrderByField(FieldPermissionType, opts...).ToFunc()
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

// ByReason orders the results by the reason field.
func ByReason(opts ...sql.OrderTermOption) OrderOption {
	return sql.OrderByField(FieldReason, opts...).ToFunc()
}

// ByUserField orders the results by user field.
func ByUserField(field string, opts ...sql.OrderTermOption) OrderOption {
	return func(s *sql.Selector) {
		sqlgraph.OrderByNeighborTerms(s, newUserStep(), sql.OrderByField(field, opts...))
	}
}

// ByPermissionField orders the results by permission field.
func ByPermissionField(field string, opts ...sql.OrderTermOption) OrderOption {
	return func(s *sql.Selector) {
		sqlgraph.OrderByNeighborTerms(s, newPermissionStep(), sql.OrderByField(field, opts...))
	}
}

// ByAssignedByUserField orders the results by assigned_by_user field.
func ByAssignedByUserField(field string, opts ...sql.OrderTermOption) OrderOption {
	return func(s *sql.Selector) {
		sqlgraph.OrderByNeighborTerms(s, newAssignedByUserStep(), sql.OrderByField(field, opts...))
	}
}

// ByOrganizationContextField orders the results by organization_context field.
func ByOrganizationContextField(field string, opts ...sql.OrderTermOption) OrderOption {
	return func(s *sql.Selector) {
		sqlgraph.OrderByNeighborTerms(s, newOrganizationContextStep(), sql.OrderByField(field, opts...))
	}
}
func newUserStep() *sqlgraph.Step {
	return sqlgraph.NewStep(
		sqlgraph.From(Table, FieldID),
		sqlgraph.To(UserInverseTable, FieldID),
		sqlgraph.Edge(sqlgraph.M2O, true, UserTable, UserColumn),
	)
}
func newPermissionStep() *sqlgraph.Step {
	return sqlgraph.NewStep(
		sqlgraph.From(Table, FieldID),
		sqlgraph.To(PermissionInverseTable, FieldID),
		sqlgraph.Edge(sqlgraph.M2O, true, PermissionTable, PermissionColumn),
	)
}
func newAssignedByUserStep() *sqlgraph.Step {
	return sqlgraph.NewStep(
		sqlgraph.From(Table, FieldID),
		sqlgraph.To(AssignedByUserInverseTable, FieldID),
		sqlgraph.Edge(sqlgraph.M2O, true, AssignedByUserTable, AssignedByUserColumn),
	)
}
func newOrganizationContextStep() *sqlgraph.Step {
	return sqlgraph.NewStep(
		sqlgraph.From(Table, FieldID),
		sqlgraph.To(OrganizationContextInverseTable, FieldID),
		sqlgraph.Edge(sqlgraph.M2O, false, OrganizationContextTable, OrganizationContextColumn),
	)
}
