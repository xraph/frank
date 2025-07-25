// Copyright 2023-present XRaph LLC. All rights reserved.
// This source code is licensed under the XRaph LLC license found
// in the LICENSE file in the root directory of this source tree.
// Code generated by ent, DO NOT EDIT.

package ent

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"entgo.io/ent"
	"entgo.io/ent/dialect/sql"
	"github.com/xraph/frank/ent/organization"
	"github.com/xraph/frank/ent/role"
	"github.com/xraph/frank/ent/user"
	"github.com/xraph/frank/ent/userrole"
	"github.com/xraph/frank/pkg/model"
	"github.com/rs/xid"
)

// UserRole is the model entity for the UserRole schema.
type UserRole struct {
	config `json:"-"`
	// ID of the ent.
	// ID of the entity
	ID xid.ID `json:"id,omitempty"`
	// CreatedAt holds the value of the "created_at" field.
	CreatedAt time.Time `json:"created_at,omitempty"`
	// UpdatedAt holds the value of the "updated_at" field.
	UpdatedAt time.Time `json:"updated_at,omitempty"`
	// DeletedAt holds the value of the "deleted_at" field.
	DeletedAt time.Time `json:"deleted_at,omitempty"`
	// UserID holds the value of the "user_id" field.
	UserID xid.ID `json:"user_id,omitempty"`
	// RoleID holds the value of the "role_id" field.
	RoleID xid.ID `json:"role_id,omitempty"`
	// platform = platform-wide, organization = org-specific, application = customer's app
	ContextType model.ContextType `json:"context_type,omitempty"`
	// ID of the context (org_id for org context, app_id for app context, null for system)
	ContextID xid.ID `json:"context_id,omitempty"`
	// Who assigned this role (field-only, no edge)
	AssignedBy xid.ID `json:"assigned_by,omitempty"`
	// AssignedAt holds the value of the "assigned_at" field.
	AssignedAt time.Time `json:"assigned_at,omitempty"`
	// When this role assignment expires (optional)
	ExpiresAt *time.Time `json:"expires_at,omitempty"`
	// Active holds the value of the "active" field.
	Active bool `json:"active,omitempty"`
	// Optional conditions for when this role applies
	Conditions map[string]interface{} `json:"conditions,omitempty"`
	// Edges holds the relations/edges for other nodes in the graph.
	// The values are being populated by the UserRoleQuery when eager-loading is set.
	Edges        UserRoleEdges `json:"edges"`
	selectValues sql.SelectValues
}

// UserRoleEdges holds the relations/edges for other nodes in the graph.
type UserRoleEdges struct {
	// User holds the value of the user edge.
	User *User `json:"user,omitempty"`
	// Role holds the value of the role edge.
	Role *Role `json:"role,omitempty"`
	// OrganizationContext holds the value of the organization_context edge.
	OrganizationContext *Organization `json:"organization_context,omitempty"`
	// AssignedByUser holds the value of the assigned_by_user edge.
	AssignedByUser *User `json:"assigned_by_user,omitempty"`
	// loadedTypes holds the information for reporting if a
	// type was loaded (or requested) in eager-loading or not.
	loadedTypes [4]bool
}

// UserOrErr returns the User value or an error if the edge
// was not loaded in eager-loading, or loaded but was not found.
func (e UserRoleEdges) UserOrErr() (*User, error) {
	if e.User != nil {
		return e.User, nil
	} else if e.loadedTypes[0] {
		return nil, &NotFoundError{label: user.Label}
	}
	return nil, &NotLoadedError{edge: "user"}
}

// RoleOrErr returns the Role value or an error if the edge
// was not loaded in eager-loading, or loaded but was not found.
func (e UserRoleEdges) RoleOrErr() (*Role, error) {
	if e.Role != nil {
		return e.Role, nil
	} else if e.loadedTypes[1] {
		return nil, &NotFoundError{label: role.Label}
	}
	return nil, &NotLoadedError{edge: "role"}
}

// OrganizationContextOrErr returns the OrganizationContext value or an error if the edge
// was not loaded in eager-loading, or loaded but was not found.
func (e UserRoleEdges) OrganizationContextOrErr() (*Organization, error) {
	if e.OrganizationContext != nil {
		return e.OrganizationContext, nil
	} else if e.loadedTypes[2] {
		return nil, &NotFoundError{label: organization.Label}
	}
	return nil, &NotLoadedError{edge: "organization_context"}
}

// AssignedByUserOrErr returns the AssignedByUser value or an error if the edge
// was not loaded in eager-loading, or loaded but was not found.
func (e UserRoleEdges) AssignedByUserOrErr() (*User, error) {
	if e.AssignedByUser != nil {
		return e.AssignedByUser, nil
	} else if e.loadedTypes[3] {
		return nil, &NotFoundError{label: user.Label}
	}
	return nil, &NotLoadedError{edge: "assigned_by_user"}
}

// scanValues returns the types for scanning values from sql.Rows.
func (*UserRole) scanValues(columns []string) ([]any, error) {
	values := make([]any, len(columns))
	for i := range columns {
		switch columns[i] {
		case userrole.FieldConditions:
			values[i] = new([]byte)
		case userrole.FieldActive:
			values[i] = new(sql.NullBool)
		case userrole.FieldContextType:
			values[i] = new(sql.NullString)
		case userrole.FieldCreatedAt, userrole.FieldUpdatedAt, userrole.FieldDeletedAt, userrole.FieldAssignedAt, userrole.FieldExpiresAt:
			values[i] = new(sql.NullTime)
		case userrole.FieldID, userrole.FieldUserID, userrole.FieldRoleID, userrole.FieldContextID, userrole.FieldAssignedBy:
			values[i] = new(xid.ID)
		default:
			values[i] = new(sql.UnknownType)
		}
	}
	return values, nil
}

// assignValues assigns the values that were returned from sql.Rows (after scanning)
// to the UserRole fields.
func (ur *UserRole) assignValues(columns []string, values []any) error {
	if m, n := len(values), len(columns); m < n {
		return fmt.Errorf("mismatch number of scan values: %d != %d", m, n)
	}
	for i := range columns {
		switch columns[i] {
		case userrole.FieldID:
			if value, ok := values[i].(*xid.ID); !ok {
				return fmt.Errorf("unexpected type %T for field id", values[i])
			} else if value != nil {
				ur.ID = *value
			}
		case userrole.FieldCreatedAt:
			if value, ok := values[i].(*sql.NullTime); !ok {
				return fmt.Errorf("unexpected type %T for field created_at", values[i])
			} else if value.Valid {
				ur.CreatedAt = value.Time
			}
		case userrole.FieldUpdatedAt:
			if value, ok := values[i].(*sql.NullTime); !ok {
				return fmt.Errorf("unexpected type %T for field updated_at", values[i])
			} else if value.Valid {
				ur.UpdatedAt = value.Time
			}
		case userrole.FieldDeletedAt:
			if value, ok := values[i].(*sql.NullTime); !ok {
				return fmt.Errorf("unexpected type %T for field deleted_at", values[i])
			} else if value.Valid {
				ur.DeletedAt = value.Time
			}
		case userrole.FieldUserID:
			if value, ok := values[i].(*xid.ID); !ok {
				return fmt.Errorf("unexpected type %T for field user_id", values[i])
			} else if value != nil {
				ur.UserID = *value
			}
		case userrole.FieldRoleID:
			if value, ok := values[i].(*xid.ID); !ok {
				return fmt.Errorf("unexpected type %T for field role_id", values[i])
			} else if value != nil {
				ur.RoleID = *value
			}
		case userrole.FieldContextType:
			if value, ok := values[i].(*sql.NullString); !ok {
				return fmt.Errorf("unexpected type %T for field context_type", values[i])
			} else if value.Valid {
				ur.ContextType = model.ContextType(value.String)
			}
		case userrole.FieldContextID:
			if value, ok := values[i].(*xid.ID); !ok {
				return fmt.Errorf("unexpected type %T for field context_id", values[i])
			} else if value != nil {
				ur.ContextID = *value
			}
		case userrole.FieldAssignedBy:
			if value, ok := values[i].(*xid.ID); !ok {
				return fmt.Errorf("unexpected type %T for field assigned_by", values[i])
			} else if value != nil {
				ur.AssignedBy = *value
			}
		case userrole.FieldAssignedAt:
			if value, ok := values[i].(*sql.NullTime); !ok {
				return fmt.Errorf("unexpected type %T for field assigned_at", values[i])
			} else if value.Valid {
				ur.AssignedAt = value.Time
			}
		case userrole.FieldExpiresAt:
			if value, ok := values[i].(*sql.NullTime); !ok {
				return fmt.Errorf("unexpected type %T for field expires_at", values[i])
			} else if value.Valid {
				ur.ExpiresAt = new(time.Time)
				*ur.ExpiresAt = value.Time
			}
		case userrole.FieldActive:
			if value, ok := values[i].(*sql.NullBool); !ok {
				return fmt.Errorf("unexpected type %T for field active", values[i])
			} else if value.Valid {
				ur.Active = value.Bool
			}
		case userrole.FieldConditions:
			if value, ok := values[i].(*[]byte); !ok {
				return fmt.Errorf("unexpected type %T for field conditions", values[i])
			} else if value != nil && len(*value) > 0 {
				if err := json.Unmarshal(*value, &ur.Conditions); err != nil {
					return fmt.Errorf("unmarshal field conditions: %w", err)
				}
			}
		default:
			ur.selectValues.Set(columns[i], values[i])
		}
	}
	return nil
}

// Value returns the ent.Value that was dynamically selected and assigned to the UserRole.
// This includes values selected through modifiers, order, etc.
func (ur *UserRole) Value(name string) (ent.Value, error) {
	return ur.selectValues.Get(name)
}

// QueryUser queries the "user" edge of the UserRole entity.
func (ur *UserRole) QueryUser() *UserQuery {
	return NewUserRoleClient(ur.config).QueryUser(ur)
}

// QueryRole queries the "role" edge of the UserRole entity.
func (ur *UserRole) QueryRole() *RoleQuery {
	return NewUserRoleClient(ur.config).QueryRole(ur)
}

// QueryOrganizationContext queries the "organization_context" edge of the UserRole entity.
func (ur *UserRole) QueryOrganizationContext() *OrganizationQuery {
	return NewUserRoleClient(ur.config).QueryOrganizationContext(ur)
}

// QueryAssignedByUser queries the "assigned_by_user" edge of the UserRole entity.
func (ur *UserRole) QueryAssignedByUser() *UserQuery {
	return NewUserRoleClient(ur.config).QueryAssignedByUser(ur)
}

// Update returns a builder for updating this UserRole.
// Note that you need to call UserRole.Unwrap() before calling this method if this UserRole
// was returned from a transaction, and the transaction was committed or rolled back.
func (ur *UserRole) Update() *UserRoleUpdateOne {
	return NewUserRoleClient(ur.config).UpdateOne(ur)
}

// Unwrap unwraps the UserRole entity that was returned from a transaction after it was closed,
// so that all future queries will be executed through the driver which created the transaction.
func (ur *UserRole) Unwrap() *UserRole {
	_tx, ok := ur.config.driver.(*txDriver)
	if !ok {
		panic("ent: UserRole is not a transactional entity")
	}
	ur.config.driver = _tx.drv
	return ur
}

// String implements the fmt.Stringer.
func (ur *UserRole) String() string {
	var builder strings.Builder
	builder.WriteString("UserRole(")
	builder.WriteString(fmt.Sprintf("id=%v, ", ur.ID))
	builder.WriteString("created_at=")
	builder.WriteString(ur.CreatedAt.Format(time.ANSIC))
	builder.WriteString(", ")
	builder.WriteString("updated_at=")
	builder.WriteString(ur.UpdatedAt.Format(time.ANSIC))
	builder.WriteString(", ")
	builder.WriteString("deleted_at=")
	builder.WriteString(ur.DeletedAt.Format(time.ANSIC))
	builder.WriteString(", ")
	builder.WriteString("user_id=")
	builder.WriteString(fmt.Sprintf("%v", ur.UserID))
	builder.WriteString(", ")
	builder.WriteString("role_id=")
	builder.WriteString(fmt.Sprintf("%v", ur.RoleID))
	builder.WriteString(", ")
	builder.WriteString("context_type=")
	builder.WriteString(fmt.Sprintf("%v", ur.ContextType))
	builder.WriteString(", ")
	builder.WriteString("context_id=")
	builder.WriteString(fmt.Sprintf("%v", ur.ContextID))
	builder.WriteString(", ")
	builder.WriteString("assigned_by=")
	builder.WriteString(fmt.Sprintf("%v", ur.AssignedBy))
	builder.WriteString(", ")
	builder.WriteString("assigned_at=")
	builder.WriteString(ur.AssignedAt.Format(time.ANSIC))
	builder.WriteString(", ")
	if v := ur.ExpiresAt; v != nil {
		builder.WriteString("expires_at=")
		builder.WriteString(v.Format(time.ANSIC))
	}
	builder.WriteString(", ")
	builder.WriteString("active=")
	builder.WriteString(fmt.Sprintf("%v", ur.Active))
	builder.WriteString(", ")
	builder.WriteString("conditions=")
	builder.WriteString(fmt.Sprintf("%v", ur.Conditions))
	builder.WriteByte(')')
	return builder.String()
}

// UserRoles is a parsable slice of UserRole.
type UserRoles []*UserRole
