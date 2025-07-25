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
	"github.com/xraph/frank/ent/membership"
	"github.com/xraph/frank/ent/organization"
	"github.com/xraph/frank/ent/role"
	"github.com/xraph/frank/ent/user"
	"github.com/xraph/frank/pkg/model"
	"github.com/rs/xid"
)

// Membership is the model entity for the Membership schema.
type Membership struct {
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
	// OrganizationID holds the value of the "organization_id" field.
	OrganizationID xid.ID `json:"organization_id,omitempty"`
	// RoleID holds the value of the "role_id" field.
	RoleID xid.ID `json:"role_id,omitempty"`
	// Email holds the value of the "email" field.
	Email string `json:"email,omitempty"`
	// Status holds the value of the "status" field.
	Status model.MembershipStatus `json:"status,omitempty"`
	// User ID who sent the invitation
	InvitedBy xid.ID `json:"invited_by,omitempty"`
	// InvitedAt holds the value of the "invited_at" field.
	InvitedAt time.Time `json:"invited_at,omitempty"`
	// When the user accepted the invitation
	JoinedAt *time.Time `json:"joined_at,omitempty"`
	// When the invitation expires
	ExpiresAt *time.Time `json:"expires_at,omitempty"`
	// Token for accepting invitations
	InvitationToken string `json:"-"`
	// Whether this member receives billing notifications
	IsBillingContact bool `json:"is_billing_contact,omitempty"`
	// Primary contact for the organization
	IsPrimaryContact bool `json:"is_primary_contact,omitempty"`
	// Datetime when the invitation left
	LeftAt *time.Time `json:"left_at,omitempty"`
	// Additional membership metadata
	Metadata map[string]interface{} `json:"metadata,omitempty"`
	// Additional membership metadata
	CustomFields map[string]interface{} `json:"custom_fields,omitempty"`
	// Edges holds the relations/edges for other nodes in the graph.
	// The values are being populated by the MembershipQuery when eager-loading is set.
	Edges        MembershipEdges `json:"edges"`
	selectValues sql.SelectValues
}

// MembershipEdges holds the relations/edges for other nodes in the graph.
type MembershipEdges struct {
	// User holds the value of the user edge.
	User *User `json:"user,omitempty"`
	// Organization holds the value of the organization edge.
	Organization *Organization `json:"organization,omitempty"`
	// Role holds the value of the role edge.
	Role *Role `json:"role,omitempty"`
	// Inviter holds the value of the inviter edge.
	Inviter *User `json:"inviter,omitempty"`
	// loadedTypes holds the information for reporting if a
	// type was loaded (or requested) in eager-loading or not.
	loadedTypes [4]bool
}

// UserOrErr returns the User value or an error if the edge
// was not loaded in eager-loading, or loaded but was not found.
func (e MembershipEdges) UserOrErr() (*User, error) {
	if e.User != nil {
		return e.User, nil
	} else if e.loadedTypes[0] {
		return nil, &NotFoundError{label: user.Label}
	}
	return nil, &NotLoadedError{edge: "user"}
}

// OrganizationOrErr returns the Organization value or an error if the edge
// was not loaded in eager-loading, or loaded but was not found.
func (e MembershipEdges) OrganizationOrErr() (*Organization, error) {
	if e.Organization != nil {
		return e.Organization, nil
	} else if e.loadedTypes[1] {
		return nil, &NotFoundError{label: organization.Label}
	}
	return nil, &NotLoadedError{edge: "organization"}
}

// RoleOrErr returns the Role value or an error if the edge
// was not loaded in eager-loading, or loaded but was not found.
func (e MembershipEdges) RoleOrErr() (*Role, error) {
	if e.Role != nil {
		return e.Role, nil
	} else if e.loadedTypes[2] {
		return nil, &NotFoundError{label: role.Label}
	}
	return nil, &NotLoadedError{edge: "role"}
}

// InviterOrErr returns the Inviter value or an error if the edge
// was not loaded in eager-loading, or loaded but was not found.
func (e MembershipEdges) InviterOrErr() (*User, error) {
	if e.Inviter != nil {
		return e.Inviter, nil
	} else if e.loadedTypes[3] {
		return nil, &NotFoundError{label: user.Label}
	}
	return nil, &NotLoadedError{edge: "inviter"}
}

// scanValues returns the types for scanning values from sql.Rows.
func (*Membership) scanValues(columns []string) ([]any, error) {
	values := make([]any, len(columns))
	for i := range columns {
		switch columns[i] {
		case membership.FieldMetadata, membership.FieldCustomFields:
			values[i] = new([]byte)
		case membership.FieldIsBillingContact, membership.FieldIsPrimaryContact:
			values[i] = new(sql.NullBool)
		case membership.FieldEmail, membership.FieldStatus, membership.FieldInvitationToken:
			values[i] = new(sql.NullString)
		case membership.FieldCreatedAt, membership.FieldUpdatedAt, membership.FieldDeletedAt, membership.FieldInvitedAt, membership.FieldJoinedAt, membership.FieldExpiresAt, membership.FieldLeftAt:
			values[i] = new(sql.NullTime)
		case membership.FieldID, membership.FieldUserID, membership.FieldOrganizationID, membership.FieldRoleID, membership.FieldInvitedBy:
			values[i] = new(xid.ID)
		default:
			values[i] = new(sql.UnknownType)
		}
	}
	return values, nil
}

// assignValues assigns the values that were returned from sql.Rows (after scanning)
// to the Membership fields.
func (m *Membership) assignValues(columns []string, values []any) error {
	if m, n := len(values), len(columns); m < n {
		return fmt.Errorf("mismatch number of scan values: %d != %d", m, n)
	}
	for i := range columns {
		switch columns[i] {
		case membership.FieldID:
			if value, ok := values[i].(*xid.ID); !ok {
				return fmt.Errorf("unexpected type %T for field id", values[i])
			} else if value != nil {
				m.ID = *value
			}
		case membership.FieldCreatedAt:
			if value, ok := values[i].(*sql.NullTime); !ok {
				return fmt.Errorf("unexpected type %T for field created_at", values[i])
			} else if value.Valid {
				m.CreatedAt = value.Time
			}
		case membership.FieldUpdatedAt:
			if value, ok := values[i].(*sql.NullTime); !ok {
				return fmt.Errorf("unexpected type %T for field updated_at", values[i])
			} else if value.Valid {
				m.UpdatedAt = value.Time
			}
		case membership.FieldDeletedAt:
			if value, ok := values[i].(*sql.NullTime); !ok {
				return fmt.Errorf("unexpected type %T for field deleted_at", values[i])
			} else if value.Valid {
				m.DeletedAt = value.Time
			}
		case membership.FieldUserID:
			if value, ok := values[i].(*xid.ID); !ok {
				return fmt.Errorf("unexpected type %T for field user_id", values[i])
			} else if value != nil {
				m.UserID = *value
			}
		case membership.FieldOrganizationID:
			if value, ok := values[i].(*xid.ID); !ok {
				return fmt.Errorf("unexpected type %T for field organization_id", values[i])
			} else if value != nil {
				m.OrganizationID = *value
			}
		case membership.FieldRoleID:
			if value, ok := values[i].(*xid.ID); !ok {
				return fmt.Errorf("unexpected type %T for field role_id", values[i])
			} else if value != nil {
				m.RoleID = *value
			}
		case membership.FieldEmail:
			if value, ok := values[i].(*sql.NullString); !ok {
				return fmt.Errorf("unexpected type %T for field email", values[i])
			} else if value.Valid {
				m.Email = value.String
			}
		case membership.FieldStatus:
			if value, ok := values[i].(*sql.NullString); !ok {
				return fmt.Errorf("unexpected type %T for field status", values[i])
			} else if value.Valid {
				m.Status = model.MembershipStatus(value.String)
			}
		case membership.FieldInvitedBy:
			if value, ok := values[i].(*xid.ID); !ok {
				return fmt.Errorf("unexpected type %T for field invited_by", values[i])
			} else if value != nil {
				m.InvitedBy = *value
			}
		case membership.FieldInvitedAt:
			if value, ok := values[i].(*sql.NullTime); !ok {
				return fmt.Errorf("unexpected type %T for field invited_at", values[i])
			} else if value.Valid {
				m.InvitedAt = value.Time
			}
		case membership.FieldJoinedAt:
			if value, ok := values[i].(*sql.NullTime); !ok {
				return fmt.Errorf("unexpected type %T for field joined_at", values[i])
			} else if value.Valid {
				m.JoinedAt = new(time.Time)
				*m.JoinedAt = value.Time
			}
		case membership.FieldExpiresAt:
			if value, ok := values[i].(*sql.NullTime); !ok {
				return fmt.Errorf("unexpected type %T for field expires_at", values[i])
			} else if value.Valid {
				m.ExpiresAt = new(time.Time)
				*m.ExpiresAt = value.Time
			}
		case membership.FieldInvitationToken:
			if value, ok := values[i].(*sql.NullString); !ok {
				return fmt.Errorf("unexpected type %T for field invitation_token", values[i])
			} else if value.Valid {
				m.InvitationToken = value.String
			}
		case membership.FieldIsBillingContact:
			if value, ok := values[i].(*sql.NullBool); !ok {
				return fmt.Errorf("unexpected type %T for field is_billing_contact", values[i])
			} else if value.Valid {
				m.IsBillingContact = value.Bool
			}
		case membership.FieldIsPrimaryContact:
			if value, ok := values[i].(*sql.NullBool); !ok {
				return fmt.Errorf("unexpected type %T for field is_primary_contact", values[i])
			} else if value.Valid {
				m.IsPrimaryContact = value.Bool
			}
		case membership.FieldLeftAt:
			if value, ok := values[i].(*sql.NullTime); !ok {
				return fmt.Errorf("unexpected type %T for field left_at", values[i])
			} else if value.Valid {
				m.LeftAt = new(time.Time)
				*m.LeftAt = value.Time
			}
		case membership.FieldMetadata:
			if value, ok := values[i].(*[]byte); !ok {
				return fmt.Errorf("unexpected type %T for field metadata", values[i])
			} else if value != nil && len(*value) > 0 {
				if err := json.Unmarshal(*value, &m.Metadata); err != nil {
					return fmt.Errorf("unmarshal field metadata: %w", err)
				}
			}
		case membership.FieldCustomFields:
			if value, ok := values[i].(*[]byte); !ok {
				return fmt.Errorf("unexpected type %T for field custom_fields", values[i])
			} else if value != nil && len(*value) > 0 {
				if err := json.Unmarshal(*value, &m.CustomFields); err != nil {
					return fmt.Errorf("unmarshal field custom_fields: %w", err)
				}
			}
		default:
			m.selectValues.Set(columns[i], values[i])
		}
	}
	return nil
}

// Value returns the ent.Value that was dynamically selected and assigned to the Membership.
// This includes values selected through modifiers, order, etc.
func (m *Membership) Value(name string) (ent.Value, error) {
	return m.selectValues.Get(name)
}

// QueryUser queries the "user" edge of the Membership entity.
func (m *Membership) QueryUser() *UserQuery {
	return NewMembershipClient(m.config).QueryUser(m)
}

// QueryOrganization queries the "organization" edge of the Membership entity.
func (m *Membership) QueryOrganization() *OrganizationQuery {
	return NewMembershipClient(m.config).QueryOrganization(m)
}

// QueryRole queries the "role" edge of the Membership entity.
func (m *Membership) QueryRole() *RoleQuery {
	return NewMembershipClient(m.config).QueryRole(m)
}

// QueryInviter queries the "inviter" edge of the Membership entity.
func (m *Membership) QueryInviter() *UserQuery {
	return NewMembershipClient(m.config).QueryInviter(m)
}

// Update returns a builder for updating this Membership.
// Note that you need to call Membership.Unwrap() before calling this method if this Membership
// was returned from a transaction, and the transaction was committed or rolled back.
func (m *Membership) Update() *MembershipUpdateOne {
	return NewMembershipClient(m.config).UpdateOne(m)
}

// Unwrap unwraps the Membership entity that was returned from a transaction after it was closed,
// so that all future queries will be executed through the driver which created the transaction.
func (m *Membership) Unwrap() *Membership {
	_tx, ok := m.config.driver.(*txDriver)
	if !ok {
		panic("ent: Membership is not a transactional entity")
	}
	m.config.driver = _tx.drv
	return m
}

// String implements the fmt.Stringer.
func (m *Membership) String() string {
	var builder strings.Builder
	builder.WriteString("Membership(")
	builder.WriteString(fmt.Sprintf("id=%v, ", m.ID))
	builder.WriteString("created_at=")
	builder.WriteString(m.CreatedAt.Format(time.ANSIC))
	builder.WriteString(", ")
	builder.WriteString("updated_at=")
	builder.WriteString(m.UpdatedAt.Format(time.ANSIC))
	builder.WriteString(", ")
	builder.WriteString("deleted_at=")
	builder.WriteString(m.DeletedAt.Format(time.ANSIC))
	builder.WriteString(", ")
	builder.WriteString("user_id=")
	builder.WriteString(fmt.Sprintf("%v", m.UserID))
	builder.WriteString(", ")
	builder.WriteString("organization_id=")
	builder.WriteString(fmt.Sprintf("%v", m.OrganizationID))
	builder.WriteString(", ")
	builder.WriteString("role_id=")
	builder.WriteString(fmt.Sprintf("%v", m.RoleID))
	builder.WriteString(", ")
	builder.WriteString("email=")
	builder.WriteString(m.Email)
	builder.WriteString(", ")
	builder.WriteString("status=")
	builder.WriteString(fmt.Sprintf("%v", m.Status))
	builder.WriteString(", ")
	builder.WriteString("invited_by=")
	builder.WriteString(fmt.Sprintf("%v", m.InvitedBy))
	builder.WriteString(", ")
	builder.WriteString("invited_at=")
	builder.WriteString(m.InvitedAt.Format(time.ANSIC))
	builder.WriteString(", ")
	if v := m.JoinedAt; v != nil {
		builder.WriteString("joined_at=")
		builder.WriteString(v.Format(time.ANSIC))
	}
	builder.WriteString(", ")
	if v := m.ExpiresAt; v != nil {
		builder.WriteString("expires_at=")
		builder.WriteString(v.Format(time.ANSIC))
	}
	builder.WriteString(", ")
	builder.WriteString("invitation_token=<sensitive>")
	builder.WriteString(", ")
	builder.WriteString("is_billing_contact=")
	builder.WriteString(fmt.Sprintf("%v", m.IsBillingContact))
	builder.WriteString(", ")
	builder.WriteString("is_primary_contact=")
	builder.WriteString(fmt.Sprintf("%v", m.IsPrimaryContact))
	builder.WriteString(", ")
	if v := m.LeftAt; v != nil {
		builder.WriteString("left_at=")
		builder.WriteString(v.Format(time.ANSIC))
	}
	builder.WriteString(", ")
	builder.WriteString("metadata=")
	builder.WriteString(fmt.Sprintf("%v", m.Metadata))
	builder.WriteString(", ")
	builder.WriteString("custom_fields=")
	builder.WriteString(fmt.Sprintf("%v", m.CustomFields))
	builder.WriteByte(')')
	return builder.String()
}

// Memberships is a parsable slice of Membership.
type Memberships []*Membership
