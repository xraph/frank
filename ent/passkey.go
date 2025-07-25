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
	"github.com/xraph/frank/ent/passkey"
	"github.com/xraph/frank/ent/user"
	"github.com/rs/xid"
)

// Passkey is the model entity for the Passkey schema.
type Passkey struct {
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
	// Name holds the value of the "name" field.
	Name string `json:"name,omitempty"`
	// CredentialID holds the value of the "credential_id" field.
	CredentialID string `json:"credential_id,omitempty"`
	// PublicKey holds the value of the "public_key" field.
	PublicKey []byte `json:"public_key,omitempty"`
	// SignCount holds the value of the "sign_count" field.
	SignCount int `json:"sign_count,omitempty"`
	// Active holds the value of the "active" field.
	Active bool `json:"active,omitempty"`
	// DeviceType holds the value of the "device_type" field.
	DeviceType string `json:"device_type,omitempty"`
	// Aaguid holds the value of the "aaguid" field.
	Aaguid string `json:"aaguid,omitempty"`
	// LastUsed holds the value of the "last_used" field.
	LastUsed *time.Time `json:"last_used,omitempty"`
	// Transports holds the value of the "transports" field.
	Transports []string `json:"transports,omitempty"`
	// Additional membership metadata
	Attestation map[string]interface{} `json:"attestation,omitempty"`
	// BackupState holds the value of the "backup_state" field.
	BackupState bool `json:"backup_state,omitempty"`
	// BackupEligible holds the value of the "backup_eligible" field.
	BackupEligible bool `json:"backup_eligible,omitempty"`
	// UserAgent holds the value of the "user_agent" field.
	UserAgent string `json:"user_agent,omitempty"`
	// IPAddress holds the value of the "ip_address" field.
	IPAddress string `json:"ip_address,omitempty"`
	// Edges holds the relations/edges for other nodes in the graph.
	// The values are being populated by the PasskeyQuery when eager-loading is set.
	Edges        PasskeyEdges `json:"edges"`
	selectValues sql.SelectValues
}

// PasskeyEdges holds the relations/edges for other nodes in the graph.
type PasskeyEdges struct {
	// User holds the value of the user edge.
	User *User `json:"user,omitempty"`
	// loadedTypes holds the information for reporting if a
	// type was loaded (or requested) in eager-loading or not.
	loadedTypes [1]bool
}

// UserOrErr returns the User value or an error if the edge
// was not loaded in eager-loading, or loaded but was not found.
func (e PasskeyEdges) UserOrErr() (*User, error) {
	if e.User != nil {
		return e.User, nil
	} else if e.loadedTypes[0] {
		return nil, &NotFoundError{label: user.Label}
	}
	return nil, &NotLoadedError{edge: "user"}
}

// scanValues returns the types for scanning values from sql.Rows.
func (*Passkey) scanValues(columns []string) ([]any, error) {
	values := make([]any, len(columns))
	for i := range columns {
		switch columns[i] {
		case passkey.FieldPublicKey, passkey.FieldTransports, passkey.FieldAttestation:
			values[i] = new([]byte)
		case passkey.FieldActive, passkey.FieldBackupState, passkey.FieldBackupEligible:
			values[i] = new(sql.NullBool)
		case passkey.FieldSignCount:
			values[i] = new(sql.NullInt64)
		case passkey.FieldName, passkey.FieldCredentialID, passkey.FieldDeviceType, passkey.FieldAaguid, passkey.FieldUserAgent, passkey.FieldIPAddress:
			values[i] = new(sql.NullString)
		case passkey.FieldCreatedAt, passkey.FieldUpdatedAt, passkey.FieldDeletedAt, passkey.FieldLastUsed:
			values[i] = new(sql.NullTime)
		case passkey.FieldID, passkey.FieldUserID:
			values[i] = new(xid.ID)
		default:
			values[i] = new(sql.UnknownType)
		}
	}
	return values, nil
}

// assignValues assigns the values that were returned from sql.Rows (after scanning)
// to the Passkey fields.
func (pa *Passkey) assignValues(columns []string, values []any) error {
	if m, n := len(values), len(columns); m < n {
		return fmt.Errorf("mismatch number of scan values: %d != %d", m, n)
	}
	for i := range columns {
		switch columns[i] {
		case passkey.FieldID:
			if value, ok := values[i].(*xid.ID); !ok {
				return fmt.Errorf("unexpected type %T for field id", values[i])
			} else if value != nil {
				pa.ID = *value
			}
		case passkey.FieldCreatedAt:
			if value, ok := values[i].(*sql.NullTime); !ok {
				return fmt.Errorf("unexpected type %T for field created_at", values[i])
			} else if value.Valid {
				pa.CreatedAt = value.Time
			}
		case passkey.FieldUpdatedAt:
			if value, ok := values[i].(*sql.NullTime); !ok {
				return fmt.Errorf("unexpected type %T for field updated_at", values[i])
			} else if value.Valid {
				pa.UpdatedAt = value.Time
			}
		case passkey.FieldDeletedAt:
			if value, ok := values[i].(*sql.NullTime); !ok {
				return fmt.Errorf("unexpected type %T for field deleted_at", values[i])
			} else if value.Valid {
				pa.DeletedAt = value.Time
			}
		case passkey.FieldUserID:
			if value, ok := values[i].(*xid.ID); !ok {
				return fmt.Errorf("unexpected type %T for field user_id", values[i])
			} else if value != nil {
				pa.UserID = *value
			}
		case passkey.FieldName:
			if value, ok := values[i].(*sql.NullString); !ok {
				return fmt.Errorf("unexpected type %T for field name", values[i])
			} else if value.Valid {
				pa.Name = value.String
			}
		case passkey.FieldCredentialID:
			if value, ok := values[i].(*sql.NullString); !ok {
				return fmt.Errorf("unexpected type %T for field credential_id", values[i])
			} else if value.Valid {
				pa.CredentialID = value.String
			}
		case passkey.FieldPublicKey:
			if value, ok := values[i].(*[]byte); !ok {
				return fmt.Errorf("unexpected type %T for field public_key", values[i])
			} else if value != nil {
				pa.PublicKey = *value
			}
		case passkey.FieldSignCount:
			if value, ok := values[i].(*sql.NullInt64); !ok {
				return fmt.Errorf("unexpected type %T for field sign_count", values[i])
			} else if value.Valid {
				pa.SignCount = int(value.Int64)
			}
		case passkey.FieldActive:
			if value, ok := values[i].(*sql.NullBool); !ok {
				return fmt.Errorf("unexpected type %T for field active", values[i])
			} else if value.Valid {
				pa.Active = value.Bool
			}
		case passkey.FieldDeviceType:
			if value, ok := values[i].(*sql.NullString); !ok {
				return fmt.Errorf("unexpected type %T for field device_type", values[i])
			} else if value.Valid {
				pa.DeviceType = value.String
			}
		case passkey.FieldAaguid:
			if value, ok := values[i].(*sql.NullString); !ok {
				return fmt.Errorf("unexpected type %T for field aaguid", values[i])
			} else if value.Valid {
				pa.Aaguid = value.String
			}
		case passkey.FieldLastUsed:
			if value, ok := values[i].(*sql.NullTime); !ok {
				return fmt.Errorf("unexpected type %T for field last_used", values[i])
			} else if value.Valid {
				pa.LastUsed = new(time.Time)
				*pa.LastUsed = value.Time
			}
		case passkey.FieldTransports:
			if value, ok := values[i].(*[]byte); !ok {
				return fmt.Errorf("unexpected type %T for field transports", values[i])
			} else if value != nil && len(*value) > 0 {
				if err := json.Unmarshal(*value, &pa.Transports); err != nil {
					return fmt.Errorf("unmarshal field transports: %w", err)
				}
			}
		case passkey.FieldAttestation:
			if value, ok := values[i].(*[]byte); !ok {
				return fmt.Errorf("unexpected type %T for field attestation", values[i])
			} else if value != nil && len(*value) > 0 {
				if err := json.Unmarshal(*value, &pa.Attestation); err != nil {
					return fmt.Errorf("unmarshal field attestation: %w", err)
				}
			}
		case passkey.FieldBackupState:
			if value, ok := values[i].(*sql.NullBool); !ok {
				return fmt.Errorf("unexpected type %T for field backup_state", values[i])
			} else if value.Valid {
				pa.BackupState = value.Bool
			}
		case passkey.FieldBackupEligible:
			if value, ok := values[i].(*sql.NullBool); !ok {
				return fmt.Errorf("unexpected type %T for field backup_eligible", values[i])
			} else if value.Valid {
				pa.BackupEligible = value.Bool
			}
		case passkey.FieldUserAgent:
			if value, ok := values[i].(*sql.NullString); !ok {
				return fmt.Errorf("unexpected type %T for field user_agent", values[i])
			} else if value.Valid {
				pa.UserAgent = value.String
			}
		case passkey.FieldIPAddress:
			if value, ok := values[i].(*sql.NullString); !ok {
				return fmt.Errorf("unexpected type %T for field ip_address", values[i])
			} else if value.Valid {
				pa.IPAddress = value.String
			}
		default:
			pa.selectValues.Set(columns[i], values[i])
		}
	}
	return nil
}

// Value returns the ent.Value that was dynamically selected and assigned to the Passkey.
// This includes values selected through modifiers, order, etc.
func (pa *Passkey) Value(name string) (ent.Value, error) {
	return pa.selectValues.Get(name)
}

// QueryUser queries the "user" edge of the Passkey entity.
func (pa *Passkey) QueryUser() *UserQuery {
	return NewPasskeyClient(pa.config).QueryUser(pa)
}

// Update returns a builder for updating this Passkey.
// Note that you need to call Passkey.Unwrap() before calling this method if this Passkey
// was returned from a transaction, and the transaction was committed or rolled back.
func (pa *Passkey) Update() *PasskeyUpdateOne {
	return NewPasskeyClient(pa.config).UpdateOne(pa)
}

// Unwrap unwraps the Passkey entity that was returned from a transaction after it was closed,
// so that all future queries will be executed through the driver which created the transaction.
func (pa *Passkey) Unwrap() *Passkey {
	_tx, ok := pa.config.driver.(*txDriver)
	if !ok {
		panic("ent: Passkey is not a transactional entity")
	}
	pa.config.driver = _tx.drv
	return pa
}

// String implements the fmt.Stringer.
func (pa *Passkey) String() string {
	var builder strings.Builder
	builder.WriteString("Passkey(")
	builder.WriteString(fmt.Sprintf("id=%v, ", pa.ID))
	builder.WriteString("created_at=")
	builder.WriteString(pa.CreatedAt.Format(time.ANSIC))
	builder.WriteString(", ")
	builder.WriteString("updated_at=")
	builder.WriteString(pa.UpdatedAt.Format(time.ANSIC))
	builder.WriteString(", ")
	builder.WriteString("deleted_at=")
	builder.WriteString(pa.DeletedAt.Format(time.ANSIC))
	builder.WriteString(", ")
	builder.WriteString("user_id=")
	builder.WriteString(fmt.Sprintf("%v", pa.UserID))
	builder.WriteString(", ")
	builder.WriteString("name=")
	builder.WriteString(pa.Name)
	builder.WriteString(", ")
	builder.WriteString("credential_id=")
	builder.WriteString(pa.CredentialID)
	builder.WriteString(", ")
	builder.WriteString("public_key=")
	builder.WriteString(fmt.Sprintf("%v", pa.PublicKey))
	builder.WriteString(", ")
	builder.WriteString("sign_count=")
	builder.WriteString(fmt.Sprintf("%v", pa.SignCount))
	builder.WriteString(", ")
	builder.WriteString("active=")
	builder.WriteString(fmt.Sprintf("%v", pa.Active))
	builder.WriteString(", ")
	builder.WriteString("device_type=")
	builder.WriteString(pa.DeviceType)
	builder.WriteString(", ")
	builder.WriteString("aaguid=")
	builder.WriteString(pa.Aaguid)
	builder.WriteString(", ")
	if v := pa.LastUsed; v != nil {
		builder.WriteString("last_used=")
		builder.WriteString(v.Format(time.ANSIC))
	}
	builder.WriteString(", ")
	builder.WriteString("transports=")
	builder.WriteString(fmt.Sprintf("%v", pa.Transports))
	builder.WriteString(", ")
	builder.WriteString("attestation=")
	builder.WriteString(fmt.Sprintf("%v", pa.Attestation))
	builder.WriteString(", ")
	builder.WriteString("backup_state=")
	builder.WriteString(fmt.Sprintf("%v", pa.BackupState))
	builder.WriteString(", ")
	builder.WriteString("backup_eligible=")
	builder.WriteString(fmt.Sprintf("%v", pa.BackupEligible))
	builder.WriteString(", ")
	builder.WriteString("user_agent=")
	builder.WriteString(pa.UserAgent)
	builder.WriteString(", ")
	builder.WriteString("ip_address=")
	builder.WriteString(pa.IPAddress)
	builder.WriteByte(')')
	return builder.String()
}

// Passkeys is a parsable slice of Passkey.
type Passkeys []*Passkey
