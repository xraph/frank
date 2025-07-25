// Copyright 2023-present XRaph LLC. All rights reserved.
// This source code is licensed under the XRaph LLC license found
// in the LICENSE file in the root directory of this source tree.
// Code generated by ent, DO NOT EDIT.

package ent

import (
	"context"
	"errors"
	"fmt"
	"time"

	"entgo.io/ent/dialect/sql"
	"entgo.io/ent/dialect/sql/sqlgraph"
	"entgo.io/ent/dialect/sql/sqljson"
	"entgo.io/ent/schema/field"
	"github.com/xraph/frank/ent/passkey"
	"github.com/xraph/frank/ent/predicate"
	"github.com/xraph/frank/ent/user"
	"github.com/rs/xid"
)

// PasskeyUpdate is the builder for updating Passkey entities.
type PasskeyUpdate struct {
	config
	hooks     []Hook
	mutation  *PasskeyMutation
	modifiers []func(*sql.UpdateBuilder)
}

// Where appends a list predicates to the PasskeyUpdate builder.
func (pu *PasskeyUpdate) Where(ps ...predicate.Passkey) *PasskeyUpdate {
	pu.mutation.Where(ps...)
	return pu
}

// SetUpdatedAt sets the "updated_at" field.
func (pu *PasskeyUpdate) SetUpdatedAt(t time.Time) *PasskeyUpdate {
	pu.mutation.SetUpdatedAt(t)
	return pu
}

// SetDeletedAt sets the "deleted_at" field.
func (pu *PasskeyUpdate) SetDeletedAt(t time.Time) *PasskeyUpdate {
	pu.mutation.SetDeletedAt(t)
	return pu
}

// SetNillableDeletedAt sets the "deleted_at" field if the given value is not nil.
func (pu *PasskeyUpdate) SetNillableDeletedAt(t *time.Time) *PasskeyUpdate {
	if t != nil {
		pu.SetDeletedAt(*t)
	}
	return pu
}

// ClearDeletedAt clears the value of the "deleted_at" field.
func (pu *PasskeyUpdate) ClearDeletedAt() *PasskeyUpdate {
	pu.mutation.ClearDeletedAt()
	return pu
}

// SetUserID sets the "user_id" field.
func (pu *PasskeyUpdate) SetUserID(x xid.ID) *PasskeyUpdate {
	pu.mutation.SetUserID(x)
	return pu
}

// SetNillableUserID sets the "user_id" field if the given value is not nil.
func (pu *PasskeyUpdate) SetNillableUserID(x *xid.ID) *PasskeyUpdate {
	if x != nil {
		pu.SetUserID(*x)
	}
	return pu
}

// SetName sets the "name" field.
func (pu *PasskeyUpdate) SetName(s string) *PasskeyUpdate {
	pu.mutation.SetName(s)
	return pu
}

// SetNillableName sets the "name" field if the given value is not nil.
func (pu *PasskeyUpdate) SetNillableName(s *string) *PasskeyUpdate {
	if s != nil {
		pu.SetName(*s)
	}
	return pu
}

// SetCredentialID sets the "credential_id" field.
func (pu *PasskeyUpdate) SetCredentialID(s string) *PasskeyUpdate {
	pu.mutation.SetCredentialID(s)
	return pu
}

// SetNillableCredentialID sets the "credential_id" field if the given value is not nil.
func (pu *PasskeyUpdate) SetNillableCredentialID(s *string) *PasskeyUpdate {
	if s != nil {
		pu.SetCredentialID(*s)
	}
	return pu
}

// SetPublicKey sets the "public_key" field.
func (pu *PasskeyUpdate) SetPublicKey(b []byte) *PasskeyUpdate {
	pu.mutation.SetPublicKey(b)
	return pu
}

// SetSignCount sets the "sign_count" field.
func (pu *PasskeyUpdate) SetSignCount(i int) *PasskeyUpdate {
	pu.mutation.ResetSignCount()
	pu.mutation.SetSignCount(i)
	return pu
}

// SetNillableSignCount sets the "sign_count" field if the given value is not nil.
func (pu *PasskeyUpdate) SetNillableSignCount(i *int) *PasskeyUpdate {
	if i != nil {
		pu.SetSignCount(*i)
	}
	return pu
}

// AddSignCount adds i to the "sign_count" field.
func (pu *PasskeyUpdate) AddSignCount(i int) *PasskeyUpdate {
	pu.mutation.AddSignCount(i)
	return pu
}

// SetActive sets the "active" field.
func (pu *PasskeyUpdate) SetActive(b bool) *PasskeyUpdate {
	pu.mutation.SetActive(b)
	return pu
}

// SetNillableActive sets the "active" field if the given value is not nil.
func (pu *PasskeyUpdate) SetNillableActive(b *bool) *PasskeyUpdate {
	if b != nil {
		pu.SetActive(*b)
	}
	return pu
}

// SetDeviceType sets the "device_type" field.
func (pu *PasskeyUpdate) SetDeviceType(s string) *PasskeyUpdate {
	pu.mutation.SetDeviceType(s)
	return pu
}

// SetNillableDeviceType sets the "device_type" field if the given value is not nil.
func (pu *PasskeyUpdate) SetNillableDeviceType(s *string) *PasskeyUpdate {
	if s != nil {
		pu.SetDeviceType(*s)
	}
	return pu
}

// ClearDeviceType clears the value of the "device_type" field.
func (pu *PasskeyUpdate) ClearDeviceType() *PasskeyUpdate {
	pu.mutation.ClearDeviceType()
	return pu
}

// SetAaguid sets the "aaguid" field.
func (pu *PasskeyUpdate) SetAaguid(s string) *PasskeyUpdate {
	pu.mutation.SetAaguid(s)
	return pu
}

// SetNillableAaguid sets the "aaguid" field if the given value is not nil.
func (pu *PasskeyUpdate) SetNillableAaguid(s *string) *PasskeyUpdate {
	if s != nil {
		pu.SetAaguid(*s)
	}
	return pu
}

// ClearAaguid clears the value of the "aaguid" field.
func (pu *PasskeyUpdate) ClearAaguid() *PasskeyUpdate {
	pu.mutation.ClearAaguid()
	return pu
}

// SetLastUsed sets the "last_used" field.
func (pu *PasskeyUpdate) SetLastUsed(t time.Time) *PasskeyUpdate {
	pu.mutation.SetLastUsed(t)
	return pu
}

// SetNillableLastUsed sets the "last_used" field if the given value is not nil.
func (pu *PasskeyUpdate) SetNillableLastUsed(t *time.Time) *PasskeyUpdate {
	if t != nil {
		pu.SetLastUsed(*t)
	}
	return pu
}

// ClearLastUsed clears the value of the "last_used" field.
func (pu *PasskeyUpdate) ClearLastUsed() *PasskeyUpdate {
	pu.mutation.ClearLastUsed()
	return pu
}

// SetTransports sets the "transports" field.
func (pu *PasskeyUpdate) SetTransports(s []string) *PasskeyUpdate {
	pu.mutation.SetTransports(s)
	return pu
}

// AppendTransports appends s to the "transports" field.
func (pu *PasskeyUpdate) AppendTransports(s []string) *PasskeyUpdate {
	pu.mutation.AppendTransports(s)
	return pu
}

// ClearTransports clears the value of the "transports" field.
func (pu *PasskeyUpdate) ClearTransports() *PasskeyUpdate {
	pu.mutation.ClearTransports()
	return pu
}

// SetAttestation sets the "attestation" field.
func (pu *PasskeyUpdate) SetAttestation(m map[string]interface{}) *PasskeyUpdate {
	pu.mutation.SetAttestation(m)
	return pu
}

// ClearAttestation clears the value of the "attestation" field.
func (pu *PasskeyUpdate) ClearAttestation() *PasskeyUpdate {
	pu.mutation.ClearAttestation()
	return pu
}

// SetBackupState sets the "backup_state" field.
func (pu *PasskeyUpdate) SetBackupState(b bool) *PasskeyUpdate {
	pu.mutation.SetBackupState(b)
	return pu
}

// SetNillableBackupState sets the "backup_state" field if the given value is not nil.
func (pu *PasskeyUpdate) SetNillableBackupState(b *bool) *PasskeyUpdate {
	if b != nil {
		pu.SetBackupState(*b)
	}
	return pu
}

// ClearBackupState clears the value of the "backup_state" field.
func (pu *PasskeyUpdate) ClearBackupState() *PasskeyUpdate {
	pu.mutation.ClearBackupState()
	return pu
}

// SetBackupEligible sets the "backup_eligible" field.
func (pu *PasskeyUpdate) SetBackupEligible(b bool) *PasskeyUpdate {
	pu.mutation.SetBackupEligible(b)
	return pu
}

// SetNillableBackupEligible sets the "backup_eligible" field if the given value is not nil.
func (pu *PasskeyUpdate) SetNillableBackupEligible(b *bool) *PasskeyUpdate {
	if b != nil {
		pu.SetBackupEligible(*b)
	}
	return pu
}

// ClearBackupEligible clears the value of the "backup_eligible" field.
func (pu *PasskeyUpdate) ClearBackupEligible() *PasskeyUpdate {
	pu.mutation.ClearBackupEligible()
	return pu
}

// SetUserAgent sets the "user_agent" field.
func (pu *PasskeyUpdate) SetUserAgent(s string) *PasskeyUpdate {
	pu.mutation.SetUserAgent(s)
	return pu
}

// SetNillableUserAgent sets the "user_agent" field if the given value is not nil.
func (pu *PasskeyUpdate) SetNillableUserAgent(s *string) *PasskeyUpdate {
	if s != nil {
		pu.SetUserAgent(*s)
	}
	return pu
}

// ClearUserAgent clears the value of the "user_agent" field.
func (pu *PasskeyUpdate) ClearUserAgent() *PasskeyUpdate {
	pu.mutation.ClearUserAgent()
	return pu
}

// SetIPAddress sets the "ip_address" field.
func (pu *PasskeyUpdate) SetIPAddress(s string) *PasskeyUpdate {
	pu.mutation.SetIPAddress(s)
	return pu
}

// SetNillableIPAddress sets the "ip_address" field if the given value is not nil.
func (pu *PasskeyUpdate) SetNillableIPAddress(s *string) *PasskeyUpdate {
	if s != nil {
		pu.SetIPAddress(*s)
	}
	return pu
}

// ClearIPAddress clears the value of the "ip_address" field.
func (pu *PasskeyUpdate) ClearIPAddress() *PasskeyUpdate {
	pu.mutation.ClearIPAddress()
	return pu
}

// SetUser sets the "user" edge to the User entity.
func (pu *PasskeyUpdate) SetUser(u *User) *PasskeyUpdate {
	return pu.SetUserID(u.ID)
}

// Mutation returns the PasskeyMutation object of the builder.
func (pu *PasskeyUpdate) Mutation() *PasskeyMutation {
	return pu.mutation
}

// ClearUser clears the "user" edge to the User entity.
func (pu *PasskeyUpdate) ClearUser() *PasskeyUpdate {
	pu.mutation.ClearUser()
	return pu
}

// Save executes the query and returns the number of nodes affected by the update operation.
func (pu *PasskeyUpdate) Save(ctx context.Context) (int, error) {
	pu.defaults()
	return withHooks(ctx, pu.sqlSave, pu.mutation, pu.hooks)
}

// SaveX is like Save, but panics if an error occurs.
func (pu *PasskeyUpdate) SaveX(ctx context.Context) int {
	affected, err := pu.Save(ctx)
	if err != nil {
		panic(err)
	}
	return affected
}

// Exec executes the query.
func (pu *PasskeyUpdate) Exec(ctx context.Context) error {
	_, err := pu.Save(ctx)
	return err
}

// ExecX is like Exec, but panics if an error occurs.
func (pu *PasskeyUpdate) ExecX(ctx context.Context) {
	if err := pu.Exec(ctx); err != nil {
		panic(err)
	}
}

// defaults sets the default values of the builder before save.
func (pu *PasskeyUpdate) defaults() {
	if _, ok := pu.mutation.UpdatedAt(); !ok {
		v := passkey.UpdateDefaultUpdatedAt()
		pu.mutation.SetUpdatedAt(v)
	}
}

// check runs all checks and user-defined validators on the builder.
func (pu *PasskeyUpdate) check() error {
	if v, ok := pu.mutation.UserID(); ok {
		if err := passkey.UserIDValidator(v.String()); err != nil {
			return &ValidationError{Name: "user_id", err: fmt.Errorf(`ent: validator failed for field "Passkey.user_id": %w`, err)}
		}
	}
	if v, ok := pu.mutation.Name(); ok {
		if err := passkey.NameValidator(v); err != nil {
			return &ValidationError{Name: "name", err: fmt.Errorf(`ent: validator failed for field "Passkey.name": %w`, err)}
		}
	}
	if v, ok := pu.mutation.CredentialID(); ok {
		if err := passkey.CredentialIDValidator(v); err != nil {
			return &ValidationError{Name: "credential_id", err: fmt.Errorf(`ent: validator failed for field "Passkey.credential_id": %w`, err)}
		}
	}
	if v, ok := pu.mutation.PublicKey(); ok {
		if err := passkey.PublicKeyValidator(v); err != nil {
			return &ValidationError{Name: "public_key", err: fmt.Errorf(`ent: validator failed for field "Passkey.public_key": %w`, err)}
		}
	}
	if pu.mutation.UserCleared() && len(pu.mutation.UserIDs()) > 0 {
		return errors.New(`ent: clearing a required unique edge "Passkey.user"`)
	}
	return nil
}

// Modify adds a statement modifier for attaching custom logic to the UPDATE statement.
func (pu *PasskeyUpdate) Modify(modifiers ...func(u *sql.UpdateBuilder)) *PasskeyUpdate {
	pu.modifiers = append(pu.modifiers, modifiers...)
	return pu
}

func (pu *PasskeyUpdate) sqlSave(ctx context.Context) (n int, err error) {
	if err := pu.check(); err != nil {
		return n, err
	}
	_spec := sqlgraph.NewUpdateSpec(passkey.Table, passkey.Columns, sqlgraph.NewFieldSpec(passkey.FieldID, field.TypeString))
	if ps := pu.mutation.predicates; len(ps) > 0 {
		_spec.Predicate = func(selector *sql.Selector) {
			for i := range ps {
				ps[i](selector)
			}
		}
	}
	if value, ok := pu.mutation.UpdatedAt(); ok {
		_spec.SetField(passkey.FieldUpdatedAt, field.TypeTime, value)
	}
	if value, ok := pu.mutation.DeletedAt(); ok {
		_spec.SetField(passkey.FieldDeletedAt, field.TypeTime, value)
	}
	if pu.mutation.DeletedAtCleared() {
		_spec.ClearField(passkey.FieldDeletedAt, field.TypeTime)
	}
	if value, ok := pu.mutation.Name(); ok {
		_spec.SetField(passkey.FieldName, field.TypeString, value)
	}
	if value, ok := pu.mutation.CredentialID(); ok {
		_spec.SetField(passkey.FieldCredentialID, field.TypeString, value)
	}
	if value, ok := pu.mutation.PublicKey(); ok {
		_spec.SetField(passkey.FieldPublicKey, field.TypeBytes, value)
	}
	if value, ok := pu.mutation.SignCount(); ok {
		_spec.SetField(passkey.FieldSignCount, field.TypeInt, value)
	}
	if value, ok := pu.mutation.AddedSignCount(); ok {
		_spec.AddField(passkey.FieldSignCount, field.TypeInt, value)
	}
	if value, ok := pu.mutation.Active(); ok {
		_spec.SetField(passkey.FieldActive, field.TypeBool, value)
	}
	if value, ok := pu.mutation.DeviceType(); ok {
		_spec.SetField(passkey.FieldDeviceType, field.TypeString, value)
	}
	if pu.mutation.DeviceTypeCleared() {
		_spec.ClearField(passkey.FieldDeviceType, field.TypeString)
	}
	if value, ok := pu.mutation.Aaguid(); ok {
		_spec.SetField(passkey.FieldAaguid, field.TypeString, value)
	}
	if pu.mutation.AaguidCleared() {
		_spec.ClearField(passkey.FieldAaguid, field.TypeString)
	}
	if value, ok := pu.mutation.LastUsed(); ok {
		_spec.SetField(passkey.FieldLastUsed, field.TypeTime, value)
	}
	if pu.mutation.LastUsedCleared() {
		_spec.ClearField(passkey.FieldLastUsed, field.TypeTime)
	}
	if value, ok := pu.mutation.Transports(); ok {
		_spec.SetField(passkey.FieldTransports, field.TypeJSON, value)
	}
	if value, ok := pu.mutation.AppendedTransports(); ok {
		_spec.AddModifier(func(u *sql.UpdateBuilder) {
			sqljson.Append(u, passkey.FieldTransports, value)
		})
	}
	if pu.mutation.TransportsCleared() {
		_spec.ClearField(passkey.FieldTransports, field.TypeJSON)
	}
	if value, ok := pu.mutation.Attestation(); ok {
		_spec.SetField(passkey.FieldAttestation, field.TypeJSON, value)
	}
	if pu.mutation.AttestationCleared() {
		_spec.ClearField(passkey.FieldAttestation, field.TypeJSON)
	}
	if value, ok := pu.mutation.BackupState(); ok {
		_spec.SetField(passkey.FieldBackupState, field.TypeBool, value)
	}
	if pu.mutation.BackupStateCleared() {
		_spec.ClearField(passkey.FieldBackupState, field.TypeBool)
	}
	if value, ok := pu.mutation.BackupEligible(); ok {
		_spec.SetField(passkey.FieldBackupEligible, field.TypeBool, value)
	}
	if pu.mutation.BackupEligibleCleared() {
		_spec.ClearField(passkey.FieldBackupEligible, field.TypeBool)
	}
	if value, ok := pu.mutation.UserAgent(); ok {
		_spec.SetField(passkey.FieldUserAgent, field.TypeString, value)
	}
	if pu.mutation.UserAgentCleared() {
		_spec.ClearField(passkey.FieldUserAgent, field.TypeString)
	}
	if value, ok := pu.mutation.IPAddress(); ok {
		_spec.SetField(passkey.FieldIPAddress, field.TypeString, value)
	}
	if pu.mutation.IPAddressCleared() {
		_spec.ClearField(passkey.FieldIPAddress, field.TypeString)
	}
	if pu.mutation.UserCleared() {
		edge := &sqlgraph.EdgeSpec{
			Rel:     sqlgraph.M2O,
			Inverse: true,
			Table:   passkey.UserTable,
			Columns: []string{passkey.UserColumn},
			Bidi:    false,
			Target: &sqlgraph.EdgeTarget{
				IDSpec: sqlgraph.NewFieldSpec(user.FieldID, field.TypeString),
			},
		}
		_spec.Edges.Clear = append(_spec.Edges.Clear, edge)
	}
	if nodes := pu.mutation.UserIDs(); len(nodes) > 0 {
		edge := &sqlgraph.EdgeSpec{
			Rel:     sqlgraph.M2O,
			Inverse: true,
			Table:   passkey.UserTable,
			Columns: []string{passkey.UserColumn},
			Bidi:    false,
			Target: &sqlgraph.EdgeTarget{
				IDSpec: sqlgraph.NewFieldSpec(user.FieldID, field.TypeString),
			},
		}
		for _, k := range nodes {
			edge.Target.Nodes = append(edge.Target.Nodes, k)
		}
		_spec.Edges.Add = append(_spec.Edges.Add, edge)
	}
	_spec.AddModifiers(pu.modifiers...)
	if n, err = sqlgraph.UpdateNodes(ctx, pu.driver, _spec); err != nil {
		if _, ok := err.(*sqlgraph.NotFoundError); ok {
			err = &NotFoundError{passkey.Label}
		} else if sqlgraph.IsConstraintError(err) {
			err = &ConstraintError{msg: err.Error(), wrap: err}
		}
		return 0, err
	}
	pu.mutation.done = true
	return n, nil
}

// PasskeyUpdateOne is the builder for updating a single Passkey entity.
type PasskeyUpdateOne struct {
	config
	fields    []string
	hooks     []Hook
	mutation  *PasskeyMutation
	modifiers []func(*sql.UpdateBuilder)
}

// SetUpdatedAt sets the "updated_at" field.
func (puo *PasskeyUpdateOne) SetUpdatedAt(t time.Time) *PasskeyUpdateOne {
	puo.mutation.SetUpdatedAt(t)
	return puo
}

// SetDeletedAt sets the "deleted_at" field.
func (puo *PasskeyUpdateOne) SetDeletedAt(t time.Time) *PasskeyUpdateOne {
	puo.mutation.SetDeletedAt(t)
	return puo
}

// SetNillableDeletedAt sets the "deleted_at" field if the given value is not nil.
func (puo *PasskeyUpdateOne) SetNillableDeletedAt(t *time.Time) *PasskeyUpdateOne {
	if t != nil {
		puo.SetDeletedAt(*t)
	}
	return puo
}

// ClearDeletedAt clears the value of the "deleted_at" field.
func (puo *PasskeyUpdateOne) ClearDeletedAt() *PasskeyUpdateOne {
	puo.mutation.ClearDeletedAt()
	return puo
}

// SetUserID sets the "user_id" field.
func (puo *PasskeyUpdateOne) SetUserID(x xid.ID) *PasskeyUpdateOne {
	puo.mutation.SetUserID(x)
	return puo
}

// SetNillableUserID sets the "user_id" field if the given value is not nil.
func (puo *PasskeyUpdateOne) SetNillableUserID(x *xid.ID) *PasskeyUpdateOne {
	if x != nil {
		puo.SetUserID(*x)
	}
	return puo
}

// SetName sets the "name" field.
func (puo *PasskeyUpdateOne) SetName(s string) *PasskeyUpdateOne {
	puo.mutation.SetName(s)
	return puo
}

// SetNillableName sets the "name" field if the given value is not nil.
func (puo *PasskeyUpdateOne) SetNillableName(s *string) *PasskeyUpdateOne {
	if s != nil {
		puo.SetName(*s)
	}
	return puo
}

// SetCredentialID sets the "credential_id" field.
func (puo *PasskeyUpdateOne) SetCredentialID(s string) *PasskeyUpdateOne {
	puo.mutation.SetCredentialID(s)
	return puo
}

// SetNillableCredentialID sets the "credential_id" field if the given value is not nil.
func (puo *PasskeyUpdateOne) SetNillableCredentialID(s *string) *PasskeyUpdateOne {
	if s != nil {
		puo.SetCredentialID(*s)
	}
	return puo
}

// SetPublicKey sets the "public_key" field.
func (puo *PasskeyUpdateOne) SetPublicKey(b []byte) *PasskeyUpdateOne {
	puo.mutation.SetPublicKey(b)
	return puo
}

// SetSignCount sets the "sign_count" field.
func (puo *PasskeyUpdateOne) SetSignCount(i int) *PasskeyUpdateOne {
	puo.mutation.ResetSignCount()
	puo.mutation.SetSignCount(i)
	return puo
}

// SetNillableSignCount sets the "sign_count" field if the given value is not nil.
func (puo *PasskeyUpdateOne) SetNillableSignCount(i *int) *PasskeyUpdateOne {
	if i != nil {
		puo.SetSignCount(*i)
	}
	return puo
}

// AddSignCount adds i to the "sign_count" field.
func (puo *PasskeyUpdateOne) AddSignCount(i int) *PasskeyUpdateOne {
	puo.mutation.AddSignCount(i)
	return puo
}

// SetActive sets the "active" field.
func (puo *PasskeyUpdateOne) SetActive(b bool) *PasskeyUpdateOne {
	puo.mutation.SetActive(b)
	return puo
}

// SetNillableActive sets the "active" field if the given value is not nil.
func (puo *PasskeyUpdateOne) SetNillableActive(b *bool) *PasskeyUpdateOne {
	if b != nil {
		puo.SetActive(*b)
	}
	return puo
}

// SetDeviceType sets the "device_type" field.
func (puo *PasskeyUpdateOne) SetDeviceType(s string) *PasskeyUpdateOne {
	puo.mutation.SetDeviceType(s)
	return puo
}

// SetNillableDeviceType sets the "device_type" field if the given value is not nil.
func (puo *PasskeyUpdateOne) SetNillableDeviceType(s *string) *PasskeyUpdateOne {
	if s != nil {
		puo.SetDeviceType(*s)
	}
	return puo
}

// ClearDeviceType clears the value of the "device_type" field.
func (puo *PasskeyUpdateOne) ClearDeviceType() *PasskeyUpdateOne {
	puo.mutation.ClearDeviceType()
	return puo
}

// SetAaguid sets the "aaguid" field.
func (puo *PasskeyUpdateOne) SetAaguid(s string) *PasskeyUpdateOne {
	puo.mutation.SetAaguid(s)
	return puo
}

// SetNillableAaguid sets the "aaguid" field if the given value is not nil.
func (puo *PasskeyUpdateOne) SetNillableAaguid(s *string) *PasskeyUpdateOne {
	if s != nil {
		puo.SetAaguid(*s)
	}
	return puo
}

// ClearAaguid clears the value of the "aaguid" field.
func (puo *PasskeyUpdateOne) ClearAaguid() *PasskeyUpdateOne {
	puo.mutation.ClearAaguid()
	return puo
}

// SetLastUsed sets the "last_used" field.
func (puo *PasskeyUpdateOne) SetLastUsed(t time.Time) *PasskeyUpdateOne {
	puo.mutation.SetLastUsed(t)
	return puo
}

// SetNillableLastUsed sets the "last_used" field if the given value is not nil.
func (puo *PasskeyUpdateOne) SetNillableLastUsed(t *time.Time) *PasskeyUpdateOne {
	if t != nil {
		puo.SetLastUsed(*t)
	}
	return puo
}

// ClearLastUsed clears the value of the "last_used" field.
func (puo *PasskeyUpdateOne) ClearLastUsed() *PasskeyUpdateOne {
	puo.mutation.ClearLastUsed()
	return puo
}

// SetTransports sets the "transports" field.
func (puo *PasskeyUpdateOne) SetTransports(s []string) *PasskeyUpdateOne {
	puo.mutation.SetTransports(s)
	return puo
}

// AppendTransports appends s to the "transports" field.
func (puo *PasskeyUpdateOne) AppendTransports(s []string) *PasskeyUpdateOne {
	puo.mutation.AppendTransports(s)
	return puo
}

// ClearTransports clears the value of the "transports" field.
func (puo *PasskeyUpdateOne) ClearTransports() *PasskeyUpdateOne {
	puo.mutation.ClearTransports()
	return puo
}

// SetAttestation sets the "attestation" field.
func (puo *PasskeyUpdateOne) SetAttestation(m map[string]interface{}) *PasskeyUpdateOne {
	puo.mutation.SetAttestation(m)
	return puo
}

// ClearAttestation clears the value of the "attestation" field.
func (puo *PasskeyUpdateOne) ClearAttestation() *PasskeyUpdateOne {
	puo.mutation.ClearAttestation()
	return puo
}

// SetBackupState sets the "backup_state" field.
func (puo *PasskeyUpdateOne) SetBackupState(b bool) *PasskeyUpdateOne {
	puo.mutation.SetBackupState(b)
	return puo
}

// SetNillableBackupState sets the "backup_state" field if the given value is not nil.
func (puo *PasskeyUpdateOne) SetNillableBackupState(b *bool) *PasskeyUpdateOne {
	if b != nil {
		puo.SetBackupState(*b)
	}
	return puo
}

// ClearBackupState clears the value of the "backup_state" field.
func (puo *PasskeyUpdateOne) ClearBackupState() *PasskeyUpdateOne {
	puo.mutation.ClearBackupState()
	return puo
}

// SetBackupEligible sets the "backup_eligible" field.
func (puo *PasskeyUpdateOne) SetBackupEligible(b bool) *PasskeyUpdateOne {
	puo.mutation.SetBackupEligible(b)
	return puo
}

// SetNillableBackupEligible sets the "backup_eligible" field if the given value is not nil.
func (puo *PasskeyUpdateOne) SetNillableBackupEligible(b *bool) *PasskeyUpdateOne {
	if b != nil {
		puo.SetBackupEligible(*b)
	}
	return puo
}

// ClearBackupEligible clears the value of the "backup_eligible" field.
func (puo *PasskeyUpdateOne) ClearBackupEligible() *PasskeyUpdateOne {
	puo.mutation.ClearBackupEligible()
	return puo
}

// SetUserAgent sets the "user_agent" field.
func (puo *PasskeyUpdateOne) SetUserAgent(s string) *PasskeyUpdateOne {
	puo.mutation.SetUserAgent(s)
	return puo
}

// SetNillableUserAgent sets the "user_agent" field if the given value is not nil.
func (puo *PasskeyUpdateOne) SetNillableUserAgent(s *string) *PasskeyUpdateOne {
	if s != nil {
		puo.SetUserAgent(*s)
	}
	return puo
}

// ClearUserAgent clears the value of the "user_agent" field.
func (puo *PasskeyUpdateOne) ClearUserAgent() *PasskeyUpdateOne {
	puo.mutation.ClearUserAgent()
	return puo
}

// SetIPAddress sets the "ip_address" field.
func (puo *PasskeyUpdateOne) SetIPAddress(s string) *PasskeyUpdateOne {
	puo.mutation.SetIPAddress(s)
	return puo
}

// SetNillableIPAddress sets the "ip_address" field if the given value is not nil.
func (puo *PasskeyUpdateOne) SetNillableIPAddress(s *string) *PasskeyUpdateOne {
	if s != nil {
		puo.SetIPAddress(*s)
	}
	return puo
}

// ClearIPAddress clears the value of the "ip_address" field.
func (puo *PasskeyUpdateOne) ClearIPAddress() *PasskeyUpdateOne {
	puo.mutation.ClearIPAddress()
	return puo
}

// SetUser sets the "user" edge to the User entity.
func (puo *PasskeyUpdateOne) SetUser(u *User) *PasskeyUpdateOne {
	return puo.SetUserID(u.ID)
}

// Mutation returns the PasskeyMutation object of the builder.
func (puo *PasskeyUpdateOne) Mutation() *PasskeyMutation {
	return puo.mutation
}

// ClearUser clears the "user" edge to the User entity.
func (puo *PasskeyUpdateOne) ClearUser() *PasskeyUpdateOne {
	puo.mutation.ClearUser()
	return puo
}

// Where appends a list predicates to the PasskeyUpdate builder.
func (puo *PasskeyUpdateOne) Where(ps ...predicate.Passkey) *PasskeyUpdateOne {
	puo.mutation.Where(ps...)
	return puo
}

// Select allows selecting one or more fields (columns) of the returned entity.
// The default is selecting all fields defined in the entity schema.
func (puo *PasskeyUpdateOne) Select(field string, fields ...string) *PasskeyUpdateOne {
	puo.fields = append([]string{field}, fields...)
	return puo
}

// Save executes the query and returns the updated Passkey entity.
func (puo *PasskeyUpdateOne) Save(ctx context.Context) (*Passkey, error) {
	puo.defaults()
	return withHooks(ctx, puo.sqlSave, puo.mutation, puo.hooks)
}

// SaveX is like Save, but panics if an error occurs.
func (puo *PasskeyUpdateOne) SaveX(ctx context.Context) *Passkey {
	node, err := puo.Save(ctx)
	if err != nil {
		panic(err)
	}
	return node
}

// Exec executes the query on the entity.
func (puo *PasskeyUpdateOne) Exec(ctx context.Context) error {
	_, err := puo.Save(ctx)
	return err
}

// ExecX is like Exec, but panics if an error occurs.
func (puo *PasskeyUpdateOne) ExecX(ctx context.Context) {
	if err := puo.Exec(ctx); err != nil {
		panic(err)
	}
}

// defaults sets the default values of the builder before save.
func (puo *PasskeyUpdateOne) defaults() {
	if _, ok := puo.mutation.UpdatedAt(); !ok {
		v := passkey.UpdateDefaultUpdatedAt()
		puo.mutation.SetUpdatedAt(v)
	}
}

// check runs all checks and user-defined validators on the builder.
func (puo *PasskeyUpdateOne) check() error {
	if v, ok := puo.mutation.UserID(); ok {
		if err := passkey.UserIDValidator(v.String()); err != nil {
			return &ValidationError{Name: "user_id", err: fmt.Errorf(`ent: validator failed for field "Passkey.user_id": %w`, err)}
		}
	}
	if v, ok := puo.mutation.Name(); ok {
		if err := passkey.NameValidator(v); err != nil {
			return &ValidationError{Name: "name", err: fmt.Errorf(`ent: validator failed for field "Passkey.name": %w`, err)}
		}
	}
	if v, ok := puo.mutation.CredentialID(); ok {
		if err := passkey.CredentialIDValidator(v); err != nil {
			return &ValidationError{Name: "credential_id", err: fmt.Errorf(`ent: validator failed for field "Passkey.credential_id": %w`, err)}
		}
	}
	if v, ok := puo.mutation.PublicKey(); ok {
		if err := passkey.PublicKeyValidator(v); err != nil {
			return &ValidationError{Name: "public_key", err: fmt.Errorf(`ent: validator failed for field "Passkey.public_key": %w`, err)}
		}
	}
	if puo.mutation.UserCleared() && len(puo.mutation.UserIDs()) > 0 {
		return errors.New(`ent: clearing a required unique edge "Passkey.user"`)
	}
	return nil
}

// Modify adds a statement modifier for attaching custom logic to the UPDATE statement.
func (puo *PasskeyUpdateOne) Modify(modifiers ...func(u *sql.UpdateBuilder)) *PasskeyUpdateOne {
	puo.modifiers = append(puo.modifiers, modifiers...)
	return puo
}

func (puo *PasskeyUpdateOne) sqlSave(ctx context.Context) (_node *Passkey, err error) {
	if err := puo.check(); err != nil {
		return _node, err
	}
	_spec := sqlgraph.NewUpdateSpec(passkey.Table, passkey.Columns, sqlgraph.NewFieldSpec(passkey.FieldID, field.TypeString))
	id, ok := puo.mutation.ID()
	if !ok {
		return nil, &ValidationError{Name: "id", err: errors.New(`ent: missing "Passkey.id" for update`)}
	}
	_spec.Node.ID.Value = id
	if fields := puo.fields; len(fields) > 0 {
		_spec.Node.Columns = make([]string, 0, len(fields))
		_spec.Node.Columns = append(_spec.Node.Columns, passkey.FieldID)
		for _, f := range fields {
			if !passkey.ValidColumn(f) {
				return nil, &ValidationError{Name: f, err: fmt.Errorf("ent: invalid field %q for query", f)}
			}
			if f != passkey.FieldID {
				_spec.Node.Columns = append(_spec.Node.Columns, f)
			}
		}
	}
	if ps := puo.mutation.predicates; len(ps) > 0 {
		_spec.Predicate = func(selector *sql.Selector) {
			for i := range ps {
				ps[i](selector)
			}
		}
	}
	if value, ok := puo.mutation.UpdatedAt(); ok {
		_spec.SetField(passkey.FieldUpdatedAt, field.TypeTime, value)
	}
	if value, ok := puo.mutation.DeletedAt(); ok {
		_spec.SetField(passkey.FieldDeletedAt, field.TypeTime, value)
	}
	if puo.mutation.DeletedAtCleared() {
		_spec.ClearField(passkey.FieldDeletedAt, field.TypeTime)
	}
	if value, ok := puo.mutation.Name(); ok {
		_spec.SetField(passkey.FieldName, field.TypeString, value)
	}
	if value, ok := puo.mutation.CredentialID(); ok {
		_spec.SetField(passkey.FieldCredentialID, field.TypeString, value)
	}
	if value, ok := puo.mutation.PublicKey(); ok {
		_spec.SetField(passkey.FieldPublicKey, field.TypeBytes, value)
	}
	if value, ok := puo.mutation.SignCount(); ok {
		_spec.SetField(passkey.FieldSignCount, field.TypeInt, value)
	}
	if value, ok := puo.mutation.AddedSignCount(); ok {
		_spec.AddField(passkey.FieldSignCount, field.TypeInt, value)
	}
	if value, ok := puo.mutation.Active(); ok {
		_spec.SetField(passkey.FieldActive, field.TypeBool, value)
	}
	if value, ok := puo.mutation.DeviceType(); ok {
		_spec.SetField(passkey.FieldDeviceType, field.TypeString, value)
	}
	if puo.mutation.DeviceTypeCleared() {
		_spec.ClearField(passkey.FieldDeviceType, field.TypeString)
	}
	if value, ok := puo.mutation.Aaguid(); ok {
		_spec.SetField(passkey.FieldAaguid, field.TypeString, value)
	}
	if puo.mutation.AaguidCleared() {
		_spec.ClearField(passkey.FieldAaguid, field.TypeString)
	}
	if value, ok := puo.mutation.LastUsed(); ok {
		_spec.SetField(passkey.FieldLastUsed, field.TypeTime, value)
	}
	if puo.mutation.LastUsedCleared() {
		_spec.ClearField(passkey.FieldLastUsed, field.TypeTime)
	}
	if value, ok := puo.mutation.Transports(); ok {
		_spec.SetField(passkey.FieldTransports, field.TypeJSON, value)
	}
	if value, ok := puo.mutation.AppendedTransports(); ok {
		_spec.AddModifier(func(u *sql.UpdateBuilder) {
			sqljson.Append(u, passkey.FieldTransports, value)
		})
	}
	if puo.mutation.TransportsCleared() {
		_spec.ClearField(passkey.FieldTransports, field.TypeJSON)
	}
	if value, ok := puo.mutation.Attestation(); ok {
		_spec.SetField(passkey.FieldAttestation, field.TypeJSON, value)
	}
	if puo.mutation.AttestationCleared() {
		_spec.ClearField(passkey.FieldAttestation, field.TypeJSON)
	}
	if value, ok := puo.mutation.BackupState(); ok {
		_spec.SetField(passkey.FieldBackupState, field.TypeBool, value)
	}
	if puo.mutation.BackupStateCleared() {
		_spec.ClearField(passkey.FieldBackupState, field.TypeBool)
	}
	if value, ok := puo.mutation.BackupEligible(); ok {
		_spec.SetField(passkey.FieldBackupEligible, field.TypeBool, value)
	}
	if puo.mutation.BackupEligibleCleared() {
		_spec.ClearField(passkey.FieldBackupEligible, field.TypeBool)
	}
	if value, ok := puo.mutation.UserAgent(); ok {
		_spec.SetField(passkey.FieldUserAgent, field.TypeString, value)
	}
	if puo.mutation.UserAgentCleared() {
		_spec.ClearField(passkey.FieldUserAgent, field.TypeString)
	}
	if value, ok := puo.mutation.IPAddress(); ok {
		_spec.SetField(passkey.FieldIPAddress, field.TypeString, value)
	}
	if puo.mutation.IPAddressCleared() {
		_spec.ClearField(passkey.FieldIPAddress, field.TypeString)
	}
	if puo.mutation.UserCleared() {
		edge := &sqlgraph.EdgeSpec{
			Rel:     sqlgraph.M2O,
			Inverse: true,
			Table:   passkey.UserTable,
			Columns: []string{passkey.UserColumn},
			Bidi:    false,
			Target: &sqlgraph.EdgeTarget{
				IDSpec: sqlgraph.NewFieldSpec(user.FieldID, field.TypeString),
			},
		}
		_spec.Edges.Clear = append(_spec.Edges.Clear, edge)
	}
	if nodes := puo.mutation.UserIDs(); len(nodes) > 0 {
		edge := &sqlgraph.EdgeSpec{
			Rel:     sqlgraph.M2O,
			Inverse: true,
			Table:   passkey.UserTable,
			Columns: []string{passkey.UserColumn},
			Bidi:    false,
			Target: &sqlgraph.EdgeTarget{
				IDSpec: sqlgraph.NewFieldSpec(user.FieldID, field.TypeString),
			},
		}
		for _, k := range nodes {
			edge.Target.Nodes = append(edge.Target.Nodes, k)
		}
		_spec.Edges.Add = append(_spec.Edges.Add, edge)
	}
	_spec.AddModifiers(puo.modifiers...)
	_node = &Passkey{config: puo.config}
	_spec.Assign = _node.assignValues
	_spec.ScanValues = _node.scanValues
	if err = sqlgraph.UpdateNode(ctx, puo.driver, _spec); err != nil {
		if _, ok := err.(*sqlgraph.NotFoundError); ok {
			err = &NotFoundError{passkey.Label}
		} else if sqlgraph.IsConstraintError(err) {
			err = &ConstraintError{msg: err.Error(), wrap: err}
		}
		return nil, err
	}
	puo.mutation.done = true
	return _node, nil
}
