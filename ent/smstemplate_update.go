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
	"github.com/xraph/frank/ent/organization"
	"github.com/xraph/frank/ent/predicate"
	"github.com/xraph/frank/ent/smstemplate"
	"github.com/rs/xid"
)

// SMSTemplateUpdate is the builder for updating SMSTemplate entities.
type SMSTemplateUpdate struct {
	config
	hooks     []Hook
	mutation  *SMSTemplateMutation
	modifiers []func(*sql.UpdateBuilder)
}

// Where appends a list predicates to the SMSTemplateUpdate builder.
func (stu *SMSTemplateUpdate) Where(ps ...predicate.SMSTemplate) *SMSTemplateUpdate {
	stu.mutation.Where(ps...)
	return stu
}

// SetUpdatedAt sets the "updated_at" field.
func (stu *SMSTemplateUpdate) SetUpdatedAt(t time.Time) *SMSTemplateUpdate {
	stu.mutation.SetUpdatedAt(t)
	return stu
}

// SetDeletedAt sets the "deleted_at" field.
func (stu *SMSTemplateUpdate) SetDeletedAt(t time.Time) *SMSTemplateUpdate {
	stu.mutation.SetDeletedAt(t)
	return stu
}

// SetNillableDeletedAt sets the "deleted_at" field if the given value is not nil.
func (stu *SMSTemplateUpdate) SetNillableDeletedAt(t *time.Time) *SMSTemplateUpdate {
	if t != nil {
		stu.SetDeletedAt(*t)
	}
	return stu
}

// ClearDeletedAt clears the value of the "deleted_at" field.
func (stu *SMSTemplateUpdate) ClearDeletedAt() *SMSTemplateUpdate {
	stu.mutation.ClearDeletedAt()
	return stu
}

// SetName sets the "name" field.
func (stu *SMSTemplateUpdate) SetName(s string) *SMSTemplateUpdate {
	stu.mutation.SetName(s)
	return stu
}

// SetNillableName sets the "name" field if the given value is not nil.
func (stu *SMSTemplateUpdate) SetNillableName(s *string) *SMSTemplateUpdate {
	if s != nil {
		stu.SetName(*s)
	}
	return stu
}

// SetContent sets the "content" field.
func (stu *SMSTemplateUpdate) SetContent(s string) *SMSTemplateUpdate {
	stu.mutation.SetContent(s)
	return stu
}

// SetNillableContent sets the "content" field if the given value is not nil.
func (stu *SMSTemplateUpdate) SetNillableContent(s *string) *SMSTemplateUpdate {
	if s != nil {
		stu.SetContent(*s)
	}
	return stu
}

// SetType sets the "type" field.
func (stu *SMSTemplateUpdate) SetType(s string) *SMSTemplateUpdate {
	stu.mutation.SetType(s)
	return stu
}

// SetNillableType sets the "type" field if the given value is not nil.
func (stu *SMSTemplateUpdate) SetNillableType(s *string) *SMSTemplateUpdate {
	if s != nil {
		stu.SetType(*s)
	}
	return stu
}

// SetOrganizationID sets the "organization_id" field.
func (stu *SMSTemplateUpdate) SetOrganizationID(x xid.ID) *SMSTemplateUpdate {
	stu.mutation.SetOrganizationID(x)
	return stu
}

// SetNillableOrganizationID sets the "organization_id" field if the given value is not nil.
func (stu *SMSTemplateUpdate) SetNillableOrganizationID(x *xid.ID) *SMSTemplateUpdate {
	if x != nil {
		stu.SetOrganizationID(*x)
	}
	return stu
}

// ClearOrganizationID clears the value of the "organization_id" field.
func (stu *SMSTemplateUpdate) ClearOrganizationID() *SMSTemplateUpdate {
	stu.mutation.ClearOrganizationID()
	return stu
}

// SetActive sets the "active" field.
func (stu *SMSTemplateUpdate) SetActive(b bool) *SMSTemplateUpdate {
	stu.mutation.SetActive(b)
	return stu
}

// SetNillableActive sets the "active" field if the given value is not nil.
func (stu *SMSTemplateUpdate) SetNillableActive(b *bool) *SMSTemplateUpdate {
	if b != nil {
		stu.SetActive(*b)
	}
	return stu
}

// SetSystem sets the "system" field.
func (stu *SMSTemplateUpdate) SetSystem(b bool) *SMSTemplateUpdate {
	stu.mutation.SetSystem(b)
	return stu
}

// SetNillableSystem sets the "system" field if the given value is not nil.
func (stu *SMSTemplateUpdate) SetNillableSystem(b *bool) *SMSTemplateUpdate {
	if b != nil {
		stu.SetSystem(*b)
	}
	return stu
}

// SetLocale sets the "locale" field.
func (stu *SMSTemplateUpdate) SetLocale(s string) *SMSTemplateUpdate {
	stu.mutation.SetLocale(s)
	return stu
}

// SetNillableLocale sets the "locale" field if the given value is not nil.
func (stu *SMSTemplateUpdate) SetNillableLocale(s *string) *SMSTemplateUpdate {
	if s != nil {
		stu.SetLocale(*s)
	}
	return stu
}

// SetMaxLength sets the "max_length" field.
func (stu *SMSTemplateUpdate) SetMaxLength(i int) *SMSTemplateUpdate {
	stu.mutation.ResetMaxLength()
	stu.mutation.SetMaxLength(i)
	return stu
}

// SetNillableMaxLength sets the "max_length" field if the given value is not nil.
func (stu *SMSTemplateUpdate) SetNillableMaxLength(i *int) *SMSTemplateUpdate {
	if i != nil {
		stu.SetMaxLength(*i)
	}
	return stu
}

// AddMaxLength adds i to the "max_length" field.
func (stu *SMSTemplateUpdate) AddMaxLength(i int) *SMSTemplateUpdate {
	stu.mutation.AddMaxLength(i)
	return stu
}

// SetMessageType sets the "message_type" field.
func (stu *SMSTemplateUpdate) SetMessageType(s string) *SMSTemplateUpdate {
	stu.mutation.SetMessageType(s)
	return stu
}

// SetNillableMessageType sets the "message_type" field if the given value is not nil.
func (stu *SMSTemplateUpdate) SetNillableMessageType(s *string) *SMSTemplateUpdate {
	if s != nil {
		stu.SetMessageType(*s)
	}
	return stu
}

// SetEstimatedSegments sets the "estimated_segments" field.
func (stu *SMSTemplateUpdate) SetEstimatedSegments(i int) *SMSTemplateUpdate {
	stu.mutation.ResetEstimatedSegments()
	stu.mutation.SetEstimatedSegments(i)
	return stu
}

// SetNillableEstimatedSegments sets the "estimated_segments" field if the given value is not nil.
func (stu *SMSTemplateUpdate) SetNillableEstimatedSegments(i *int) *SMSTemplateUpdate {
	if i != nil {
		stu.SetEstimatedSegments(*i)
	}
	return stu
}

// AddEstimatedSegments adds i to the "estimated_segments" field.
func (stu *SMSTemplateUpdate) AddEstimatedSegments(i int) *SMSTemplateUpdate {
	stu.mutation.AddEstimatedSegments(i)
	return stu
}

// ClearEstimatedSegments clears the value of the "estimated_segments" field.
func (stu *SMSTemplateUpdate) ClearEstimatedSegments() *SMSTemplateUpdate {
	stu.mutation.ClearEstimatedSegments()
	return stu
}

// SetEstimatedCost sets the "estimated_cost" field.
func (stu *SMSTemplateUpdate) SetEstimatedCost(f float64) *SMSTemplateUpdate {
	stu.mutation.ResetEstimatedCost()
	stu.mutation.SetEstimatedCost(f)
	return stu
}

// SetNillableEstimatedCost sets the "estimated_cost" field if the given value is not nil.
func (stu *SMSTemplateUpdate) SetNillableEstimatedCost(f *float64) *SMSTemplateUpdate {
	if f != nil {
		stu.SetEstimatedCost(*f)
	}
	return stu
}

// AddEstimatedCost adds f to the "estimated_cost" field.
func (stu *SMSTemplateUpdate) AddEstimatedCost(f float64) *SMSTemplateUpdate {
	stu.mutation.AddEstimatedCost(f)
	return stu
}

// ClearEstimatedCost clears the value of the "estimated_cost" field.
func (stu *SMSTemplateUpdate) ClearEstimatedCost() *SMSTemplateUpdate {
	stu.mutation.ClearEstimatedCost()
	return stu
}

// SetCurrency sets the "currency" field.
func (stu *SMSTemplateUpdate) SetCurrency(s string) *SMSTemplateUpdate {
	stu.mutation.SetCurrency(s)
	return stu
}

// SetNillableCurrency sets the "currency" field if the given value is not nil.
func (stu *SMSTemplateUpdate) SetNillableCurrency(s *string) *SMSTemplateUpdate {
	if s != nil {
		stu.SetCurrency(*s)
	}
	return stu
}

// ClearCurrency clears the value of the "currency" field.
func (stu *SMSTemplateUpdate) ClearCurrency() *SMSTemplateUpdate {
	stu.mutation.ClearCurrency()
	return stu
}

// SetVariables sets the "variables" field.
func (stu *SMSTemplateUpdate) SetVariables(s []string) *SMSTemplateUpdate {
	stu.mutation.SetVariables(s)
	return stu
}

// AppendVariables appends s to the "variables" field.
func (stu *SMSTemplateUpdate) AppendVariables(s []string) *SMSTemplateUpdate {
	stu.mutation.AppendVariables(s)
	return stu
}

// ClearVariables clears the value of the "variables" field.
func (stu *SMSTemplateUpdate) ClearVariables() *SMSTemplateUpdate {
	stu.mutation.ClearVariables()
	return stu
}

// SetMetadata sets the "metadata" field.
func (stu *SMSTemplateUpdate) SetMetadata(m map[string]interface{}) *SMSTemplateUpdate {
	stu.mutation.SetMetadata(m)
	return stu
}

// ClearMetadata clears the value of the "metadata" field.
func (stu *SMSTemplateUpdate) ClearMetadata() *SMSTemplateUpdate {
	stu.mutation.ClearMetadata()
	return stu
}

// SetLastUsedAt sets the "last_used_at" field.
func (stu *SMSTemplateUpdate) SetLastUsedAt(t time.Time) *SMSTemplateUpdate {
	stu.mutation.SetLastUsedAt(t)
	return stu
}

// SetNillableLastUsedAt sets the "last_used_at" field if the given value is not nil.
func (stu *SMSTemplateUpdate) SetNillableLastUsedAt(t *time.Time) *SMSTemplateUpdate {
	if t != nil {
		stu.SetLastUsedAt(*t)
	}
	return stu
}

// ClearLastUsedAt clears the value of the "last_used_at" field.
func (stu *SMSTemplateUpdate) ClearLastUsedAt() *SMSTemplateUpdate {
	stu.mutation.ClearLastUsedAt()
	return stu
}

// SetUsageCount sets the "usage_count" field.
func (stu *SMSTemplateUpdate) SetUsageCount(i int) *SMSTemplateUpdate {
	stu.mutation.ResetUsageCount()
	stu.mutation.SetUsageCount(i)
	return stu
}

// SetNillableUsageCount sets the "usage_count" field if the given value is not nil.
func (stu *SMSTemplateUpdate) SetNillableUsageCount(i *int) *SMSTemplateUpdate {
	if i != nil {
		stu.SetUsageCount(*i)
	}
	return stu
}

// AddUsageCount adds i to the "usage_count" field.
func (stu *SMSTemplateUpdate) AddUsageCount(i int) *SMSTemplateUpdate {
	stu.mutation.AddUsageCount(i)
	return stu
}

// SetOrganization sets the "organization" edge to the Organization entity.
func (stu *SMSTemplateUpdate) SetOrganization(o *Organization) *SMSTemplateUpdate {
	return stu.SetOrganizationID(o.ID)
}

// Mutation returns the SMSTemplateMutation object of the builder.
func (stu *SMSTemplateUpdate) Mutation() *SMSTemplateMutation {
	return stu.mutation
}

// ClearOrganization clears the "organization" edge to the Organization entity.
func (stu *SMSTemplateUpdate) ClearOrganization() *SMSTemplateUpdate {
	stu.mutation.ClearOrganization()
	return stu
}

// Save executes the query and returns the number of nodes affected by the update operation.
func (stu *SMSTemplateUpdate) Save(ctx context.Context) (int, error) {
	stu.defaults()
	return withHooks(ctx, stu.sqlSave, stu.mutation, stu.hooks)
}

// SaveX is like Save, but panics if an error occurs.
func (stu *SMSTemplateUpdate) SaveX(ctx context.Context) int {
	affected, err := stu.Save(ctx)
	if err != nil {
		panic(err)
	}
	return affected
}

// Exec executes the query.
func (stu *SMSTemplateUpdate) Exec(ctx context.Context) error {
	_, err := stu.Save(ctx)
	return err
}

// ExecX is like Exec, but panics if an error occurs.
func (stu *SMSTemplateUpdate) ExecX(ctx context.Context) {
	if err := stu.Exec(ctx); err != nil {
		panic(err)
	}
}

// defaults sets the default values of the builder before save.
func (stu *SMSTemplateUpdate) defaults() {
	if _, ok := stu.mutation.UpdatedAt(); !ok {
		v := smstemplate.UpdateDefaultUpdatedAt()
		stu.mutation.SetUpdatedAt(v)
	}
}

// check runs all checks and user-defined validators on the builder.
func (stu *SMSTemplateUpdate) check() error {
	if v, ok := stu.mutation.Name(); ok {
		if err := smstemplate.NameValidator(v); err != nil {
			return &ValidationError{Name: "name", err: fmt.Errorf(`ent: validator failed for field "SMSTemplate.name": %w`, err)}
		}
	}
	if v, ok := stu.mutation.Content(); ok {
		if err := smstemplate.ContentValidator(v); err != nil {
			return &ValidationError{Name: "content", err: fmt.Errorf(`ent: validator failed for field "SMSTemplate.content": %w`, err)}
		}
	}
	if v, ok := stu.mutation.GetType(); ok {
		if err := smstemplate.TypeValidator(v); err != nil {
			return &ValidationError{Name: "type", err: fmt.Errorf(`ent: validator failed for field "SMSTemplate.type": %w`, err)}
		}
	}
	return nil
}

// Modify adds a statement modifier for attaching custom logic to the UPDATE statement.
func (stu *SMSTemplateUpdate) Modify(modifiers ...func(u *sql.UpdateBuilder)) *SMSTemplateUpdate {
	stu.modifiers = append(stu.modifiers, modifiers...)
	return stu
}

func (stu *SMSTemplateUpdate) sqlSave(ctx context.Context) (n int, err error) {
	if err := stu.check(); err != nil {
		return n, err
	}
	_spec := sqlgraph.NewUpdateSpec(smstemplate.Table, smstemplate.Columns, sqlgraph.NewFieldSpec(smstemplate.FieldID, field.TypeString))
	if ps := stu.mutation.predicates; len(ps) > 0 {
		_spec.Predicate = func(selector *sql.Selector) {
			for i := range ps {
				ps[i](selector)
			}
		}
	}
	if value, ok := stu.mutation.UpdatedAt(); ok {
		_spec.SetField(smstemplate.FieldUpdatedAt, field.TypeTime, value)
	}
	if value, ok := stu.mutation.DeletedAt(); ok {
		_spec.SetField(smstemplate.FieldDeletedAt, field.TypeTime, value)
	}
	if stu.mutation.DeletedAtCleared() {
		_spec.ClearField(smstemplate.FieldDeletedAt, field.TypeTime)
	}
	if value, ok := stu.mutation.Name(); ok {
		_spec.SetField(smstemplate.FieldName, field.TypeString, value)
	}
	if value, ok := stu.mutation.Content(); ok {
		_spec.SetField(smstemplate.FieldContent, field.TypeString, value)
	}
	if value, ok := stu.mutation.GetType(); ok {
		_spec.SetField(smstemplate.FieldType, field.TypeString, value)
	}
	if value, ok := stu.mutation.Active(); ok {
		_spec.SetField(smstemplate.FieldActive, field.TypeBool, value)
	}
	if value, ok := stu.mutation.System(); ok {
		_spec.SetField(smstemplate.FieldSystem, field.TypeBool, value)
	}
	if value, ok := stu.mutation.Locale(); ok {
		_spec.SetField(smstemplate.FieldLocale, field.TypeString, value)
	}
	if value, ok := stu.mutation.MaxLength(); ok {
		_spec.SetField(smstemplate.FieldMaxLength, field.TypeInt, value)
	}
	if value, ok := stu.mutation.AddedMaxLength(); ok {
		_spec.AddField(smstemplate.FieldMaxLength, field.TypeInt, value)
	}
	if value, ok := stu.mutation.MessageType(); ok {
		_spec.SetField(smstemplate.FieldMessageType, field.TypeString, value)
	}
	if value, ok := stu.mutation.EstimatedSegments(); ok {
		_spec.SetField(smstemplate.FieldEstimatedSegments, field.TypeInt, value)
	}
	if value, ok := stu.mutation.AddedEstimatedSegments(); ok {
		_spec.AddField(smstemplate.FieldEstimatedSegments, field.TypeInt, value)
	}
	if stu.mutation.EstimatedSegmentsCleared() {
		_spec.ClearField(smstemplate.FieldEstimatedSegments, field.TypeInt)
	}
	if value, ok := stu.mutation.EstimatedCost(); ok {
		_spec.SetField(smstemplate.FieldEstimatedCost, field.TypeFloat64, value)
	}
	if value, ok := stu.mutation.AddedEstimatedCost(); ok {
		_spec.AddField(smstemplate.FieldEstimatedCost, field.TypeFloat64, value)
	}
	if stu.mutation.EstimatedCostCleared() {
		_spec.ClearField(smstemplate.FieldEstimatedCost, field.TypeFloat64)
	}
	if value, ok := stu.mutation.Currency(); ok {
		_spec.SetField(smstemplate.FieldCurrency, field.TypeString, value)
	}
	if stu.mutation.CurrencyCleared() {
		_spec.ClearField(smstemplate.FieldCurrency, field.TypeString)
	}
	if value, ok := stu.mutation.Variables(); ok {
		_spec.SetField(smstemplate.FieldVariables, field.TypeJSON, value)
	}
	if value, ok := stu.mutation.AppendedVariables(); ok {
		_spec.AddModifier(func(u *sql.UpdateBuilder) {
			sqljson.Append(u, smstemplate.FieldVariables, value)
		})
	}
	if stu.mutation.VariablesCleared() {
		_spec.ClearField(smstemplate.FieldVariables, field.TypeJSON)
	}
	if value, ok := stu.mutation.Metadata(); ok {
		_spec.SetField(smstemplate.FieldMetadata, field.TypeJSON, value)
	}
	if stu.mutation.MetadataCleared() {
		_spec.ClearField(smstemplate.FieldMetadata, field.TypeJSON)
	}
	if value, ok := stu.mutation.LastUsedAt(); ok {
		_spec.SetField(smstemplate.FieldLastUsedAt, field.TypeTime, value)
	}
	if stu.mutation.LastUsedAtCleared() {
		_spec.ClearField(smstemplate.FieldLastUsedAt, field.TypeTime)
	}
	if value, ok := stu.mutation.UsageCount(); ok {
		_spec.SetField(smstemplate.FieldUsageCount, field.TypeInt, value)
	}
	if value, ok := stu.mutation.AddedUsageCount(); ok {
		_spec.AddField(smstemplate.FieldUsageCount, field.TypeInt, value)
	}
	if stu.mutation.OrganizationCleared() {
		edge := &sqlgraph.EdgeSpec{
			Rel:     sqlgraph.M2O,
			Inverse: true,
			Table:   smstemplate.OrganizationTable,
			Columns: []string{smstemplate.OrganizationColumn},
			Bidi:    false,
			Target: &sqlgraph.EdgeTarget{
				IDSpec: sqlgraph.NewFieldSpec(organization.FieldID, field.TypeString),
			},
		}
		_spec.Edges.Clear = append(_spec.Edges.Clear, edge)
	}
	if nodes := stu.mutation.OrganizationIDs(); len(nodes) > 0 {
		edge := &sqlgraph.EdgeSpec{
			Rel:     sqlgraph.M2O,
			Inverse: true,
			Table:   smstemplate.OrganizationTable,
			Columns: []string{smstemplate.OrganizationColumn},
			Bidi:    false,
			Target: &sqlgraph.EdgeTarget{
				IDSpec: sqlgraph.NewFieldSpec(organization.FieldID, field.TypeString),
			},
		}
		for _, k := range nodes {
			edge.Target.Nodes = append(edge.Target.Nodes, k)
		}
		_spec.Edges.Add = append(_spec.Edges.Add, edge)
	}
	_spec.AddModifiers(stu.modifiers...)
	if n, err = sqlgraph.UpdateNodes(ctx, stu.driver, _spec); err != nil {
		if _, ok := err.(*sqlgraph.NotFoundError); ok {
			err = &NotFoundError{smstemplate.Label}
		} else if sqlgraph.IsConstraintError(err) {
			err = &ConstraintError{msg: err.Error(), wrap: err}
		}
		return 0, err
	}
	stu.mutation.done = true
	return n, nil
}

// SMSTemplateUpdateOne is the builder for updating a single SMSTemplate entity.
type SMSTemplateUpdateOne struct {
	config
	fields    []string
	hooks     []Hook
	mutation  *SMSTemplateMutation
	modifiers []func(*sql.UpdateBuilder)
}

// SetUpdatedAt sets the "updated_at" field.
func (stuo *SMSTemplateUpdateOne) SetUpdatedAt(t time.Time) *SMSTemplateUpdateOne {
	stuo.mutation.SetUpdatedAt(t)
	return stuo
}

// SetDeletedAt sets the "deleted_at" field.
func (stuo *SMSTemplateUpdateOne) SetDeletedAt(t time.Time) *SMSTemplateUpdateOne {
	stuo.mutation.SetDeletedAt(t)
	return stuo
}

// SetNillableDeletedAt sets the "deleted_at" field if the given value is not nil.
func (stuo *SMSTemplateUpdateOne) SetNillableDeletedAt(t *time.Time) *SMSTemplateUpdateOne {
	if t != nil {
		stuo.SetDeletedAt(*t)
	}
	return stuo
}

// ClearDeletedAt clears the value of the "deleted_at" field.
func (stuo *SMSTemplateUpdateOne) ClearDeletedAt() *SMSTemplateUpdateOne {
	stuo.mutation.ClearDeletedAt()
	return stuo
}

// SetName sets the "name" field.
func (stuo *SMSTemplateUpdateOne) SetName(s string) *SMSTemplateUpdateOne {
	stuo.mutation.SetName(s)
	return stuo
}

// SetNillableName sets the "name" field if the given value is not nil.
func (stuo *SMSTemplateUpdateOne) SetNillableName(s *string) *SMSTemplateUpdateOne {
	if s != nil {
		stuo.SetName(*s)
	}
	return stuo
}

// SetContent sets the "content" field.
func (stuo *SMSTemplateUpdateOne) SetContent(s string) *SMSTemplateUpdateOne {
	stuo.mutation.SetContent(s)
	return stuo
}

// SetNillableContent sets the "content" field if the given value is not nil.
func (stuo *SMSTemplateUpdateOne) SetNillableContent(s *string) *SMSTemplateUpdateOne {
	if s != nil {
		stuo.SetContent(*s)
	}
	return stuo
}

// SetType sets the "type" field.
func (stuo *SMSTemplateUpdateOne) SetType(s string) *SMSTemplateUpdateOne {
	stuo.mutation.SetType(s)
	return stuo
}

// SetNillableType sets the "type" field if the given value is not nil.
func (stuo *SMSTemplateUpdateOne) SetNillableType(s *string) *SMSTemplateUpdateOne {
	if s != nil {
		stuo.SetType(*s)
	}
	return stuo
}

// SetOrganizationID sets the "organization_id" field.
func (stuo *SMSTemplateUpdateOne) SetOrganizationID(x xid.ID) *SMSTemplateUpdateOne {
	stuo.mutation.SetOrganizationID(x)
	return stuo
}

// SetNillableOrganizationID sets the "organization_id" field if the given value is not nil.
func (stuo *SMSTemplateUpdateOne) SetNillableOrganizationID(x *xid.ID) *SMSTemplateUpdateOne {
	if x != nil {
		stuo.SetOrganizationID(*x)
	}
	return stuo
}

// ClearOrganizationID clears the value of the "organization_id" field.
func (stuo *SMSTemplateUpdateOne) ClearOrganizationID() *SMSTemplateUpdateOne {
	stuo.mutation.ClearOrganizationID()
	return stuo
}

// SetActive sets the "active" field.
func (stuo *SMSTemplateUpdateOne) SetActive(b bool) *SMSTemplateUpdateOne {
	stuo.mutation.SetActive(b)
	return stuo
}

// SetNillableActive sets the "active" field if the given value is not nil.
func (stuo *SMSTemplateUpdateOne) SetNillableActive(b *bool) *SMSTemplateUpdateOne {
	if b != nil {
		stuo.SetActive(*b)
	}
	return stuo
}

// SetSystem sets the "system" field.
func (stuo *SMSTemplateUpdateOne) SetSystem(b bool) *SMSTemplateUpdateOne {
	stuo.mutation.SetSystem(b)
	return stuo
}

// SetNillableSystem sets the "system" field if the given value is not nil.
func (stuo *SMSTemplateUpdateOne) SetNillableSystem(b *bool) *SMSTemplateUpdateOne {
	if b != nil {
		stuo.SetSystem(*b)
	}
	return stuo
}

// SetLocale sets the "locale" field.
func (stuo *SMSTemplateUpdateOne) SetLocale(s string) *SMSTemplateUpdateOne {
	stuo.mutation.SetLocale(s)
	return stuo
}

// SetNillableLocale sets the "locale" field if the given value is not nil.
func (stuo *SMSTemplateUpdateOne) SetNillableLocale(s *string) *SMSTemplateUpdateOne {
	if s != nil {
		stuo.SetLocale(*s)
	}
	return stuo
}

// SetMaxLength sets the "max_length" field.
func (stuo *SMSTemplateUpdateOne) SetMaxLength(i int) *SMSTemplateUpdateOne {
	stuo.mutation.ResetMaxLength()
	stuo.mutation.SetMaxLength(i)
	return stuo
}

// SetNillableMaxLength sets the "max_length" field if the given value is not nil.
func (stuo *SMSTemplateUpdateOne) SetNillableMaxLength(i *int) *SMSTemplateUpdateOne {
	if i != nil {
		stuo.SetMaxLength(*i)
	}
	return stuo
}

// AddMaxLength adds i to the "max_length" field.
func (stuo *SMSTemplateUpdateOne) AddMaxLength(i int) *SMSTemplateUpdateOne {
	stuo.mutation.AddMaxLength(i)
	return stuo
}

// SetMessageType sets the "message_type" field.
func (stuo *SMSTemplateUpdateOne) SetMessageType(s string) *SMSTemplateUpdateOne {
	stuo.mutation.SetMessageType(s)
	return stuo
}

// SetNillableMessageType sets the "message_type" field if the given value is not nil.
func (stuo *SMSTemplateUpdateOne) SetNillableMessageType(s *string) *SMSTemplateUpdateOne {
	if s != nil {
		stuo.SetMessageType(*s)
	}
	return stuo
}

// SetEstimatedSegments sets the "estimated_segments" field.
func (stuo *SMSTemplateUpdateOne) SetEstimatedSegments(i int) *SMSTemplateUpdateOne {
	stuo.mutation.ResetEstimatedSegments()
	stuo.mutation.SetEstimatedSegments(i)
	return stuo
}

// SetNillableEstimatedSegments sets the "estimated_segments" field if the given value is not nil.
func (stuo *SMSTemplateUpdateOne) SetNillableEstimatedSegments(i *int) *SMSTemplateUpdateOne {
	if i != nil {
		stuo.SetEstimatedSegments(*i)
	}
	return stuo
}

// AddEstimatedSegments adds i to the "estimated_segments" field.
func (stuo *SMSTemplateUpdateOne) AddEstimatedSegments(i int) *SMSTemplateUpdateOne {
	stuo.mutation.AddEstimatedSegments(i)
	return stuo
}

// ClearEstimatedSegments clears the value of the "estimated_segments" field.
func (stuo *SMSTemplateUpdateOne) ClearEstimatedSegments() *SMSTemplateUpdateOne {
	stuo.mutation.ClearEstimatedSegments()
	return stuo
}

// SetEstimatedCost sets the "estimated_cost" field.
func (stuo *SMSTemplateUpdateOne) SetEstimatedCost(f float64) *SMSTemplateUpdateOne {
	stuo.mutation.ResetEstimatedCost()
	stuo.mutation.SetEstimatedCost(f)
	return stuo
}

// SetNillableEstimatedCost sets the "estimated_cost" field if the given value is not nil.
func (stuo *SMSTemplateUpdateOne) SetNillableEstimatedCost(f *float64) *SMSTemplateUpdateOne {
	if f != nil {
		stuo.SetEstimatedCost(*f)
	}
	return stuo
}

// AddEstimatedCost adds f to the "estimated_cost" field.
func (stuo *SMSTemplateUpdateOne) AddEstimatedCost(f float64) *SMSTemplateUpdateOne {
	stuo.mutation.AddEstimatedCost(f)
	return stuo
}

// ClearEstimatedCost clears the value of the "estimated_cost" field.
func (stuo *SMSTemplateUpdateOne) ClearEstimatedCost() *SMSTemplateUpdateOne {
	stuo.mutation.ClearEstimatedCost()
	return stuo
}

// SetCurrency sets the "currency" field.
func (stuo *SMSTemplateUpdateOne) SetCurrency(s string) *SMSTemplateUpdateOne {
	stuo.mutation.SetCurrency(s)
	return stuo
}

// SetNillableCurrency sets the "currency" field if the given value is not nil.
func (stuo *SMSTemplateUpdateOne) SetNillableCurrency(s *string) *SMSTemplateUpdateOne {
	if s != nil {
		stuo.SetCurrency(*s)
	}
	return stuo
}

// ClearCurrency clears the value of the "currency" field.
func (stuo *SMSTemplateUpdateOne) ClearCurrency() *SMSTemplateUpdateOne {
	stuo.mutation.ClearCurrency()
	return stuo
}

// SetVariables sets the "variables" field.
func (stuo *SMSTemplateUpdateOne) SetVariables(s []string) *SMSTemplateUpdateOne {
	stuo.mutation.SetVariables(s)
	return stuo
}

// AppendVariables appends s to the "variables" field.
func (stuo *SMSTemplateUpdateOne) AppendVariables(s []string) *SMSTemplateUpdateOne {
	stuo.mutation.AppendVariables(s)
	return stuo
}

// ClearVariables clears the value of the "variables" field.
func (stuo *SMSTemplateUpdateOne) ClearVariables() *SMSTemplateUpdateOne {
	stuo.mutation.ClearVariables()
	return stuo
}

// SetMetadata sets the "metadata" field.
func (stuo *SMSTemplateUpdateOne) SetMetadata(m map[string]interface{}) *SMSTemplateUpdateOne {
	stuo.mutation.SetMetadata(m)
	return stuo
}

// ClearMetadata clears the value of the "metadata" field.
func (stuo *SMSTemplateUpdateOne) ClearMetadata() *SMSTemplateUpdateOne {
	stuo.mutation.ClearMetadata()
	return stuo
}

// SetLastUsedAt sets the "last_used_at" field.
func (stuo *SMSTemplateUpdateOne) SetLastUsedAt(t time.Time) *SMSTemplateUpdateOne {
	stuo.mutation.SetLastUsedAt(t)
	return stuo
}

// SetNillableLastUsedAt sets the "last_used_at" field if the given value is not nil.
func (stuo *SMSTemplateUpdateOne) SetNillableLastUsedAt(t *time.Time) *SMSTemplateUpdateOne {
	if t != nil {
		stuo.SetLastUsedAt(*t)
	}
	return stuo
}

// ClearLastUsedAt clears the value of the "last_used_at" field.
func (stuo *SMSTemplateUpdateOne) ClearLastUsedAt() *SMSTemplateUpdateOne {
	stuo.mutation.ClearLastUsedAt()
	return stuo
}

// SetUsageCount sets the "usage_count" field.
func (stuo *SMSTemplateUpdateOne) SetUsageCount(i int) *SMSTemplateUpdateOne {
	stuo.mutation.ResetUsageCount()
	stuo.mutation.SetUsageCount(i)
	return stuo
}

// SetNillableUsageCount sets the "usage_count" field if the given value is not nil.
func (stuo *SMSTemplateUpdateOne) SetNillableUsageCount(i *int) *SMSTemplateUpdateOne {
	if i != nil {
		stuo.SetUsageCount(*i)
	}
	return stuo
}

// AddUsageCount adds i to the "usage_count" field.
func (stuo *SMSTemplateUpdateOne) AddUsageCount(i int) *SMSTemplateUpdateOne {
	stuo.mutation.AddUsageCount(i)
	return stuo
}

// SetOrganization sets the "organization" edge to the Organization entity.
func (stuo *SMSTemplateUpdateOne) SetOrganization(o *Organization) *SMSTemplateUpdateOne {
	return stuo.SetOrganizationID(o.ID)
}

// Mutation returns the SMSTemplateMutation object of the builder.
func (stuo *SMSTemplateUpdateOne) Mutation() *SMSTemplateMutation {
	return stuo.mutation
}

// ClearOrganization clears the "organization" edge to the Organization entity.
func (stuo *SMSTemplateUpdateOne) ClearOrganization() *SMSTemplateUpdateOne {
	stuo.mutation.ClearOrganization()
	return stuo
}

// Where appends a list predicates to the SMSTemplateUpdate builder.
func (stuo *SMSTemplateUpdateOne) Where(ps ...predicate.SMSTemplate) *SMSTemplateUpdateOne {
	stuo.mutation.Where(ps...)
	return stuo
}

// Select allows selecting one or more fields (columns) of the returned entity.
// The default is selecting all fields defined in the entity schema.
func (stuo *SMSTemplateUpdateOne) Select(field string, fields ...string) *SMSTemplateUpdateOne {
	stuo.fields = append([]string{field}, fields...)
	return stuo
}

// Save executes the query and returns the updated SMSTemplate entity.
func (stuo *SMSTemplateUpdateOne) Save(ctx context.Context) (*SMSTemplate, error) {
	stuo.defaults()
	return withHooks(ctx, stuo.sqlSave, stuo.mutation, stuo.hooks)
}

// SaveX is like Save, but panics if an error occurs.
func (stuo *SMSTemplateUpdateOne) SaveX(ctx context.Context) *SMSTemplate {
	node, err := stuo.Save(ctx)
	if err != nil {
		panic(err)
	}
	return node
}

// Exec executes the query on the entity.
func (stuo *SMSTemplateUpdateOne) Exec(ctx context.Context) error {
	_, err := stuo.Save(ctx)
	return err
}

// ExecX is like Exec, but panics if an error occurs.
func (stuo *SMSTemplateUpdateOne) ExecX(ctx context.Context) {
	if err := stuo.Exec(ctx); err != nil {
		panic(err)
	}
}

// defaults sets the default values of the builder before save.
func (stuo *SMSTemplateUpdateOne) defaults() {
	if _, ok := stuo.mutation.UpdatedAt(); !ok {
		v := smstemplate.UpdateDefaultUpdatedAt()
		stuo.mutation.SetUpdatedAt(v)
	}
}

// check runs all checks and user-defined validators on the builder.
func (stuo *SMSTemplateUpdateOne) check() error {
	if v, ok := stuo.mutation.Name(); ok {
		if err := smstemplate.NameValidator(v); err != nil {
			return &ValidationError{Name: "name", err: fmt.Errorf(`ent: validator failed for field "SMSTemplate.name": %w`, err)}
		}
	}
	if v, ok := stuo.mutation.Content(); ok {
		if err := smstemplate.ContentValidator(v); err != nil {
			return &ValidationError{Name: "content", err: fmt.Errorf(`ent: validator failed for field "SMSTemplate.content": %w`, err)}
		}
	}
	if v, ok := stuo.mutation.GetType(); ok {
		if err := smstemplate.TypeValidator(v); err != nil {
			return &ValidationError{Name: "type", err: fmt.Errorf(`ent: validator failed for field "SMSTemplate.type": %w`, err)}
		}
	}
	return nil
}

// Modify adds a statement modifier for attaching custom logic to the UPDATE statement.
func (stuo *SMSTemplateUpdateOne) Modify(modifiers ...func(u *sql.UpdateBuilder)) *SMSTemplateUpdateOne {
	stuo.modifiers = append(stuo.modifiers, modifiers...)
	return stuo
}

func (stuo *SMSTemplateUpdateOne) sqlSave(ctx context.Context) (_node *SMSTemplate, err error) {
	if err := stuo.check(); err != nil {
		return _node, err
	}
	_spec := sqlgraph.NewUpdateSpec(smstemplate.Table, smstemplate.Columns, sqlgraph.NewFieldSpec(smstemplate.FieldID, field.TypeString))
	id, ok := stuo.mutation.ID()
	if !ok {
		return nil, &ValidationError{Name: "id", err: errors.New(`ent: missing "SMSTemplate.id" for update`)}
	}
	_spec.Node.ID.Value = id
	if fields := stuo.fields; len(fields) > 0 {
		_spec.Node.Columns = make([]string, 0, len(fields))
		_spec.Node.Columns = append(_spec.Node.Columns, smstemplate.FieldID)
		for _, f := range fields {
			if !smstemplate.ValidColumn(f) {
				return nil, &ValidationError{Name: f, err: fmt.Errorf("ent: invalid field %q for query", f)}
			}
			if f != smstemplate.FieldID {
				_spec.Node.Columns = append(_spec.Node.Columns, f)
			}
		}
	}
	if ps := stuo.mutation.predicates; len(ps) > 0 {
		_spec.Predicate = func(selector *sql.Selector) {
			for i := range ps {
				ps[i](selector)
			}
		}
	}
	if value, ok := stuo.mutation.UpdatedAt(); ok {
		_spec.SetField(smstemplate.FieldUpdatedAt, field.TypeTime, value)
	}
	if value, ok := stuo.mutation.DeletedAt(); ok {
		_spec.SetField(smstemplate.FieldDeletedAt, field.TypeTime, value)
	}
	if stuo.mutation.DeletedAtCleared() {
		_spec.ClearField(smstemplate.FieldDeletedAt, field.TypeTime)
	}
	if value, ok := stuo.mutation.Name(); ok {
		_spec.SetField(smstemplate.FieldName, field.TypeString, value)
	}
	if value, ok := stuo.mutation.Content(); ok {
		_spec.SetField(smstemplate.FieldContent, field.TypeString, value)
	}
	if value, ok := stuo.mutation.GetType(); ok {
		_spec.SetField(smstemplate.FieldType, field.TypeString, value)
	}
	if value, ok := stuo.mutation.Active(); ok {
		_spec.SetField(smstemplate.FieldActive, field.TypeBool, value)
	}
	if value, ok := stuo.mutation.System(); ok {
		_spec.SetField(smstemplate.FieldSystem, field.TypeBool, value)
	}
	if value, ok := stuo.mutation.Locale(); ok {
		_spec.SetField(smstemplate.FieldLocale, field.TypeString, value)
	}
	if value, ok := stuo.mutation.MaxLength(); ok {
		_spec.SetField(smstemplate.FieldMaxLength, field.TypeInt, value)
	}
	if value, ok := stuo.mutation.AddedMaxLength(); ok {
		_spec.AddField(smstemplate.FieldMaxLength, field.TypeInt, value)
	}
	if value, ok := stuo.mutation.MessageType(); ok {
		_spec.SetField(smstemplate.FieldMessageType, field.TypeString, value)
	}
	if value, ok := stuo.mutation.EstimatedSegments(); ok {
		_spec.SetField(smstemplate.FieldEstimatedSegments, field.TypeInt, value)
	}
	if value, ok := stuo.mutation.AddedEstimatedSegments(); ok {
		_spec.AddField(smstemplate.FieldEstimatedSegments, field.TypeInt, value)
	}
	if stuo.mutation.EstimatedSegmentsCleared() {
		_spec.ClearField(smstemplate.FieldEstimatedSegments, field.TypeInt)
	}
	if value, ok := stuo.mutation.EstimatedCost(); ok {
		_spec.SetField(smstemplate.FieldEstimatedCost, field.TypeFloat64, value)
	}
	if value, ok := stuo.mutation.AddedEstimatedCost(); ok {
		_spec.AddField(smstemplate.FieldEstimatedCost, field.TypeFloat64, value)
	}
	if stuo.mutation.EstimatedCostCleared() {
		_spec.ClearField(smstemplate.FieldEstimatedCost, field.TypeFloat64)
	}
	if value, ok := stuo.mutation.Currency(); ok {
		_spec.SetField(smstemplate.FieldCurrency, field.TypeString, value)
	}
	if stuo.mutation.CurrencyCleared() {
		_spec.ClearField(smstemplate.FieldCurrency, field.TypeString)
	}
	if value, ok := stuo.mutation.Variables(); ok {
		_spec.SetField(smstemplate.FieldVariables, field.TypeJSON, value)
	}
	if value, ok := stuo.mutation.AppendedVariables(); ok {
		_spec.AddModifier(func(u *sql.UpdateBuilder) {
			sqljson.Append(u, smstemplate.FieldVariables, value)
		})
	}
	if stuo.mutation.VariablesCleared() {
		_spec.ClearField(smstemplate.FieldVariables, field.TypeJSON)
	}
	if value, ok := stuo.mutation.Metadata(); ok {
		_spec.SetField(smstemplate.FieldMetadata, field.TypeJSON, value)
	}
	if stuo.mutation.MetadataCleared() {
		_spec.ClearField(smstemplate.FieldMetadata, field.TypeJSON)
	}
	if value, ok := stuo.mutation.LastUsedAt(); ok {
		_spec.SetField(smstemplate.FieldLastUsedAt, field.TypeTime, value)
	}
	if stuo.mutation.LastUsedAtCleared() {
		_spec.ClearField(smstemplate.FieldLastUsedAt, field.TypeTime)
	}
	if value, ok := stuo.mutation.UsageCount(); ok {
		_spec.SetField(smstemplate.FieldUsageCount, field.TypeInt, value)
	}
	if value, ok := stuo.mutation.AddedUsageCount(); ok {
		_spec.AddField(smstemplate.FieldUsageCount, field.TypeInt, value)
	}
	if stuo.mutation.OrganizationCleared() {
		edge := &sqlgraph.EdgeSpec{
			Rel:     sqlgraph.M2O,
			Inverse: true,
			Table:   smstemplate.OrganizationTable,
			Columns: []string{smstemplate.OrganizationColumn},
			Bidi:    false,
			Target: &sqlgraph.EdgeTarget{
				IDSpec: sqlgraph.NewFieldSpec(organization.FieldID, field.TypeString),
			},
		}
		_spec.Edges.Clear = append(_spec.Edges.Clear, edge)
	}
	if nodes := stuo.mutation.OrganizationIDs(); len(nodes) > 0 {
		edge := &sqlgraph.EdgeSpec{
			Rel:     sqlgraph.M2O,
			Inverse: true,
			Table:   smstemplate.OrganizationTable,
			Columns: []string{smstemplate.OrganizationColumn},
			Bidi:    false,
			Target: &sqlgraph.EdgeTarget{
				IDSpec: sqlgraph.NewFieldSpec(organization.FieldID, field.TypeString),
			},
		}
		for _, k := range nodes {
			edge.Target.Nodes = append(edge.Target.Nodes, k)
		}
		_spec.Edges.Add = append(_spec.Edges.Add, edge)
	}
	_spec.AddModifiers(stuo.modifiers...)
	_node = &SMSTemplate{config: stuo.config}
	_spec.Assign = _node.assignValues
	_spec.ScanValues = _node.scanValues
	if err = sqlgraph.UpdateNode(ctx, stuo.driver, _spec); err != nil {
		if _, ok := err.(*sqlgraph.NotFoundError); ok {
			err = &NotFoundError{smstemplate.Label}
		} else if sqlgraph.IsConstraintError(err) {
			err = &ConstraintError{msg: err.Error(), wrap: err}
		}
		return nil, err
	}
	stuo.mutation.done = true
	return _node, nil
}
