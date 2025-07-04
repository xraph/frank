// Copyright 2023-present XRaph LLC. All rights reserved.
// This source code is licensed under the XRaph LLC license found
// in the LICENSE file in the root directory of this source tree.
// Code generated by ent, DO NOT EDIT.

package ent

import (
	"context"

	"entgo.io/ent/dialect/sql"
	"entgo.io/ent/dialect/sql/sqlgraph"
	"entgo.io/ent/schema/field"
	"github.com/xraph/frank/ent/apikeyactivity"
	"github.com/xraph/frank/ent/predicate"
)

// ApiKeyActivityDelete is the builder for deleting a ApiKeyActivity entity.
type ApiKeyActivityDelete struct {
	config
	hooks    []Hook
	mutation *ApiKeyActivityMutation
}

// Where appends a list predicates to the ApiKeyActivityDelete builder.
func (akad *ApiKeyActivityDelete) Where(ps ...predicate.ApiKeyActivity) *ApiKeyActivityDelete {
	akad.mutation.Where(ps...)
	return akad
}

// Exec executes the deletion query and returns how many vertices were deleted.
func (akad *ApiKeyActivityDelete) Exec(ctx context.Context) (int, error) {
	return withHooks(ctx, akad.sqlExec, akad.mutation, akad.hooks)
}

// ExecX is like Exec, but panics if an error occurs.
func (akad *ApiKeyActivityDelete) ExecX(ctx context.Context) int {
	n, err := akad.Exec(ctx)
	if err != nil {
		panic(err)
	}
	return n
}

func (akad *ApiKeyActivityDelete) sqlExec(ctx context.Context) (int, error) {
	_spec := sqlgraph.NewDeleteSpec(apikeyactivity.Table, sqlgraph.NewFieldSpec(apikeyactivity.FieldID, field.TypeString))
	if ps := akad.mutation.predicates; len(ps) > 0 {
		_spec.Predicate = func(selector *sql.Selector) {
			for i := range ps {
				ps[i](selector)
			}
		}
	}
	affected, err := sqlgraph.DeleteNodes(ctx, akad.driver, _spec)
	if err != nil && sqlgraph.IsConstraintError(err) {
		err = &ConstraintError{msg: err.Error(), wrap: err}
	}
	akad.mutation.done = true
	return affected, err
}

// ApiKeyActivityDeleteOne is the builder for deleting a single ApiKeyActivity entity.
type ApiKeyActivityDeleteOne struct {
	akad *ApiKeyActivityDelete
}

// Where appends a list predicates to the ApiKeyActivityDelete builder.
func (akado *ApiKeyActivityDeleteOne) Where(ps ...predicate.ApiKeyActivity) *ApiKeyActivityDeleteOne {
	akado.akad.mutation.Where(ps...)
	return akado
}

// Exec executes the deletion query.
func (akado *ApiKeyActivityDeleteOne) Exec(ctx context.Context) error {
	n, err := akado.akad.Exec(ctx)
	switch {
	case err != nil:
		return err
	case n == 0:
		return &NotFoundError{apikeyactivity.Label}
	default:
		return nil
	}
}

// ExecX is like Exec, but panics if an error occurs.
func (akado *ApiKeyActivityDeleteOne) ExecX(ctx context.Context) {
	if err := akado.Exec(ctx); err != nil {
		panic(err)
	}
}
