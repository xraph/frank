// Copyright 2023-present XRaph LLC. All rights reserved.
// This source code is licensed under the XRaph LLC license found
// in the LICENSE file in the root directory of this source tree.
// Code generated by ent, DO NOT EDIT.

package oauthscope

import (
	"time"

	"entgo.io/ent/dialect/sql"
	"entgo.io/ent/dialect/sql/sqlgraph"
	"github.com/rs/xid"
	"github.com/xraph/frank/ent/predicate"
)

// ID filters vertices based on their ID field.
func ID(id xid.ID) predicate.OAuthScope {
	return predicate.OAuthScope(sql.FieldEQ(FieldID, id))
}

// IDEQ applies the EQ predicate on the ID field.
func IDEQ(id xid.ID) predicate.OAuthScope {
	return predicate.OAuthScope(sql.FieldEQ(FieldID, id))
}

// IDNEQ applies the NEQ predicate on the ID field.
func IDNEQ(id xid.ID) predicate.OAuthScope {
	return predicate.OAuthScope(sql.FieldNEQ(FieldID, id))
}

// IDIn applies the In predicate on the ID field.
func IDIn(ids ...xid.ID) predicate.OAuthScope {
	return predicate.OAuthScope(sql.FieldIn(FieldID, ids...))
}

// IDNotIn applies the NotIn predicate on the ID field.
func IDNotIn(ids ...xid.ID) predicate.OAuthScope {
	return predicate.OAuthScope(sql.FieldNotIn(FieldID, ids...))
}

// IDGT applies the GT predicate on the ID field.
func IDGT(id xid.ID) predicate.OAuthScope {
	return predicate.OAuthScope(sql.FieldGT(FieldID, id))
}

// IDGTE applies the GTE predicate on the ID field.
func IDGTE(id xid.ID) predicate.OAuthScope {
	return predicate.OAuthScope(sql.FieldGTE(FieldID, id))
}

// IDLT applies the LT predicate on the ID field.
func IDLT(id xid.ID) predicate.OAuthScope {
	return predicate.OAuthScope(sql.FieldLT(FieldID, id))
}

// IDLTE applies the LTE predicate on the ID field.
func IDLTE(id xid.ID) predicate.OAuthScope {
	return predicate.OAuthScope(sql.FieldLTE(FieldID, id))
}

// CreatedAt applies equality check predicate on the "created_at" field. It's identical to CreatedAtEQ.
func CreatedAt(v time.Time) predicate.OAuthScope {
	return predicate.OAuthScope(sql.FieldEQ(FieldCreatedAt, v))
}

// UpdatedAt applies equality check predicate on the "updated_at" field. It's identical to UpdatedAtEQ.
func UpdatedAt(v time.Time) predicate.OAuthScope {
	return predicate.OAuthScope(sql.FieldEQ(FieldUpdatedAt, v))
}

// DeletedAt applies equality check predicate on the "deleted_at" field. It's identical to DeletedAtEQ.
func DeletedAt(v time.Time) predicate.OAuthScope {
	return predicate.OAuthScope(sql.FieldEQ(FieldDeletedAt, v))
}

// Name applies equality check predicate on the "name" field. It's identical to NameEQ.
func Name(v string) predicate.OAuthScope {
	return predicate.OAuthScope(sql.FieldEQ(FieldName, v))
}

// Description applies equality check predicate on the "description" field. It's identical to DescriptionEQ.
func Description(v string) predicate.OAuthScope {
	return predicate.OAuthScope(sql.FieldEQ(FieldDescription, v))
}

// DefaultScope applies equality check predicate on the "default_scope" field. It's identical to DefaultScopeEQ.
func DefaultScope(v bool) predicate.OAuthScope {
	return predicate.OAuthScope(sql.FieldEQ(FieldDefaultScope, v))
}

// Public applies equality check predicate on the "public" field. It's identical to PublicEQ.
func Public(v bool) predicate.OAuthScope {
	return predicate.OAuthScope(sql.FieldEQ(FieldPublic, v))
}

// CreatedAtEQ applies the EQ predicate on the "created_at" field.
func CreatedAtEQ(v time.Time) predicate.OAuthScope {
	return predicate.OAuthScope(sql.FieldEQ(FieldCreatedAt, v))
}

// CreatedAtNEQ applies the NEQ predicate on the "created_at" field.
func CreatedAtNEQ(v time.Time) predicate.OAuthScope {
	return predicate.OAuthScope(sql.FieldNEQ(FieldCreatedAt, v))
}

// CreatedAtIn applies the In predicate on the "created_at" field.
func CreatedAtIn(vs ...time.Time) predicate.OAuthScope {
	return predicate.OAuthScope(sql.FieldIn(FieldCreatedAt, vs...))
}

// CreatedAtNotIn applies the NotIn predicate on the "created_at" field.
func CreatedAtNotIn(vs ...time.Time) predicate.OAuthScope {
	return predicate.OAuthScope(sql.FieldNotIn(FieldCreatedAt, vs...))
}

// CreatedAtGT applies the GT predicate on the "created_at" field.
func CreatedAtGT(v time.Time) predicate.OAuthScope {
	return predicate.OAuthScope(sql.FieldGT(FieldCreatedAt, v))
}

// CreatedAtGTE applies the GTE predicate on the "created_at" field.
func CreatedAtGTE(v time.Time) predicate.OAuthScope {
	return predicate.OAuthScope(sql.FieldGTE(FieldCreatedAt, v))
}

// CreatedAtLT applies the LT predicate on the "created_at" field.
func CreatedAtLT(v time.Time) predicate.OAuthScope {
	return predicate.OAuthScope(sql.FieldLT(FieldCreatedAt, v))
}

// CreatedAtLTE applies the LTE predicate on the "created_at" field.
func CreatedAtLTE(v time.Time) predicate.OAuthScope {
	return predicate.OAuthScope(sql.FieldLTE(FieldCreatedAt, v))
}

// UpdatedAtEQ applies the EQ predicate on the "updated_at" field.
func UpdatedAtEQ(v time.Time) predicate.OAuthScope {
	return predicate.OAuthScope(sql.FieldEQ(FieldUpdatedAt, v))
}

// UpdatedAtNEQ applies the NEQ predicate on the "updated_at" field.
func UpdatedAtNEQ(v time.Time) predicate.OAuthScope {
	return predicate.OAuthScope(sql.FieldNEQ(FieldUpdatedAt, v))
}

// UpdatedAtIn applies the In predicate on the "updated_at" field.
func UpdatedAtIn(vs ...time.Time) predicate.OAuthScope {
	return predicate.OAuthScope(sql.FieldIn(FieldUpdatedAt, vs...))
}

// UpdatedAtNotIn applies the NotIn predicate on the "updated_at" field.
func UpdatedAtNotIn(vs ...time.Time) predicate.OAuthScope {
	return predicate.OAuthScope(sql.FieldNotIn(FieldUpdatedAt, vs...))
}

// UpdatedAtGT applies the GT predicate on the "updated_at" field.
func UpdatedAtGT(v time.Time) predicate.OAuthScope {
	return predicate.OAuthScope(sql.FieldGT(FieldUpdatedAt, v))
}

// UpdatedAtGTE applies the GTE predicate on the "updated_at" field.
func UpdatedAtGTE(v time.Time) predicate.OAuthScope {
	return predicate.OAuthScope(sql.FieldGTE(FieldUpdatedAt, v))
}

// UpdatedAtLT applies the LT predicate on the "updated_at" field.
func UpdatedAtLT(v time.Time) predicate.OAuthScope {
	return predicate.OAuthScope(sql.FieldLT(FieldUpdatedAt, v))
}

// UpdatedAtLTE applies the LTE predicate on the "updated_at" field.
func UpdatedAtLTE(v time.Time) predicate.OAuthScope {
	return predicate.OAuthScope(sql.FieldLTE(FieldUpdatedAt, v))
}

// DeletedAtEQ applies the EQ predicate on the "deleted_at" field.
func DeletedAtEQ(v time.Time) predicate.OAuthScope {
	return predicate.OAuthScope(sql.FieldEQ(FieldDeletedAt, v))
}

// DeletedAtNEQ applies the NEQ predicate on the "deleted_at" field.
func DeletedAtNEQ(v time.Time) predicate.OAuthScope {
	return predicate.OAuthScope(sql.FieldNEQ(FieldDeletedAt, v))
}

// DeletedAtIn applies the In predicate on the "deleted_at" field.
func DeletedAtIn(vs ...time.Time) predicate.OAuthScope {
	return predicate.OAuthScope(sql.FieldIn(FieldDeletedAt, vs...))
}

// DeletedAtNotIn applies the NotIn predicate on the "deleted_at" field.
func DeletedAtNotIn(vs ...time.Time) predicate.OAuthScope {
	return predicate.OAuthScope(sql.FieldNotIn(FieldDeletedAt, vs...))
}

// DeletedAtGT applies the GT predicate on the "deleted_at" field.
func DeletedAtGT(v time.Time) predicate.OAuthScope {
	return predicate.OAuthScope(sql.FieldGT(FieldDeletedAt, v))
}

// DeletedAtGTE applies the GTE predicate on the "deleted_at" field.
func DeletedAtGTE(v time.Time) predicate.OAuthScope {
	return predicate.OAuthScope(sql.FieldGTE(FieldDeletedAt, v))
}

// DeletedAtLT applies the LT predicate on the "deleted_at" field.
func DeletedAtLT(v time.Time) predicate.OAuthScope {
	return predicate.OAuthScope(sql.FieldLT(FieldDeletedAt, v))
}

// DeletedAtLTE applies the LTE predicate on the "deleted_at" field.
func DeletedAtLTE(v time.Time) predicate.OAuthScope {
	return predicate.OAuthScope(sql.FieldLTE(FieldDeletedAt, v))
}

// DeletedAtIsNil applies the IsNil predicate on the "deleted_at" field.
func DeletedAtIsNil() predicate.OAuthScope {
	return predicate.OAuthScope(sql.FieldIsNull(FieldDeletedAt))
}

// DeletedAtNotNil applies the NotNil predicate on the "deleted_at" field.
func DeletedAtNotNil() predicate.OAuthScope {
	return predicate.OAuthScope(sql.FieldNotNull(FieldDeletedAt))
}

// NameEQ applies the EQ predicate on the "name" field.
func NameEQ(v string) predicate.OAuthScope {
	return predicate.OAuthScope(sql.FieldEQ(FieldName, v))
}

// NameNEQ applies the NEQ predicate on the "name" field.
func NameNEQ(v string) predicate.OAuthScope {
	return predicate.OAuthScope(sql.FieldNEQ(FieldName, v))
}

// NameIn applies the In predicate on the "name" field.
func NameIn(vs ...string) predicate.OAuthScope {
	return predicate.OAuthScope(sql.FieldIn(FieldName, vs...))
}

// NameNotIn applies the NotIn predicate on the "name" field.
func NameNotIn(vs ...string) predicate.OAuthScope {
	return predicate.OAuthScope(sql.FieldNotIn(FieldName, vs...))
}

// NameGT applies the GT predicate on the "name" field.
func NameGT(v string) predicate.OAuthScope {
	return predicate.OAuthScope(sql.FieldGT(FieldName, v))
}

// NameGTE applies the GTE predicate on the "name" field.
func NameGTE(v string) predicate.OAuthScope {
	return predicate.OAuthScope(sql.FieldGTE(FieldName, v))
}

// NameLT applies the LT predicate on the "name" field.
func NameLT(v string) predicate.OAuthScope {
	return predicate.OAuthScope(sql.FieldLT(FieldName, v))
}

// NameLTE applies the LTE predicate on the "name" field.
func NameLTE(v string) predicate.OAuthScope {
	return predicate.OAuthScope(sql.FieldLTE(FieldName, v))
}

// NameContains applies the Contains predicate on the "name" field.
func NameContains(v string) predicate.OAuthScope {
	return predicate.OAuthScope(sql.FieldContains(FieldName, v))
}

// NameHasPrefix applies the HasPrefix predicate on the "name" field.
func NameHasPrefix(v string) predicate.OAuthScope {
	return predicate.OAuthScope(sql.FieldHasPrefix(FieldName, v))
}

// NameHasSuffix applies the HasSuffix predicate on the "name" field.
func NameHasSuffix(v string) predicate.OAuthScope {
	return predicate.OAuthScope(sql.FieldHasSuffix(FieldName, v))
}

// NameEqualFold applies the EqualFold predicate on the "name" field.
func NameEqualFold(v string) predicate.OAuthScope {
	return predicate.OAuthScope(sql.FieldEqualFold(FieldName, v))
}

// NameContainsFold applies the ContainsFold predicate on the "name" field.
func NameContainsFold(v string) predicate.OAuthScope {
	return predicate.OAuthScope(sql.FieldContainsFold(FieldName, v))
}

// DescriptionEQ applies the EQ predicate on the "description" field.
func DescriptionEQ(v string) predicate.OAuthScope {
	return predicate.OAuthScope(sql.FieldEQ(FieldDescription, v))
}

// DescriptionNEQ applies the NEQ predicate on the "description" field.
func DescriptionNEQ(v string) predicate.OAuthScope {
	return predicate.OAuthScope(sql.FieldNEQ(FieldDescription, v))
}

// DescriptionIn applies the In predicate on the "description" field.
func DescriptionIn(vs ...string) predicate.OAuthScope {
	return predicate.OAuthScope(sql.FieldIn(FieldDescription, vs...))
}

// DescriptionNotIn applies the NotIn predicate on the "description" field.
func DescriptionNotIn(vs ...string) predicate.OAuthScope {
	return predicate.OAuthScope(sql.FieldNotIn(FieldDescription, vs...))
}

// DescriptionGT applies the GT predicate on the "description" field.
func DescriptionGT(v string) predicate.OAuthScope {
	return predicate.OAuthScope(sql.FieldGT(FieldDescription, v))
}

// DescriptionGTE applies the GTE predicate on the "description" field.
func DescriptionGTE(v string) predicate.OAuthScope {
	return predicate.OAuthScope(sql.FieldGTE(FieldDescription, v))
}

// DescriptionLT applies the LT predicate on the "description" field.
func DescriptionLT(v string) predicate.OAuthScope {
	return predicate.OAuthScope(sql.FieldLT(FieldDescription, v))
}

// DescriptionLTE applies the LTE predicate on the "description" field.
func DescriptionLTE(v string) predicate.OAuthScope {
	return predicate.OAuthScope(sql.FieldLTE(FieldDescription, v))
}

// DescriptionContains applies the Contains predicate on the "description" field.
func DescriptionContains(v string) predicate.OAuthScope {
	return predicate.OAuthScope(sql.FieldContains(FieldDescription, v))
}

// DescriptionHasPrefix applies the HasPrefix predicate on the "description" field.
func DescriptionHasPrefix(v string) predicate.OAuthScope {
	return predicate.OAuthScope(sql.FieldHasPrefix(FieldDescription, v))
}

// DescriptionHasSuffix applies the HasSuffix predicate on the "description" field.
func DescriptionHasSuffix(v string) predicate.OAuthScope {
	return predicate.OAuthScope(sql.FieldHasSuffix(FieldDescription, v))
}

// DescriptionEqualFold applies the EqualFold predicate on the "description" field.
func DescriptionEqualFold(v string) predicate.OAuthScope {
	return predicate.OAuthScope(sql.FieldEqualFold(FieldDescription, v))
}

// DescriptionContainsFold applies the ContainsFold predicate on the "description" field.
func DescriptionContainsFold(v string) predicate.OAuthScope {
	return predicate.OAuthScope(sql.FieldContainsFold(FieldDescription, v))
}

// DefaultScopeEQ applies the EQ predicate on the "default_scope" field.
func DefaultScopeEQ(v bool) predicate.OAuthScope {
	return predicate.OAuthScope(sql.FieldEQ(FieldDefaultScope, v))
}

// DefaultScopeNEQ applies the NEQ predicate on the "default_scope" field.
func DefaultScopeNEQ(v bool) predicate.OAuthScope {
	return predicate.OAuthScope(sql.FieldNEQ(FieldDefaultScope, v))
}

// PublicEQ applies the EQ predicate on the "public" field.
func PublicEQ(v bool) predicate.OAuthScope {
	return predicate.OAuthScope(sql.FieldEQ(FieldPublic, v))
}

// PublicNEQ applies the NEQ predicate on the "public" field.
func PublicNEQ(v bool) predicate.OAuthScope {
	return predicate.OAuthScope(sql.FieldNEQ(FieldPublic, v))
}

// HasClients applies the HasEdge predicate on the "clients" edge.
func HasClients() predicate.OAuthScope {
	return predicate.OAuthScope(func(s *sql.Selector) {
		step := sqlgraph.NewStep(
			sqlgraph.From(Table, FieldID),
			sqlgraph.Edge(sqlgraph.M2M, true, ClientsTable, ClientsPrimaryKey...),
		)
		sqlgraph.HasNeighbors(s, step)
	})
}

// HasClientsWith applies the HasEdge predicate on the "clients" edge with a given conditions (other predicates).
func HasClientsWith(preds ...predicate.OAuthClient) predicate.OAuthScope {
	return predicate.OAuthScope(func(s *sql.Selector) {
		step := newClientsStep()
		sqlgraph.HasNeighborsWith(s, step, func(s *sql.Selector) {
			for _, p := range preds {
				p(s)
			}
		})
	})
}

// HasTokens applies the HasEdge predicate on the "tokens" edge.
func HasTokens() predicate.OAuthScope {
	return predicate.OAuthScope(func(s *sql.Selector) {
		step := sqlgraph.NewStep(
			sqlgraph.From(Table, FieldID),
			sqlgraph.Edge(sqlgraph.M2M, true, TokensTable, TokensPrimaryKey...),
		)
		sqlgraph.HasNeighbors(s, step)
	})
}

// HasTokensWith applies the HasEdge predicate on the "tokens" edge with a given conditions (other predicates).
func HasTokensWith(preds ...predicate.OAuthToken) predicate.OAuthScope {
	return predicate.OAuthScope(func(s *sql.Selector) {
		step := newTokensStep()
		sqlgraph.HasNeighborsWith(s, step, func(s *sql.Selector) {
			for _, p := range preds {
				p(s)
			}
		})
	})
}

// HasAuthorizations applies the HasEdge predicate on the "authorizations" edge.
func HasAuthorizations() predicate.OAuthScope {
	return predicate.OAuthScope(func(s *sql.Selector) {
		step := sqlgraph.NewStep(
			sqlgraph.From(Table, FieldID),
			sqlgraph.Edge(sqlgraph.M2M, true, AuthorizationsTable, AuthorizationsPrimaryKey...),
		)
		sqlgraph.HasNeighbors(s, step)
	})
}

// HasAuthorizationsWith applies the HasEdge predicate on the "authorizations" edge with a given conditions (other predicates).
func HasAuthorizationsWith(preds ...predicate.OAuthAuthorization) predicate.OAuthScope {
	return predicate.OAuthScope(func(s *sql.Selector) {
		step := newAuthorizationsStep()
		sqlgraph.HasNeighborsWith(s, step, func(s *sql.Selector) {
			for _, p := range preds {
				p(s)
			}
		})
	})
}

// And groups predicates with the AND operator between them.
func And(predicates ...predicate.OAuthScope) predicate.OAuthScope {
	return predicate.OAuthScope(sql.AndPredicates(predicates...))
}

// Or groups predicates with the OR operator between them.
func Or(predicates ...predicate.OAuthScope) predicate.OAuthScope {
	return predicate.OAuthScope(sql.OrPredicates(predicates...))
}

// Not applies the not operator on the given predicate.
func Not(p predicate.OAuthScope) predicate.OAuthScope {
	return predicate.OAuthScope(sql.NotPredicates(p))
}
