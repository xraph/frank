// Copyright 2023-present XRaph LLC. All rights reserved.
// This source code is licensed under the XRaph LLC license found
// in the LICENSE file in the root directory of this source tree.
// Code generated by ent, DO NOT EDIT.

package ent

import (
	"context"
	"database/sql/driver"
	"fmt"
	"math"

	"entgo.io/ent"
	"entgo.io/ent/dialect"
	"entgo.io/ent/dialect/sql"
	"entgo.io/ent/dialect/sql/sqlgraph"
	"entgo.io/ent/schema/field"
	"github.com/xraph/frank/ent/featureflag"
	"github.com/xraph/frank/ent/organizationfeature"
	"github.com/xraph/frank/ent/predicate"
	"github.com/rs/xid"
)

// FeatureFlagQuery is the builder for querying FeatureFlag entities.
type FeatureFlagQuery struct {
	config
	ctx                           *QueryContext
	order                         []featureflag.OrderOption
	inters                        []Interceptor
	predicates                    []predicate.FeatureFlag
	withOrganizationFeatures      *OrganizationFeatureQuery
	modifiers                     []func(*sql.Selector)
	withNamedOrganizationFeatures map[string]*OrganizationFeatureQuery
	// intermediate query (i.e. traversal path).
	sql  *sql.Selector
	path func(context.Context) (*sql.Selector, error)
}

// Where adds a new predicate for the FeatureFlagQuery builder.
func (ffq *FeatureFlagQuery) Where(ps ...predicate.FeatureFlag) *FeatureFlagQuery {
	ffq.predicates = append(ffq.predicates, ps...)
	return ffq
}

// Limit the number of records to be returned by this query.
func (ffq *FeatureFlagQuery) Limit(limit int) *FeatureFlagQuery {
	ffq.ctx.Limit = &limit
	return ffq
}

// Offset to start from.
func (ffq *FeatureFlagQuery) Offset(offset int) *FeatureFlagQuery {
	ffq.ctx.Offset = &offset
	return ffq
}

// Unique configures the query builder to filter duplicate records on query.
// By default, unique is set to true, and can be disabled using this method.
func (ffq *FeatureFlagQuery) Unique(unique bool) *FeatureFlagQuery {
	ffq.ctx.Unique = &unique
	return ffq
}

// Order specifies how the records should be ordered.
func (ffq *FeatureFlagQuery) Order(o ...featureflag.OrderOption) *FeatureFlagQuery {
	ffq.order = append(ffq.order, o...)
	return ffq
}

// QueryOrganizationFeatures chains the current query on the "organization_features" edge.
func (ffq *FeatureFlagQuery) QueryOrganizationFeatures() *OrganizationFeatureQuery {
	query := (&OrganizationFeatureClient{config: ffq.config}).Query()
	query.path = func(ctx context.Context) (fromU *sql.Selector, err error) {
		if err := ffq.prepareQuery(ctx); err != nil {
			return nil, err
		}
		selector := ffq.sqlQuery(ctx)
		if err := selector.Err(); err != nil {
			return nil, err
		}
		step := sqlgraph.NewStep(
			sqlgraph.From(featureflag.Table, featureflag.FieldID, selector),
			sqlgraph.To(organizationfeature.Table, organizationfeature.FieldID),
			sqlgraph.Edge(sqlgraph.O2M, false, featureflag.OrganizationFeaturesTable, featureflag.OrganizationFeaturesColumn),
		)
		fromU = sqlgraph.SetNeighbors(ffq.driver.Dialect(), step)
		return fromU, nil
	}
	return query
}

// First returns the first FeatureFlag entity from the query.
// Returns a *NotFoundError when no FeatureFlag was found.
func (ffq *FeatureFlagQuery) First(ctx context.Context) (*FeatureFlag, error) {
	nodes, err := ffq.Limit(1).All(setContextOp(ctx, ffq.ctx, ent.OpQueryFirst))
	if err != nil {
		return nil, err
	}
	if len(nodes) == 0 {
		return nil, &NotFoundError{featureflag.Label}
	}
	return nodes[0], nil
}

// FirstX is like First, but panics if an error occurs.
func (ffq *FeatureFlagQuery) FirstX(ctx context.Context) *FeatureFlag {
	node, err := ffq.First(ctx)
	if err != nil && !IsNotFound(err) {
		panic(err)
	}
	return node
}

// FirstID returns the first FeatureFlag ID from the query.
// Returns a *NotFoundError when no FeatureFlag ID was found.
func (ffq *FeatureFlagQuery) FirstID(ctx context.Context) (id xid.ID, err error) {
	var ids []xid.ID
	if ids, err = ffq.Limit(1).IDs(setContextOp(ctx, ffq.ctx, ent.OpQueryFirstID)); err != nil {
		return
	}
	if len(ids) == 0 {
		err = &NotFoundError{featureflag.Label}
		return
	}
	return ids[0], nil
}

// FirstIDX is like FirstID, but panics if an error occurs.
func (ffq *FeatureFlagQuery) FirstIDX(ctx context.Context) xid.ID {
	id, err := ffq.FirstID(ctx)
	if err != nil && !IsNotFound(err) {
		panic(err)
	}
	return id
}

// Only returns a single FeatureFlag entity found by the query, ensuring it only returns one.
// Returns a *NotSingularError when more than one FeatureFlag entity is found.
// Returns a *NotFoundError when no FeatureFlag entities are found.
func (ffq *FeatureFlagQuery) Only(ctx context.Context) (*FeatureFlag, error) {
	nodes, err := ffq.Limit(2).All(setContextOp(ctx, ffq.ctx, ent.OpQueryOnly))
	if err != nil {
		return nil, err
	}
	switch len(nodes) {
	case 1:
		return nodes[0], nil
	case 0:
		return nil, &NotFoundError{featureflag.Label}
	default:
		return nil, &NotSingularError{featureflag.Label}
	}
}

// OnlyX is like Only, but panics if an error occurs.
func (ffq *FeatureFlagQuery) OnlyX(ctx context.Context) *FeatureFlag {
	node, err := ffq.Only(ctx)
	if err != nil {
		panic(err)
	}
	return node
}

// OnlyID is like Only, but returns the only FeatureFlag ID in the query.
// Returns a *NotSingularError when more than one FeatureFlag ID is found.
// Returns a *NotFoundError when no entities are found.
func (ffq *FeatureFlagQuery) OnlyID(ctx context.Context) (id xid.ID, err error) {
	var ids []xid.ID
	if ids, err = ffq.Limit(2).IDs(setContextOp(ctx, ffq.ctx, ent.OpQueryOnlyID)); err != nil {
		return
	}
	switch len(ids) {
	case 1:
		id = ids[0]
	case 0:
		err = &NotFoundError{featureflag.Label}
	default:
		err = &NotSingularError{featureflag.Label}
	}
	return
}

// OnlyIDX is like OnlyID, but panics if an error occurs.
func (ffq *FeatureFlagQuery) OnlyIDX(ctx context.Context) xid.ID {
	id, err := ffq.OnlyID(ctx)
	if err != nil {
		panic(err)
	}
	return id
}

// All executes the query and returns a list of FeatureFlags.
func (ffq *FeatureFlagQuery) All(ctx context.Context) ([]*FeatureFlag, error) {
	ctx = setContextOp(ctx, ffq.ctx, ent.OpQueryAll)
	if err := ffq.prepareQuery(ctx); err != nil {
		return nil, err
	}
	qr := querierAll[[]*FeatureFlag, *FeatureFlagQuery]()
	return withInterceptors[[]*FeatureFlag](ctx, ffq, qr, ffq.inters)
}

// AllX is like All, but panics if an error occurs.
func (ffq *FeatureFlagQuery) AllX(ctx context.Context) []*FeatureFlag {
	nodes, err := ffq.All(ctx)
	if err != nil {
		panic(err)
	}
	return nodes
}

// IDs executes the query and returns a list of FeatureFlag IDs.
func (ffq *FeatureFlagQuery) IDs(ctx context.Context) (ids []xid.ID, err error) {
	if ffq.ctx.Unique == nil && ffq.path != nil {
		ffq.Unique(true)
	}
	ctx = setContextOp(ctx, ffq.ctx, ent.OpQueryIDs)
	if err = ffq.Select(featureflag.FieldID).Scan(ctx, &ids); err != nil {
		return nil, err
	}
	return ids, nil
}

// IDsX is like IDs, but panics if an error occurs.
func (ffq *FeatureFlagQuery) IDsX(ctx context.Context) []xid.ID {
	ids, err := ffq.IDs(ctx)
	if err != nil {
		panic(err)
	}
	return ids
}

// Count returns the count of the given query.
func (ffq *FeatureFlagQuery) Count(ctx context.Context) (int, error) {
	ctx = setContextOp(ctx, ffq.ctx, ent.OpQueryCount)
	if err := ffq.prepareQuery(ctx); err != nil {
		return 0, err
	}
	return withInterceptors[int](ctx, ffq, querierCount[*FeatureFlagQuery](), ffq.inters)
}

// CountX is like Count, but panics if an error occurs.
func (ffq *FeatureFlagQuery) CountX(ctx context.Context) int {
	count, err := ffq.Count(ctx)
	if err != nil {
		panic(err)
	}
	return count
}

// Exist returns true if the query has elements in the graph.
func (ffq *FeatureFlagQuery) Exist(ctx context.Context) (bool, error) {
	ctx = setContextOp(ctx, ffq.ctx, ent.OpQueryExist)
	switch _, err := ffq.FirstID(ctx); {
	case IsNotFound(err):
		return false, nil
	case err != nil:
		return false, fmt.Errorf("ent: check existence: %w", err)
	default:
		return true, nil
	}
}

// ExistX is like Exist, but panics if an error occurs.
func (ffq *FeatureFlagQuery) ExistX(ctx context.Context) bool {
	exist, err := ffq.Exist(ctx)
	if err != nil {
		panic(err)
	}
	return exist
}

// Clone returns a duplicate of the FeatureFlagQuery builder, including all associated steps. It can be
// used to prepare common query builders and use them differently after the clone is made.
func (ffq *FeatureFlagQuery) Clone() *FeatureFlagQuery {
	if ffq == nil {
		return nil
	}
	return &FeatureFlagQuery{
		config:                   ffq.config,
		ctx:                      ffq.ctx.Clone(),
		order:                    append([]featureflag.OrderOption{}, ffq.order...),
		inters:                   append([]Interceptor{}, ffq.inters...),
		predicates:               append([]predicate.FeatureFlag{}, ffq.predicates...),
		withOrganizationFeatures: ffq.withOrganizationFeatures.Clone(),
		// clone intermediate query.
		sql:       ffq.sql.Clone(),
		path:      ffq.path,
		modifiers: append([]func(*sql.Selector){}, ffq.modifiers...),
	}
}

// WithOrganizationFeatures tells the query-builder to eager-load the nodes that are connected to
// the "organization_features" edge. The optional arguments are used to configure the query builder of the edge.
func (ffq *FeatureFlagQuery) WithOrganizationFeatures(opts ...func(*OrganizationFeatureQuery)) *FeatureFlagQuery {
	query := (&OrganizationFeatureClient{config: ffq.config}).Query()
	for _, opt := range opts {
		opt(query)
	}
	ffq.withOrganizationFeatures = query
	return ffq
}

// GroupBy is used to group vertices by one or more fields/columns.
// It is often used with aggregate functions, like: count, max, mean, min, sum.
//
// Example:
//
//	var v []struct {
//		CreatedAt time.Time `json:"created_at,omitempty"`
//		Count int `json:"count,omitempty"`
//	}
//
//	client.FeatureFlag.Query().
//		GroupBy(featureflag.FieldCreatedAt).
//		Aggregate(ent.Count()).
//		Scan(ctx, &v)
func (ffq *FeatureFlagQuery) GroupBy(field string, fields ...string) *FeatureFlagGroupBy {
	ffq.ctx.Fields = append([]string{field}, fields...)
	grbuild := &FeatureFlagGroupBy{build: ffq}
	grbuild.flds = &ffq.ctx.Fields
	grbuild.label = featureflag.Label
	grbuild.scan = grbuild.Scan
	return grbuild
}

// Select allows the selection one or more fields/columns for the given query,
// instead of selecting all fields in the entity.
//
// Example:
//
//	var v []struct {
//		CreatedAt time.Time `json:"created_at,omitempty"`
//	}
//
//	client.FeatureFlag.Query().
//		Select(featureflag.FieldCreatedAt).
//		Scan(ctx, &v)
func (ffq *FeatureFlagQuery) Select(fields ...string) *FeatureFlagSelect {
	ffq.ctx.Fields = append(ffq.ctx.Fields, fields...)
	sbuild := &FeatureFlagSelect{FeatureFlagQuery: ffq}
	sbuild.label = featureflag.Label
	sbuild.flds, sbuild.scan = &ffq.ctx.Fields, sbuild.Scan
	return sbuild
}

// Aggregate returns a FeatureFlagSelect configured with the given aggregations.
func (ffq *FeatureFlagQuery) Aggregate(fns ...AggregateFunc) *FeatureFlagSelect {
	return ffq.Select().Aggregate(fns...)
}

func (ffq *FeatureFlagQuery) prepareQuery(ctx context.Context) error {
	for _, inter := range ffq.inters {
		if inter == nil {
			return fmt.Errorf("ent: uninitialized interceptor (forgotten import ent/runtime?)")
		}
		if trv, ok := inter.(Traverser); ok {
			if err := trv.Traverse(ctx, ffq); err != nil {
				return err
			}
		}
	}
	for _, f := range ffq.ctx.Fields {
		if !featureflag.ValidColumn(f) {
			return &ValidationError{Name: f, err: fmt.Errorf("ent: invalid field %q for query", f)}
		}
	}
	if ffq.path != nil {
		prev, err := ffq.path(ctx)
		if err != nil {
			return err
		}
		ffq.sql = prev
	}
	return nil
}

func (ffq *FeatureFlagQuery) sqlAll(ctx context.Context, hooks ...queryHook) ([]*FeatureFlag, error) {
	var (
		nodes       = []*FeatureFlag{}
		_spec       = ffq.querySpec()
		loadedTypes = [1]bool{
			ffq.withOrganizationFeatures != nil,
		}
	)
	_spec.ScanValues = func(columns []string) ([]any, error) {
		return (*FeatureFlag).scanValues(nil, columns)
	}
	_spec.Assign = func(columns []string, values []any) error {
		node := &FeatureFlag{config: ffq.config}
		nodes = append(nodes, node)
		node.Edges.loadedTypes = loadedTypes
		return node.assignValues(columns, values)
	}
	if len(ffq.modifiers) > 0 {
		_spec.Modifiers = ffq.modifiers
	}
	for i := range hooks {
		hooks[i](ctx, _spec)
	}
	if err := sqlgraph.QueryNodes(ctx, ffq.driver, _spec); err != nil {
		return nil, err
	}
	if len(nodes) == 0 {
		return nodes, nil
	}
	if query := ffq.withOrganizationFeatures; query != nil {
		if err := ffq.loadOrganizationFeatures(ctx, query, nodes,
			func(n *FeatureFlag) { n.Edges.OrganizationFeatures = []*OrganizationFeature{} },
			func(n *FeatureFlag, e *OrganizationFeature) {
				n.Edges.OrganizationFeatures = append(n.Edges.OrganizationFeatures, e)
				if !e.Edges.loadedTypes[1] {
					e.Edges.Feature = n
				}
			}); err != nil {
			return nil, err
		}
	}
	for name, query := range ffq.withNamedOrganizationFeatures {
		if err := ffq.loadOrganizationFeatures(ctx, query, nodes,
			func(n *FeatureFlag) { n.appendNamedOrganizationFeatures(name) },
			func(n *FeatureFlag, e *OrganizationFeature) {
				n.appendNamedOrganizationFeatures(name, e)
				if !e.Edges.loadedTypes[1] {
					e.Edges.Feature = n
				}
			}); err != nil {
			return nil, err
		}
	}
	return nodes, nil
}

func (ffq *FeatureFlagQuery) loadOrganizationFeatures(ctx context.Context, query *OrganizationFeatureQuery, nodes []*FeatureFlag, init func(*FeatureFlag), assign func(*FeatureFlag, *OrganizationFeature)) error {
	fks := make([]driver.Value, 0, len(nodes))
	nodeids := make(map[xid.ID]*FeatureFlag)
	for i := range nodes {
		fks = append(fks, nodes[i].ID)
		nodeids[nodes[i].ID] = nodes[i]
		if init != nil {
			init(nodes[i])
		}
	}
	if len(query.ctx.Fields) > 0 {
		query.ctx.AppendFieldOnce(organizationfeature.FieldFeatureID)
	}
	query.Where(predicate.OrganizationFeature(func(s *sql.Selector) {
		s.Where(sql.InValues(s.C(featureflag.OrganizationFeaturesColumn), fks...))
	}))
	neighbors, err := query.All(ctx)
	if err != nil {
		return err
	}
	for _, n := range neighbors {
		fk := n.FeatureID
		node, ok := nodeids[fk]
		if !ok {
			return fmt.Errorf(`unexpected referenced foreign-key "feature_id" returned %v for node %v`, fk, n.ID)
		}
		assign(node, n)
	}
	return nil
}

func (ffq *FeatureFlagQuery) sqlCount(ctx context.Context) (int, error) {
	_spec := ffq.querySpec()
	if len(ffq.modifiers) > 0 {
		_spec.Modifiers = ffq.modifiers
	}
	_spec.Node.Columns = ffq.ctx.Fields
	if len(ffq.ctx.Fields) > 0 {
		_spec.Unique = ffq.ctx.Unique != nil && *ffq.ctx.Unique
	}
	return sqlgraph.CountNodes(ctx, ffq.driver, _spec)
}

func (ffq *FeatureFlagQuery) querySpec() *sqlgraph.QuerySpec {
	_spec := sqlgraph.NewQuerySpec(featureflag.Table, featureflag.Columns, sqlgraph.NewFieldSpec(featureflag.FieldID, field.TypeString))
	_spec.From = ffq.sql
	if unique := ffq.ctx.Unique; unique != nil {
		_spec.Unique = *unique
	} else if ffq.path != nil {
		_spec.Unique = true
	}
	if fields := ffq.ctx.Fields; len(fields) > 0 {
		_spec.Node.Columns = make([]string, 0, len(fields))
		_spec.Node.Columns = append(_spec.Node.Columns, featureflag.FieldID)
		for i := range fields {
			if fields[i] != featureflag.FieldID {
				_spec.Node.Columns = append(_spec.Node.Columns, fields[i])
			}
		}
	}
	if ps := ffq.predicates; len(ps) > 0 {
		_spec.Predicate = func(selector *sql.Selector) {
			for i := range ps {
				ps[i](selector)
			}
		}
	}
	if limit := ffq.ctx.Limit; limit != nil {
		_spec.Limit = *limit
	}
	if offset := ffq.ctx.Offset; offset != nil {
		_spec.Offset = *offset
	}
	if ps := ffq.order; len(ps) > 0 {
		_spec.Order = func(selector *sql.Selector) {
			for i := range ps {
				ps[i](selector)
			}
		}
	}
	return _spec
}

func (ffq *FeatureFlagQuery) sqlQuery(ctx context.Context) *sql.Selector {
	builder := sql.Dialect(ffq.driver.Dialect())
	t1 := builder.Table(featureflag.Table)
	columns := ffq.ctx.Fields
	if len(columns) == 0 {
		columns = featureflag.Columns
	}
	selector := builder.Select(t1.Columns(columns...)...).From(t1)
	if ffq.sql != nil {
		selector = ffq.sql
		selector.Select(selector.Columns(columns...)...)
	}
	if ffq.ctx.Unique != nil && *ffq.ctx.Unique {
		selector.Distinct()
	}
	for _, m := range ffq.modifiers {
		m(selector)
	}
	for _, p := range ffq.predicates {
		p(selector)
	}
	for _, p := range ffq.order {
		p(selector)
	}
	if offset := ffq.ctx.Offset; offset != nil {
		// limit is mandatory for offset clause. We start
		// with default value, and override it below if needed.
		selector.Offset(*offset).Limit(math.MaxInt32)
	}
	if limit := ffq.ctx.Limit; limit != nil {
		selector.Limit(*limit)
	}
	return selector
}

// ForUpdate locks the selected rows against concurrent updates, and prevent them from being
// updated, deleted or "selected ... for update" by other sessions, until the transaction is
// either committed or rolled-back.
func (ffq *FeatureFlagQuery) ForUpdate(opts ...sql.LockOption) *FeatureFlagQuery {
	if ffq.driver.Dialect() == dialect.Postgres {
		ffq.Unique(false)
	}
	ffq.modifiers = append(ffq.modifiers, func(s *sql.Selector) {
		s.ForUpdate(opts...)
	})
	return ffq
}

// ForShare behaves similarly to ForUpdate, except that it acquires a shared mode lock
// on any rows that are read. Other sessions can read the rows, but cannot modify them
// until your transaction commits.
func (ffq *FeatureFlagQuery) ForShare(opts ...sql.LockOption) *FeatureFlagQuery {
	if ffq.driver.Dialect() == dialect.Postgres {
		ffq.Unique(false)
	}
	ffq.modifiers = append(ffq.modifiers, func(s *sql.Selector) {
		s.ForShare(opts...)
	})
	return ffq
}

// Modify adds a query modifier for attaching custom logic to queries.
func (ffq *FeatureFlagQuery) Modify(modifiers ...func(s *sql.Selector)) *FeatureFlagSelect {
	ffq.modifiers = append(ffq.modifiers, modifiers...)
	return ffq.Select()
}

// WithNamedOrganizationFeatures tells the query-builder to eager-load the nodes that are connected to the "organization_features"
// edge with the given name. The optional arguments are used to configure the query builder of the edge.
func (ffq *FeatureFlagQuery) WithNamedOrganizationFeatures(name string, opts ...func(*OrganizationFeatureQuery)) *FeatureFlagQuery {
	query := (&OrganizationFeatureClient{config: ffq.config}).Query()
	for _, opt := range opts {
		opt(query)
	}
	if ffq.withNamedOrganizationFeatures == nil {
		ffq.withNamedOrganizationFeatures = make(map[string]*OrganizationFeatureQuery)
	}
	ffq.withNamedOrganizationFeatures[name] = query
	return ffq
}

// FeatureFlagGroupBy is the group-by builder for FeatureFlag entities.
type FeatureFlagGroupBy struct {
	selector
	build *FeatureFlagQuery
}

// Aggregate adds the given aggregation functions to the group-by query.
func (ffgb *FeatureFlagGroupBy) Aggregate(fns ...AggregateFunc) *FeatureFlagGroupBy {
	ffgb.fns = append(ffgb.fns, fns...)
	return ffgb
}

// Scan applies the selector query and scans the result into the given value.
func (ffgb *FeatureFlagGroupBy) Scan(ctx context.Context, v any) error {
	ctx = setContextOp(ctx, ffgb.build.ctx, ent.OpQueryGroupBy)
	if err := ffgb.build.prepareQuery(ctx); err != nil {
		return err
	}
	return scanWithInterceptors[*FeatureFlagQuery, *FeatureFlagGroupBy](ctx, ffgb.build, ffgb, ffgb.build.inters, v)
}

func (ffgb *FeatureFlagGroupBy) sqlScan(ctx context.Context, root *FeatureFlagQuery, v any) error {
	selector := root.sqlQuery(ctx).Select()
	aggregation := make([]string, 0, len(ffgb.fns))
	for _, fn := range ffgb.fns {
		aggregation = append(aggregation, fn(selector))
	}
	if len(selector.SelectedColumns()) == 0 {
		columns := make([]string, 0, len(*ffgb.flds)+len(ffgb.fns))
		for _, f := range *ffgb.flds {
			columns = append(columns, selector.C(f))
		}
		columns = append(columns, aggregation...)
		selector.Select(columns...)
	}
	selector.GroupBy(selector.Columns(*ffgb.flds...)...)
	if err := selector.Err(); err != nil {
		return err
	}
	rows := &sql.Rows{}
	query, args := selector.Query()
	if err := ffgb.build.driver.Query(ctx, query, args, rows); err != nil {
		return err
	}
	defer rows.Close()
	return sql.ScanSlice(rows, v)
}

// FeatureFlagSelect is the builder for selecting fields of FeatureFlag entities.
type FeatureFlagSelect struct {
	*FeatureFlagQuery
	selector
}

// Aggregate adds the given aggregation functions to the selector query.
func (ffs *FeatureFlagSelect) Aggregate(fns ...AggregateFunc) *FeatureFlagSelect {
	ffs.fns = append(ffs.fns, fns...)
	return ffs
}

// Scan applies the selector query and scans the result into the given value.
func (ffs *FeatureFlagSelect) Scan(ctx context.Context, v any) error {
	ctx = setContextOp(ctx, ffs.ctx, ent.OpQuerySelect)
	if err := ffs.prepareQuery(ctx); err != nil {
		return err
	}
	return scanWithInterceptors[*FeatureFlagQuery, *FeatureFlagSelect](ctx, ffs.FeatureFlagQuery, ffs, ffs.inters, v)
}

func (ffs *FeatureFlagSelect) sqlScan(ctx context.Context, root *FeatureFlagQuery, v any) error {
	selector := root.sqlQuery(ctx)
	aggregation := make([]string, 0, len(ffs.fns))
	for _, fn := range ffs.fns {
		aggregation = append(aggregation, fn(selector))
	}
	switch n := len(*ffs.selector.flds); {
	case n == 0 && len(aggregation) > 0:
		selector.Select(aggregation...)
	case n != 0 && len(aggregation) > 0:
		selector.AppendSelect(aggregation...)
	}
	rows := &sql.Rows{}
	query, args := selector.Query()
	if err := ffs.driver.Query(ctx, query, args, rows); err != nil {
		return err
	}
	defer rows.Close()
	return sql.ScanSlice(rows, v)
}

// Modify adds a query modifier for attaching custom logic to queries.
func (ffs *FeatureFlagSelect) Modify(modifiers ...func(s *sql.Selector)) *FeatureFlagSelect {
	ffs.modifiers = append(ffs.modifiers, modifiers...)
	return ffs
}
