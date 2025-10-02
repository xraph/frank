package models

import (
	"context"
	"database/sql"
	"time"

	"github.com/rs/xid"
	"github.com/uptrace/bun"
)

// CommonModel provides common fields for all models
type CommonModel struct {
	ID string `bun:"id,pk,type:varchar(20)" json:"id"`
}

// BeforeAppendModel implements bun.BeforeAppendModelHook
func (m *CommonModel) BeforeAppendModel(ctx context.Context, query bun.Query) error {
	switch query.(type) {
	case *bun.InsertQuery:
		if m.ID == "" {
			m.ID = xid.New().String()
		}
	}
	return nil
}

// Timestamps provides created_at and updated_at fields
type Timestamps struct {
	CreatedAt time.Time `bun:"created_at,nullzero,notnull,default:current_timestamp" json:"created_at"`
	UpdatedAt time.Time `bun:"updated_at,nullzero,notnull,default:current_timestamp" json:"updated_at"`
}

// BeforeAppendModel implements bun.BeforeAppendModelHook for Timestamps
func (t *Timestamps) BeforeAppendModel(ctx context.Context, query bun.Query) error {
	switch query.(type) {
	case *bun.InsertQuery:
		now := time.Now()
		if t.CreatedAt.IsZero() {
			t.CreatedAt = now
		}
		if t.UpdatedAt.IsZero() {
			t.UpdatedAt = now
		}
	case *bun.UpdateQuery:
		t.UpdatedAt = time.Now()
	}
	return nil
}

// SoftDelete provides soft delete functionality
type SoftDelete struct {
	DeletedAt *time.Time `bun:"deleted_at,soft_delete,nullzero" json:"deleted_at,omitempty"`
}

// IsDeleted checks if the record is soft deleted
func (s *SoftDelete) IsDeleted() bool {
	return s.DeletedAt != nil && !s.DeletedAt.IsZero()
}

// Delete soft deletes the record
func (s *SoftDelete) Delete() {
	now := time.Now()
	s.DeletedAt = &now
}

// Restore restores a soft deleted record
func (s *SoftDelete) Restore() {
	s.DeletedAt = nil
}

// Metadata provides a generic metadata field
type Metadata struct {
	Metadata map[string]interface{} `bun:"metadata,type:jsonb" json:"metadata,omitempty"`
}

// JSONMap is a helper type for JSONB fields
type JSONMap map[string]interface{}

// Value implements driver.Valuer
func (j JSONMap) Value() (interface{}, error) {
	if j == nil {
		return nil, nil
	}
	return j, nil
}

// Scan implements sql.Scanner
func (j *JSONMap) Scan(src interface{}) error {
	if src == nil {
		*j = nil
		return nil
	}
	return nil
}

// NullableTime handles nullable timestamp fields
type NullableTime struct {
	sql.NullTime
}

// MarshalJSON implements json.Marshaler
func (nt NullableTime) MarshalJSON() ([]byte, error) {
	if !nt.Valid {
		return []byte("null"), nil
	}
	return nt.Time.MarshalJSON()
}

// UnmarshalJSON implements json.Unmarshaler
func (nt *NullableTime) UnmarshalJSON(data []byte) error {
	if string(data) == "null" {
		nt.Valid = false
		return nil
	}
	if err := nt.Time.UnmarshalJSON(data); err != nil {
		return err
	}
	nt.Valid = true
	return nil
}

// contextKey type for context values
type contextKey string

const (
	// SkipSoftDeleteKey is used to skip soft delete filtering
	SkipSoftDeleteKey contextKey = "skip_soft_delete"
)

// SkipSoftDelete returns a context that skips soft delete filtering
func SkipSoftDelete(ctx context.Context) context.Context {
	return context.WithValue(ctx, SkipSoftDeleteKey, true)
}

// ShouldSkipSoftDelete checks if soft delete should be skipped
func ShouldSkipSoftDelete(ctx context.Context) bool {
	skip, ok := ctx.Value(SkipSoftDeleteKey).(bool)
	return ok && skip
}
