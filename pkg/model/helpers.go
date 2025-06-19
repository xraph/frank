package model

import (
	"net/http"
	"reflect"
	"time"

	"github.com/danielgtaylor/huma/v2"
	"github.com/juicycleff/frank/pkg/errors"
	"github.com/rs/xid"
)

const InPath = "path"
const inQuery = "query"

// Output is a generic struct to represent an HTTP response containing headers and a body of type T.
// ContentType specifies the MIME type of the response.
// LastModified indicates the last modification time of the resource.
// SetCookie provides an HTTP cookie to set in the client's browser.
// Body contains the actual response data of type T.
type Output[T any] struct {
	ContentType  string      `header:"Content-Type"`
	LastModified time.Time   `header:"Last-Modified"`
	SetCookie    http.Cookie `header:"Set-Cookie"`
	Session      http.Cookie `cookie:"session"`

	Body T
}

type OutputWithStatus[T any] struct {
	Output[T]
	Status int
}

type RedirectOutput struct {
	Status   int
	Location string `json:"location" header:"Location"`
}

type EmptyOutputBody struct{}
type EmptyOutput = Output[EmptyOutputBody]

type OrganisationParams struct {
	// OrgID xid.ID `json:"orgId" path:"orgId"`
	OrgID string `json:"orgId" query:"orgId"`
}

type OrganisationPathParams struct {
	// OrgID xid.ID `json:"orgId" path:"orgId"`
	PathOrgID xid.ID `json:"orgId" path:"orgId"`
}

func (o *OrganisationParams) OrgIsXID() bool {
	fromString, err := xid.FromString(o.OrgID)
	if err != nil {
		return false
	}

	return fromString.String() == o.OrgID
}

func (o *OrganisationParams) OrgToXID() (xid.ID, error) {
	return xid.FromString(o.OrgID)
}

type ProjectParams struct {
	ProjectID xid.ID `json:"projectId" path:"projectId"`
}

type MemberParams struct {
	MemberID xid.ID `json:"memberId" path:"memberId"`
}

// ErrorResponse represents a standardized error response
type ErrorResponse = errors.Error

// Base represents basic information shared by most resources
type Base struct {
	ID        xid.ID    `json:"id" example:"01FZS6TV7KP869DR7RXNEHXQKX"`
	CreatedAt time.Time `json:"createdAt" example:"2023-01-01T12:00:00Z"`
	UpdatedAt time.Time `json:"updatedAt" example:"2023-01-01T12:00:00Z"`
}

// AuditBase represents basic information shared by most resources
type AuditBase struct {
	CreatedBy xid.ID `json:"createdBy" example:"01FZS6TV7KP869DR7RXNEHXQKX"`
	UpdatedBy xid.ID `json:"updatedBy" example:"01FZS6TV7KP869DR7RXNEHXQKX"`
}

type OptionalParam[T any] struct {
	Value T
	IsSet bool
}

// Schema Define schema to use wrapped type
func (o OptionalParam[T]) Schema(r huma.Registry) *huma.Schema {
	return huma.SchemaFromType(r, reflect.TypeOf(o.Value))
}

// Receiver Expose wrapped value to receive parsed value from Huma
// MUST have pointer receiver
func (o *OptionalParam[T]) Receiver() reflect.Value {
	return reflect.ValueOf(o).Elem().Field(0)
}

// OnParamSet React to request param being parsed to update internal state
// MUST have pointer receiver
func (o *OptionalParam[T]) OnParamSet(isSet bool, parsed any) {
	o.IsSet = isSet
}

func ParseMembershipStatus(status string) MembershipStatus {
	switch status {
	case "active":
		return MembershipStatusActive
	case "inactive":
		return MembershipStatusInactive
	case "suspended":
		return MembershipStatusSuspended
	case "pending":
		return MembershipStatusPending
	default:
		return MembershipStatusActive
	}
}

type JSONObject = map[string]interface{}
