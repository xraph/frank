package controllers

import (
	"context"
	"fmt"

	"github.com/juicycleff/frank/gen/users"
	"goa.design/clue/log"
	"goa.design/goa/v3/security"
)

// users service example implementation.
// The example methods log the requests and return zero values.
type userssrvc struct{}

// NewUsers returns the users service implementation.
func NewUsers() users.Service {
	return &userssrvc{}
}

// JWTAuth implements the authorization logic for service "users" for the "jwt"
// security scheme.
func (s *userssrvc) JWTAuth(ctx context.Context, token string, scheme *security.JWTScheme) (context.Context, error) {
	//
	// TBD: add authorization logic.
	//
	// In case of authorization failure this function should return
	// one of the generated error structs, e.g.:
	//
	//    return ctx, myservice.MakeUnauthorizedError("invalid token")
	//
	// Alternatively this function may return an instance of
	// goa.ServiceError with a Name field value that matches one of
	// the design error names, e.g:
	//
	//    return ctx, goa.PermanentError("unauthorized", "invalid token")
	//
	return ctx, fmt.Errorf("not implemented")
}

// List users
func (s *userssrvc) List(ctx context.Context, p *users.ListPayload) (res *users.ListResult, err error) {
	res = &users.ListResult{}
	log.Printf(ctx, "users.list")
	return
}

// Create a new user
func (s *userssrvc) Create(ctx context.Context, p *users.CreatePayload) (res *users.User, err error) {
	res = &users.User{}
	log.Printf(ctx, "users.create")
	return
}

// Get user by ID
func (s *userssrvc) Get(ctx context.Context, p *users.GetPayload) (res *users.User, err error) {
	res = &users.User{}
	log.Printf(ctx, "users.get")
	return
}

// Update user
func (s *userssrvc) Update(ctx context.Context, p *users.UpdatePayload) (res *users.User, err error) {
	res = &users.User{}
	log.Printf(ctx, "users.update")
	return
}

// Delete user
func (s *userssrvc) Delete(ctx context.Context, p *users.DeletePayload) (err error) {
	log.Printf(ctx, "users.delete")
	return
}

// Update current user
func (s *userssrvc) UpdateMe(ctx context.Context, p *users.UpdateMePayload) (res *users.User, err error) {
	res = &users.User{}
	log.Printf(ctx, "users.update_me")
	return
}

// Update current user password
func (s *userssrvc) UpdatePassword(ctx context.Context, p *users.UpdatePasswordPayload) (res *users.UpdatePasswordResult, err error) {
	res = &users.UpdatePasswordResult{}
	log.Printf(ctx, "users.update_password")
	return
}

// Get current user sessions
func (s *userssrvc) GetSessions(ctx context.Context, p *users.GetSessionsPayload) (res *users.GetSessionsResult, err error) {
	res = &users.GetSessionsResult{}
	log.Printf(ctx, "users.get_sessions")
	return
}

// Delete user session
func (s *userssrvc) DeleteSession(ctx context.Context, p *users.DeleteSessionPayload) (err error) {
	log.Printf(ctx, "users.delete_session")
	return
}

// Get user organizations
func (s *userssrvc) GetOrganizations(ctx context.Context, p *users.GetOrganizationsPayload) (res *users.GetOrganizationsResult, err error) {
	res = &users.GetOrganizationsResult{}
	log.Printf(ctx, "users.get_organizations")
	return
}
