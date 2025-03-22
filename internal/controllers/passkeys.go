package controllers

import (
	"context"
	"fmt"

	"github.com/juicycleff/frank/gen/passkeys"
	"goa.design/clue/log"
	"goa.design/goa/v3/security"
)

// passkeys service example implementation.
// The example methods log the requests and return zero values.
type passkeyssrvc struct{}

// NewPasskeys returns the passkeys service implementation.
func NewPasskeys() passkeys.Service {
	return &passkeyssrvc{}
}

// JWTAuth implements the authorization logic for service "passkeys" for the
// "jwt" security scheme.
func (s *passkeyssrvc) JWTAuth(ctx context.Context, token string, scheme *security.JWTScheme) (context.Context, error) {
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

// OAuth2Auth implements the authorization logic for service "passkeys" for the
// "oauth2" security scheme.
func (s *passkeyssrvc) OAuth2Auth(ctx context.Context, token string, scheme *security.OAuth2Scheme) (context.Context, error) {
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

// APIKeyAuth implements the authorization logic for service "passkeys" for the
// "api_key" security scheme.
func (s *passkeyssrvc) APIKeyAuth(ctx context.Context, key string, scheme *security.APIKeyScheme) (context.Context, error) {
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

// Begin passkey registration
func (s *passkeyssrvc) RegisterBegin(ctx context.Context, p *passkeys.RegisterBeginPayload) (res *passkeys.RegisterBeginResult, err error) {
	res = &passkeys.RegisterBeginResult{}
	log.Printf(ctx, "passkeys.register_begin")
	return
}

// Complete passkey registration
func (s *passkeyssrvc) RegisterComplete(ctx context.Context, p *passkeys.RegisterCompletePayload) (res *passkeys.RegisteredPasskey, err error) {
	res = &passkeys.RegisteredPasskey{}
	log.Printf(ctx, "passkeys.register_complete")
	return
}

// Begin passkey authentication
func (s *passkeyssrvc) LoginBegin(ctx context.Context, p *passkeys.LoginBeginPayload) (res *passkeys.LoginBeginResult, err error) {
	res = &passkeys.LoginBeginResult{}
	log.Printf(ctx, "passkeys.login_begin")
	return
}

// Complete passkey authentication
func (s *passkeyssrvc) LoginComplete(ctx context.Context, p *passkeys.LoginCompletePayload) (res *passkeys.LoginCompleteResult, err error) {
	res = &passkeys.LoginCompleteResult{}
	log.Printf(ctx, "passkeys.login_complete")
	return
}

// List registered passkeys
func (s *passkeyssrvc) List(ctx context.Context, p *passkeys.ListPayload) (res *passkeys.ListResult, err error) {
	res = &passkeys.ListResult{}
	log.Printf(ctx, "passkeys.list")
	return
}

// Update passkey
func (s *passkeyssrvc) Update(ctx context.Context, p *passkeys.UpdatePayload) (res *passkeys.UpdateResult, err error) {
	res = &passkeys.UpdateResult{}
	log.Printf(ctx, "passkeys.update")
	return
}

// Delete passkey
func (s *passkeyssrvc) Delete(ctx context.Context, p *passkeys.DeletePayload) (err error) {
	log.Printf(ctx, "passkeys.delete")
	return
}
