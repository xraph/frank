package controllers

import (
	"context"
	"fmt"

	"github.com/juicycleff/frank/gen/passwordless"
	"goa.design/clue/log"
	"goa.design/goa/v3/security"
)

// passwordless service example implementation.
// The example methods log the requests and return zero values.
type passwordlesssrvc struct{}

// NewPasswordless returns the passwordless service implementation.
func NewPasswordless() passwordless.Service {
	return &passwordlesssrvc{}
}

// OAuth2Auth implements the authorization logic for service "passwordless" for
// the "oauth2" security scheme.
func (s *passwordlesssrvc) OAuth2Auth(ctx context.Context, token string, scheme *security.OAuth2Scheme) (context.Context, error) {
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

// APIKeyAuth implements the authorization logic for service "passwordless" for
// the "api_key" security scheme.
func (s *passwordlesssrvc) APIKeyAuth(ctx context.Context, key string, scheme *security.APIKeyScheme) (context.Context, error) {
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

// JWTAuth implements the authorization logic for service "passwordless" for
// the "jwt" security scheme.
func (s *passwordlesssrvc) JWTAuth(ctx context.Context, token string, scheme *security.JWTScheme) (context.Context, error) {
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

// Initiate passwordless email authentication
func (s *passwordlesssrvc) Email(ctx context.Context, p *passwordless.EmailPayload) (res *passwordless.EmailResult, err error) {
	res = &passwordless.EmailResult{}
	log.Printf(ctx, "passwordless.email")
	return
}

// Initiate passwordless SMS authentication
func (s *passwordlesssrvc) Sms(ctx context.Context, p *passwordless.SmsPayload) (res *passwordless.SmsResult, err error) {
	res = &passwordless.SmsResult{}
	log.Printf(ctx, "passwordless.sms")
	return
}

// Verify passwordless authentication
func (s *passwordlesssrvc) Verify(ctx context.Context, p *passwordless.VerifyPayload) (res *passwordless.VerifyResult, err error) {
	res = &passwordless.VerifyResult{}
	log.Printf(ctx, "passwordless.verify")
	return
}

// Get available passwordless authentication methods
func (s *passwordlesssrvc) Methods(ctx context.Context, p *passwordless.MethodsPayload) (res *passwordless.MethodsResult, err error) {
	res = &passwordless.MethodsResult{}
	log.Printf(ctx, "passwordless.methods")
	return
}

// Generate magic link for passwordless login
func (s *passwordlesssrvc) MagicLink(ctx context.Context, p *passwordless.MagicLinkPayload) (res *passwordless.MagicLinkResult, err error) {
	res = &passwordless.MagicLinkResult{}
	log.Printf(ctx, "passwordless.magic_link")
	return
}
