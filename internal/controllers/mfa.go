package controllers

import (
	"context"
	"fmt"

	"github.com/juicycleff/frank/gen/mfa"
	"goa.design/clue/log"
	"goa.design/goa/v3/security"
)

// mfa service example implementation.
// The example methods log the requests and return zero values.
type mfasrvc struct{}

// NewMfa returns the mfa service implementation.
func NewMfa() mfa.Service {
	return &mfasrvc{}
}

// JWTAuth implements the authorization logic for service "mfa" for the "jwt"
// security scheme.
func (s *mfasrvc) JWTAuth(ctx context.Context, token string, scheme *security.JWTScheme) (context.Context, error) {
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

// Start MFA enrollment
func (s *mfasrvc) Enroll(ctx context.Context, p *mfa.EnrollPayload) (res *mfa.EnrollResult, err error) {
	res = &mfa.EnrollResult{}
	log.Printf(ctx, "mfa.enroll")
	return
}

// Verify MFA code
func (s *mfasrvc) Verify(ctx context.Context, p *mfa.VerifyPayload) (res *mfa.VerifyResult, err error) {
	res = &mfa.VerifyResult{}
	log.Printf(ctx, "mfa.verify")
	return
}

// Disable MFA method
func (s *mfasrvc) Unenroll(ctx context.Context, p *mfa.UnenrollPayload) (res *mfa.UnenrollResult, err error) {
	res = &mfa.UnenrollResult{}
	log.Printf(ctx, "mfa.unenroll")
	return
}

// Get enabled MFA methods
func (s *mfasrvc) Methods(ctx context.Context, p *mfa.MethodsPayload) (res *mfa.MethodsResult, err error) {
	res = &mfa.MethodsResult{}
	log.Printf(ctx, "mfa.methods")
	return
}

// Send verification code
func (s *mfasrvc) SendCode(ctx context.Context, p *mfa.SendCodePayload) (res *mfa.SendCodeResult, err error) {
	res = &mfa.SendCodeResult{}
	log.Printf(ctx, "mfa.send_code")
	return
}
