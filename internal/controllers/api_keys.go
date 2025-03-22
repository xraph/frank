package controllers

import (
	"context"
	"fmt"

	apikeys "github.com/juicycleff/frank/gen/api_keys"
	"goa.design/clue/log"
	"goa.design/goa/v3/security"
)

// api_keys service example implementation.
// The example methods log the requests and return zero values.
type apiKeyssrvc struct{}

// NewAPIKeys returns the api_keys service implementation.
func NewAPIKeys() apikeys.Service {
	return &apiKeyssrvc{}
}

// JWTAuth implements the authorization logic for service "api_keys" for the
// "jwt" security scheme.
func (s *apiKeyssrvc) JWTAuth(ctx context.Context, token string, scheme *security.JWTScheme) (context.Context, error) {
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

// List API keys
func (s *apiKeyssrvc) List(ctx context.Context, p *apikeys.ListPayload) (res *apikeys.ListResult, err error) {
	res = &apikeys.ListResult{}
	log.Printf(ctx, "apiKeys.list")
	return
}

// Create a new API key
func (s *apiKeyssrvc) Create(ctx context.Context, p *apikeys.CreatePayload) (res *apikeys.APIKeyWithSecretResponse, err error) {
	res = &apikeys.APIKeyWithSecretResponse{}
	log.Printf(ctx, "apiKeys.create")
	return
}

// Get API key by ID
func (s *apiKeyssrvc) Get(ctx context.Context, p *apikeys.GetPayload) (res *apikeys.APIKeyResponse, err error) {
	res = &apikeys.APIKeyResponse{}
	log.Printf(ctx, "apiKeys.get")
	return
}

// Update API key
func (s *apiKeyssrvc) Update(ctx context.Context, p *apikeys.UpdatePayload) (res *apikeys.APIKeyResponse, err error) {
	res = &apikeys.APIKeyResponse{}
	log.Printf(ctx, "apiKeys.update")
	return
}

// Delete API key
func (s *apiKeyssrvc) Delete(ctx context.Context, p *apikeys.DeletePayload) (err error) {
	log.Printf(ctx, "apiKeys.delete")
	return
}

// Validate API key
func (s *apiKeyssrvc) Validate(ctx context.Context, p *apikeys.ValidatePayload) (res *apikeys.ValidateResult, err error) {
	res = &apikeys.ValidateResult{}
	log.Printf(ctx, "apiKeys.validate")
	return
}
