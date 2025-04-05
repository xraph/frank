package controllers

import (
	"context"
	"fmt"
	"time"

	"github.com/juicycleff/frank/config"
	"github.com/juicycleff/frank/ent"
	apikeys "github.com/juicycleff/frank/gen/api_keys"
	"github.com/juicycleff/frank/gen/designtypes"
	apikeyshhttp "github.com/juicycleff/frank/gen/http/api_keys/server"
	apikeys2 "github.com/juicycleff/frank/internal/apikeys"
	"github.com/juicycleff/frank/internal/middleware"
	"github.com/juicycleff/frank/internal/services"
	"github.com/juicycleff/frank/pkg/automapper"
	"github.com/juicycleff/frank/pkg/errors"
	"github.com/juicycleff/frank/pkg/logging"
	"goa.design/clue/debug"
	"goa.design/clue/log"
	goahttp "goa.design/goa/v3/http"
	"goa.design/goa/v3/security"
)

func RegisterAPIKeyHTTPService(
	mux goahttp.Muxer,
	svcs *services.Services,
	config *config.Config,
	logger logging.Logger,
	auther *AutherService,
) {
	eh := errorHandler(logger)
	svc := NewAPIKeys(svcs.APIKey, config, logger, auther)

	endpoints := apikeys.NewEndpoints(svc)
	handler := apikeyshhttp.New(endpoints, mux, decoder, encoder, eh, errors.CustomErrorFormatter)

	endpoints.Use(debug.LogPayloads())
	endpoints.Use(log.Endpoint)

	apikeyshhttp.Mount(mux, handler)
}

// api_keys service example implementation.
// The example methods log the requests and return zero values.
type apiKeyssrvc struct {
	apiKeyService apikeys2.Service
	config        *config.Config
	logger        logging.Logger
	auther        *AutherService
	mapper        *automapper.Mapper
}

// NewAPIKeys returns the api_keys service implementation.
func NewAPIKeys(
	apiKeyService apikeys2.Service,
	config *config.Config,
	logger logging.Logger,
	auther *AutherService,
) apikeys.Service {

	mapper := automapper.NewMapper()

	// Create and configure the mapper
	userMapper := automapper.CreateMap[*ent.User, designtypes.User]()
	automapper.RegisterWithTypes(mapper, userMapper)

	return &apiKeyssrvc{
		apiKeyService: apiKeyService,
		config:        config,
		logger:        logger,
		auther:        auther,
		mapper:        mapper,
	}
}

// JWTAuth implements the authorization logic for service "api_keys" for the
// "jwt" security scheme.
func (s *apiKeyssrvc) JWTAuth(ctx context.Context, token string, scheme *security.JWTScheme) (context.Context, error) {
	return s.auther.JWTAuth(ctx, token, scheme)
}

// List API keys
func (s *apiKeyssrvc) List(ctx context.Context, p *apikeys.ListPayload) (res *apikeys.ListResult, err error) {
	res = &apikeys.ListResult{}

	// Get user and organization IDs from context
	userID, _ := middleware.GetUserID(ctx)
	orgID, _ := middleware.GetOrganizationID(ctx)

	if userID == "" && orgID == "" {
		err = errors.New(errors.CodeMissingRequiredField, "either user ID or organization ID is required")
		return
	}

	keyType := ""
	if p.Type == nil {
		return nil, errors.New(errors.CodeInvalidInput, "type is not supported")
	}
	keyType = *p.Type

	// Create list params
	params := apikeys2.ListParams{
		Offset:         p.Offset,
		Limit:          p.Limit,
		UserID:         userID,
		OrganizationID: orgID,
		Type:           keyType,
	}

	// List API keys
	apiKeys, total, err := s.apiKeyService.List(ctx, params)
	if err != nil {
		return nil, err
	}

	fmt.Println(apiKeys)
	fmt.Println(total)

	res.Total = total
	res.Total = total
	res.Pagination = &designtypes.Pagination{
		Offset:      p.Offset,
		Limit:       p.Limit,
		Total:       total,
		TotalPages:  1,
		CurrentPage: 1,
		HasNext:     false,
		HasPrevious: false,
	}

	return
}

// Create a new API key
func (s *apiKeyssrvc) Create(ctx context.Context, p *apikeys.CreatePayload) (res *apikeys.APIKeyWithSecretResponse, err error) {
	res = &apikeys.APIKeyWithSecretResponse{}

	// Get user and organization IDs from context
	userID, _ := middleware.GetUserID(ctx)
	orgID, _ := middleware.GetOrganizationID(ctx)

	if userID == "" && orgID == "" {
		return nil, errors.New(errors.CodeMissingRequiredField, "either user ID or organization ID is required")
	}

	// Set default type if not provided
	if p.Key.Type == "" {
		p.Key.Type = "client"
	}

	// Convert expires_in to duration if provided
	var expiresIn *time.Duration
	if p.Key.ExpiresIn != nil {
		duration := time.Duration(*p.Key.ExpiresIn) * time.Second
		expiresIn = &duration
	}

	// Map to service input
	createInput := apikeys2.CreateAPIKeyRequest{
		Name:           p.Key.Name,
		Type:           p.Key.Type,
		UserID:         userID,
		OrganizationID: orgID,
		Permissions:    p.Key.Permissions,
		Scopes:         p.Key.Scopes,
		Metadata:       p.Key.Metadata,
		ExpiresIn:      expiresIn,
	}

	// Create API key
	apiKeyWithKey, err := s.apiKeyService.Create(ctx, createInput)
	if err != nil {
		return nil, err
	}

	mapper := automapper.CreateMap[*apikeys2.APIKeyWithKeyResponse, apikeys.APIKeyWithSecretResponse]()
	automapper.MapTo(apiKeyWithKey, res, mapper)

	return res, nil
}

// Get API key by ID
func (s *apiKeyssrvc) Get(ctx context.Context, p *apikeys.GetPayload) (res *apikeys.APIKeyResponse, err error) {
	res = &apikeys.APIKeyResponse{}

	// Get API key
	apiKey, err := s.apiKeyService.Get(ctx, p.ID)
	if err != nil {
		return nil, err
	}

	mapper := automapper.CreateMap[*ent.ApiKey, apikeys.APIKeyResponse]()
	automapper.MapTo(apiKey, res, mapper)

	return res, nil
}

// Update API key
func (s *apiKeyssrvc) Update(ctx context.Context, p *apikeys.UpdatePayload) (res *apikeys.APIKeyResponse, err error) {
	res = &apikeys.APIKeyResponse{}

	// Map to service input
	updateInput := apikeys2.UpdateAPIKeyRequest{
		Name:        p.Key.Name,
		Active:      p.Key.Active,
		Permissions: p.Key.Permissions,
		Scopes:      p.Key.Scopes,
		Metadata:    p.Key.Metadata,
	}

	if p.Key.ExpiresAt != nil {
		// expire, err := time.ParseDateTime(*p.Key.ExpiresAt)
		// if err != nil {
		// 	return nil, errors.New(errors.CodeInvalidInput, "invalid expires at")
		// }
		//
		// updateInput.ExpiresAt = &expire
	}

	// Update API key
	updatedAPIKey, err := s.apiKeyService.Update(ctx, p.ID, updateInput)
	if err != nil {
		return nil, err
	}
	mapper := automapper.CreateMap[*ent.ApiKey, apikeys.APIKeyResponse]()
	automapper.MapTo(updatedAPIKey, res, mapper)

	return res, nil
}

// Delete API key
func (s *apiKeyssrvc) Delete(ctx context.Context, p *apikeys.DeletePayload) (err error) {
	// Delete API key
	return s.apiKeyService.Delete(ctx, p.ID)
}

// Validate API key
func (s *apiKeyssrvc) Validate(ctx context.Context, p *apikeys.ValidatePayload) (res *apikeys.ValidateResult, err error) {
	res = &apikeys.ValidateResult{}

	info, ok := middleware.GetRequestInfo(ctx)
	if !ok {
		return nil, errors.New(errors.CodeInternalServer, "failed to get request info")
	}

	// Get API key from header
	apiKey := info.Req.Header.Get("X-API-Key")
	if apiKey == "" {
		// Try to get from query parameter
		apiKey = info.Req.URL.Query().Get("api_key")
		if apiKey == "" {
			err = errors.New(errors.CodeInvalidAPIKey, "API key is required")
			return
		}
	}

	// Validate API key
	validatedKey, err := s.apiKeyService.Validate(ctx, apiKey)
	if err != nil {
		return nil, err
	}

	out := &apikeys.APIKeyResponse{}
	mapper := automapper.CreateMap[*ent.ApiKey, apikeys.APIKeyResponse]()
	automapper.MapTo(validatedKey, out, mapper)

	// Return validated API key
	res.Valid = true
	res.Key = out

	return res, nil
}
