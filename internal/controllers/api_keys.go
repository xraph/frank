package controllers

import (
	"context"
	"fmt"

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
