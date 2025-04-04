package controllers

import (
	"context"

	"github.com/juicycleff/frank/config"
	"github.com/juicycleff/frank/ent"
	"github.com/juicycleff/frank/gen/designtypes"
	usershttp "github.com/juicycleff/frank/gen/http/users/server"
	"github.com/juicycleff/frank/gen/users"
	"github.com/juicycleff/frank/internal/auth/session"
	"github.com/juicycleff/frank/internal/middleware"
	"github.com/juicycleff/frank/internal/services"
	"github.com/juicycleff/frank/pkg/automapper"
	"github.com/juicycleff/frank/pkg/errors"
	"github.com/juicycleff/frank/pkg/logging"
	"github.com/juicycleff/frank/user"
	"github.com/samber/lo"
	"goa.design/clue/debug"
	"goa.design/clue/log"
	goahttp "goa.design/goa/v3/http"
	"goa.design/goa/v3/security"
)

// users service example implementation.
// The example methods log the requests and return zero values.
type userssrvc struct {
	userService    user.Service
	config         *config.Config
	logger         logging.Logger
	sessionManager *session.Manager
	cookieHandler  *session.CookieHandler
	auther         *AutherService
	mapper         *automapper.Mapper
}

func RegisterUserHTTPService(
	mux goahttp.Muxer,
	svcs *services.Services,
	config *config.Config,
	logger logging.Logger,
	auther *AutherService,
) {
	eh := errorHandler(logger)
	svc := NewUsers(svcs.User, svcs.Session, svcs.CookieHandler, config, logger, auther)

	endpoints := users.NewEndpoints(svc)
	handler := usershttp.New(endpoints, mux, decoder, encoder, eh, errors.CustomErrorFormatter)

	endpoints.Use(debug.LogPayloads())
	endpoints.Use(log.Endpoint)

	usershttp.Mount(mux, handler)
}

// NewUsers returns the users service implementation.
func NewUsers(
	userService user.Service,
	sessionManager *session.Manager,
	cookieHandler *session.CookieHandler,
	config *config.Config,
	logger logging.Logger,
	auther *AutherService,
) users.Service {
	mapper := automapper.NewMapper()

	// Create and configure the mapper
	userMapper := automapper.CreateMap[*ent.User, designtypes.User]()
	automapper.RegisterWithTypes(mapper, userMapper)

	return &userssrvc{
		userService:    userService,
		config:         config,
		logger:         logger,
		sessionManager: sessionManager,
		cookieHandler:  cookieHandler,
		auther:         auther,
		mapper:         mapper,
	}
}

// JWTAuth implements the authorization logic for service "users" for the "jwt"
// security scheme.
func (s *userssrvc) JWTAuth(ctx context.Context, token string, scheme *security.JWTScheme) (context.Context, error) {
	return s.auther.JWTAuth(ctx, token, scheme)
}

// List users
func (s *userssrvc) List(ctx context.Context, p *users.ListPayload) (res *users.ListResult, err error) {
	res = &users.ListResult{}
	log.Printf(ctx, "users.list")
	return
}

// Create a new user
func (s *userssrvc) Create(ctx context.Context, p *users.CreatePayload) (res *designtypes.User, err error) {
	res = &designtypes.User{}

	input := user.CreateUserInput{
		Email:    p.Email,
		Locale:   p.Locale,
		Metadata: p.Metadata,
	}
	if p.Password != nil {
		input.Password = *p.Password
	}
	if p.FirstName != nil {
		input.FirstName = *p.FirstName
	}
	if p.LastName != nil {
		input.LastName = *p.LastName
	}
	if p.OrganizationID != nil {
		input.OrganizationID = *p.OrganizationID
	}
	if p.ProfileImageURL != nil {
		input.ProfileImageURL = *p.ProfileImageURL
	}
	if p.PhoneNumber != nil {
		input.PhoneNumber = *p.PhoneNumber
	}

	// Create user
	usr, err := s.userService.Create(ctx, input)
	if err != nil {
		return nil, err
	}

	mapper := automapper.CreateMap[*ent.User, designtypes.User]()
	automapper.MapTo(usr, res, mapper)

	return res, nil
}

// Get user by ID
func (s *userssrvc) Get(ctx context.Context, p *users.GetPayload) (res *designtypes.User, err error) {
	if p.ID == "" {
		return nil, errors.New(errors.CodeInvalidInput, "user ID is required")
	}

	res = &designtypes.User{}

	// Get user
	usr, err := s.userService.Get(ctx, p.ID)
	if err != nil {
		return nil, err
	}

	mapper := automapper.CreateMap[*ent.User, designtypes.User]()
	automapper.MapTo(usr, res, mapper)

	return res, nil
}

// Update user
func (s *userssrvc) Update(ctx context.Context, p *users.UpdatePayload) (res *designtypes.User, err error) {
	if p.ID == "" {
		return nil, errors.New(errors.CodeInvalidInput, "user ID is required")
	}

	res = &designtypes.User{}

	// Update user
	updatedUser, err := s.userService.Update(ctx, p.ID, user.UpdateUserInput{
		PhoneNumber:           p.User.PhoneNumber,
		FirstName:             p.User.FirstName,
		LastName:              p.User.LastName,
		Metadata:              p.User.Metadata,
		ProfileImageURL:       p.User.ProfileImageURL,
		Locale:                p.User.Locale,
		Active:                p.User.Active,
		PrimaryOrganizationID: p.User.PrimaryOrganizationID,
	})
	if err != nil {
		return nil, err
	}

	mapper := automapper.CreateMap[*ent.User, designtypes.User]()
	automapper.MapTo(updatedUser, res, mapper)

	return res, nil
}

// Delete user
func (s *userssrvc) Delete(ctx context.Context, p *users.DeletePayload) (err error) {
	// Get user ID from path
	if p.ID == "" {
		return errors.New(errors.CodeInvalidInput, "user ID is required")
	}

	// Delete user
	err = s.userService.Delete(ctx, p.ID)
	if err != nil {
		return err
	}

	// Return success
	return nil
}

// UpdateMe updates current user
func (s *userssrvc) UpdateMe(ctx context.Context, p *users.UpdateMePayload) (res *designtypes.User, err error) {
	// Get user ID from context
	userID, ok := middleware.GetUserID(ctx)
	if !ok {
		return nil, errors.New(errors.CodeUnauthorized, "not authenticated")
	}

	res = &designtypes.User{}

	input := user.UpdateUserInput{
		Locale:                p.Locale,
		Metadata:              p.Metadata,
		PhoneNumber:           p.PhoneNumber,
		FirstName:             p.FirstName,
		LastName:              p.LastName,
		ProfileImageURL:       p.ProfileImageURL,
		Active:                p.Active,
		PrimaryOrganizationID: p.PrimaryOrganizationID,
	}

	// Create user
	usr, err := s.userService.Update(ctx, userID, input)
	if err != nil {
		return nil, err
	}

	mapper := automapper.CreateMap[*ent.User, designtypes.User]()
	automapper.MapTo(usr, res, mapper)

	return res, nil
}

// UpdatePassword update current user password
func (s *userssrvc) UpdatePassword(ctx context.Context, p *users.UpdatePasswordPayload) (res *users.UpdatePasswordResult, err error) {
	res = &users.UpdatePasswordResult{}
	log.Printf(ctx, "users.update_password")
	return
}

// GetSessions get current user sessions
func (s *userssrvc) GetSessions(ctx context.Context, p *users.GetSessionsPayload) (res *users.GetUserSessionResponse, err error) {
	userId, ok := middleware.GetUserID(ctx)
	if !ok {
		return nil, errors.New(errors.CodeUnauthorized, "not authenticated")
	}

	res = &users.GetUserSessionResponse{}

	if s.sessionManager == nil {
		return nil, errors.New(errors.CodeInternalServer, "session not available")
	}

	sessions, err := s.sessionManager.GetUserSessions(ctx, userId)
	if err != nil {
		return nil, err
	}

	mapper := automapper.CreateMap[*session.SessionInfo, designtypes.Session]()
	sessData := automapper.MapToArray(sessions, mapper)

	res.Data = lo.Map(sessData, func(item designtypes.Session, index int) *designtypes.Session {
		return &item
	})

	res.Pagination = &designtypes.Pagination{
		Offset:      0,
		Limit:       0,
		Total:       len(sessData),
		TotalPages:  1,
		CurrentPage: 1,
		HasNext:     false,
		HasPrevious: false,
	}

	return res, nil
}

// DeleteSession delete user session
func (s *userssrvc) DeleteSession(ctx context.Context, p *users.DeleteSessionPayload) (err error) {
	// Get user ID from context
	_, ok := middleware.GetUserID(ctx)
	if !ok {
		return errors.New(errors.CodeUnauthorized, "not authenticated")
	}

	// Get session ID from path
	if p.SessionID == "" {
		return errors.New(errors.CodeInvalidInput, "session ID is required")
	}

	// Delete session (implementation depends on session manager)
	if s.sessionManager != nil {
		err = s.sessionManager.RevokeSession(ctx, p.SessionID)
		if err != nil {
			return err
		}
	}
	// For now, return success
	return nil
}

// GetOrganizations get user organizations
func (s *userssrvc) GetOrganizations(ctx context.Context, p *users.GetOrganizationsPayload) (res *users.GetOrganizationsResult, err error) {
	res = &users.GetOrganizationsResult{}
	log.Printf(ctx, "users.get_organizations")
	return
}
