package controllers

import (
	"context"
	"fmt"

	"github.com/juicycleff/frank/config"
	"github.com/juicycleff/frank/ent"
	"github.com/juicycleff/frank/gen/designtypes"
	rbachttp "github.com/juicycleff/frank/gen/http/rbac/server"
	"github.com/juicycleff/frank/gen/rbac"
	rbac2 "github.com/juicycleff/frank/internal/rbac"
	"github.com/juicycleff/frank/internal/services"
	"github.com/juicycleff/frank/pkg/automapper"
	"github.com/juicycleff/frank/pkg/errors"
	"github.com/juicycleff/frank/pkg/logging"
	"github.com/juicycleff/frank/pkg/user"
	"goa.design/clue/debug"
	"goa.design/clue/log"
	goahttp "goa.design/goa/v3/http"
	"goa.design/goa/v3/security"
)

func RegisterRBACHTTPService(
	mux goahttp.Muxer,
	svcs *services.Services,
	config *config.Config,
	logger logging.Logger,
	auther *AutherService,
) {
	eh := errorHandler(logger)
	svc := NewRbac(svcs.RBAC, svcs.User, config, logger, auther)

	endpoints := rbac.NewEndpoints(svc)
	handler := rbachttp.New(endpoints, mux, decoder, encoder, eh, errors.CustomErrorFormatter)

	endpoints.Use(debug.LogPayloads())
	endpoints.Use(log.Endpoint)

	rbachttp.Mount(mux, handler)
}

// rbac service example implementation.
// The example methods log the requests and return zero values.
type rbacsrvc struct {
	rbacService rbac2.Service
	userService user.Service
	config      *config.Config
	logger      logging.Logger
	auther      *AutherService
	mapper      *automapper.Mapper
}

// NewRbac returns the rbac service implementation.
func NewRbac(
	rbacService rbac2.Service,
	userService user.Service,
	config *config.Config,
	logger logging.Logger,
	auther *AutherService,
) rbac.Service {
	mapper := automapper.NewMapper()

	// Create and configure the mapper
	userMapper := automapper.CreateMap[*ent.User, designtypes.User]()
	automapper.RegisterWithTypes(mapper, userMapper)

	return &rbacsrvc{
		rbacService: rbacService,
		userService: userService,
		config:      config,
		logger:      logger,
		auther:      auther,
		mapper:      mapper,
	}
}

// JWTAuth implements the authorization logic for service "rbac" for the "jwt"
// security scheme.
func (s *rbacsrvc) JWTAuth(ctx context.Context, token string, scheme *security.JWTScheme) (context.Context, error) {
	return s.auther.JWTAuth(ctx, token, scheme)
}

// ListPermissions List permissions
func (s *rbacsrvc) ListPermissions(ctx context.Context, p *rbac.ListPermissionsPayload) (res *rbac.ListPermissionsResponse, err error) {
	res = &rbac.ListPermissionsResponse{}
	log.Printf(ctx, "rbac.list_permissions")
	return
}

// CreatePermission Create a new permission
func (s *rbacsrvc) CreatePermission(ctx context.Context, p *rbac.CreatePermissionPayload) (res *designtypes.PermissionResponse, err error) {
	res = &designtypes.PermissionResponse{}
	log.Printf(ctx, "rbac.create_permission")
	return
}

// GetPermission Get permission by ID
func (s *rbacsrvc) GetPermission(ctx context.Context, p *rbac.GetPermissionPayload) (res *designtypes.PermissionResponse, err error) {
	res = &designtypes.PermissionResponse{}
	log.Printf(ctx, "rbac.get_permission")
	return
}

// UpdatePermission Update permission
func (s *rbacsrvc) UpdatePermission(ctx context.Context, p *rbac.UpdatePermissionPayload) (res *designtypes.PermissionResponse, err error) {
	res = &designtypes.PermissionResponse{}
	log.Printf(ctx, "rbac.update_permission")
	return
}

// DeletePermission Delete permission
func (s *rbacsrvc) DeletePermission(ctx context.Context, p *rbac.DeletePermissionPayload) (err error) {
	log.Printf(ctx, "rbac.delete_permission")
	return
}

// ListRoles List roles
func (s *rbacsrvc) ListRoles(ctx context.Context, p *rbac.ListRolesPayload) (res *rbac.ListRolesResult, err error) {
	res = &rbac.ListRolesResult{}
	log.Printf(ctx, "rbac.list_roles")
	return
}

// CreateRole Create a new role
func (s *rbacsrvc) CreateRole(ctx context.Context, p *rbac.CreateRolePayload) (res *designtypes.RoleResponse, err error) {
	res = &designtypes.RoleResponse{}
	log.Printf(ctx, "rbac.create_role")
	return
}

// GetRole Get role by ID
func (s *rbacsrvc) GetRole(ctx context.Context, p *rbac.GetRolePayload) (res *designtypes.RoleResponse, err error) {
	res = &designtypes.RoleResponse{}
	log.Printf(ctx, "rbac.get_role")
	return
}

// UpdateRole Update role
func (s *rbacsrvc) UpdateRole(ctx context.Context, p *rbac.UpdateRolePayload) (res *designtypes.RoleResponse, err error) {
	res = &designtypes.RoleResponse{}
	log.Printf(ctx, "rbac.update_role")
	return
}

// DeleteRole Delete role
func (s *rbacsrvc) DeleteRole(ctx context.Context, p *rbac.DeleteRolePayload) (err error) {
	return s.rbacService.DeleteRole(ctx, p.ID)
}

// ListRolePermissions List role permissions
func (s *rbacsrvc) ListRolePermissions(ctx context.Context, p *rbac.ListRolePermissionsPayload) (res *rbac.ListRolePermissionsResult, err error) {
	res = &rbac.ListRolePermissionsResult{}

	params := rbac2.ListPermissionsParams{
		Offset:   0,
		Limit:    0,
		Resource: "",
		Action:   "",
		Search:   "",
	}

	// Get role
	perms, count, err := s.rbacService.ListPermissions(ctx, params)
	if err != nil {
		return nil, err
	}

	fmt.Println(perms)
	fmt.Println(count)

	return
}

// AddRolePermission Add permission to role
func (s *rbacsrvc) AddRolePermission(ctx context.Context, p *rbac.AddRolePermissionPayload) (res *rbac.AddRolePermissionResult, err error) {
	res = &rbac.AddRolePermissionResult{}
	id := p.ID
	if id == "" {
		err = errors.New(errors.CodeInvalidInput, "role id is required")
		return
	}

	permissionId := p.Permission.PermissionID
	if permissionId == "" {
		err = errors.New(errors.CodeInvalidInput, "permission id is required")
		return
	}

	err = s.rbacService.AddPermissionToRole(ctx, id, permissionId)
	if err != nil {
		return
	}

	res.Message = "Permission added to role"
	return
}

// RemoveRolePermission Remove permission from role
func (s *rbacsrvc) RemoveRolePermission(ctx context.Context, p *rbac.RemoveRolePermissionPayload) (err error) {
	id := p.ID
	if id == "" {
		err = errors.New(errors.CodeInvalidInput, "role id is required")
		return
	}

	permissionId := p.PermissionID
	if permissionId == "" {
		err = errors.New(errors.CodeInvalidInput, "permission id is required")
		return
	}

	err = s.rbacService.RemovePermissionFromRole(ctx, id, permissionId)
	return
}

// CheckPermission Check if user has a permission
func (s *rbacsrvc) CheckPermission(ctx context.Context, p *rbac.CheckPermissionPayload) (res *rbac.CheckPermissionResult, err error) {
	res = &rbac.CheckPermissionResult{}
	log.Printf(ctx, "rbac.check_permission")
	return
}

// CheckRole Check if user has a role
func (s *rbacsrvc) CheckRole(ctx context.Context, p *rbac.CheckRolePayload) (res *rbac.CheckRoleResult, err error) {
	res = &rbac.CheckRoleResult{}
	log.Printf(ctx, "rbac.check_role")
	return
}
