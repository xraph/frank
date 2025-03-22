package controllers

import (
	"context"
	"fmt"

	"github.com/juicycleff/frank/gen/designtypes"
	"github.com/juicycleff/frank/gen/rbac"
	"goa.design/clue/log"
	"goa.design/goa/v3/security"
)

// rbac service example implementation.
// The example methods log the requests and return zero values.
type rbacsrvc struct{}

// NewRbac returns the rbac service implementation.
func NewRbac() rbac.Service {
	return &rbacsrvc{}
}

// JWTAuth implements the authorization logic for service "rbac" for the "jwt"
// security scheme.
func (s *rbacsrvc) JWTAuth(ctx context.Context, token string, scheme *security.JWTScheme) (context.Context, error) {
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
	log.Printf(ctx, "rbac.delete_role")
	return
}

// ListRolePermissions List role permissions
func (s *rbacsrvc) ListRolePermissions(ctx context.Context, p *rbac.ListRolePermissionsPayload) (res *rbac.ListRolePermissionsResult, err error) {
	res = &rbac.ListRolePermissionsResult{}
	log.Printf(ctx, "rbac.list_role_permissions")
	return
}

// AddRolePermission Add permission to role
func (s *rbacsrvc) AddRolePermission(ctx context.Context, p *rbac.AddRolePermissionPayload) (res *rbac.AddRolePermissionResult, err error) {
	res = &rbac.AddRolePermissionResult{}
	log.Printf(ctx, "rbac.add_role_permission")
	return
}

// RemoveRolePermission Remove permission from role
func (s *rbacsrvc) RemoveRolePermission(ctx context.Context, p *rbac.RemoveRolePermissionPayload) (err error) {
	log.Printf(ctx, "rbac.remove_role_permission")
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
