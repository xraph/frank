package authz

import (
	"net/http"

	"github.com/danielgtaylor/huma/v2"
	"github.com/juicycleff/frank/pkg/errors"
	"github.com/juicycleff/frank/pkg/logging"
	"github.com/rs/xid"
	"go.uber.org/zap"
)

// HumaPermissionMiddleware creates middleware for checking permissions in Huma API
func HumaPermissionMiddleware(api huma.API, permChecker PermissionChecker, logger logging.Logger) func(permission Permission, resourceType ResourceType, resourceIDParam string) func(ctx huma.Context, next func(huma.Context)) {
	return func(permission Permission, resourceType ResourceType, resourceIDParam string) func(ctx huma.Context, next func(huma.Context)) {
		return func(ctx huma.Context, next func(huma.Context)) {
			var resourceID string

			// For global resources, no resource ID is needed
			if resourceType != ResourceGlobal {
				resourceID = ctx.Param(resourceIDParam)
				if resourceID == "" {
					huma.WriteErr(api, ctx, http.StatusBadRequest,
						"Resource ID is required", errors.New(errors.CodeForbidden, "Resource ID is required"),
					)
					return
				}
			}

			// Check permission
			hasPermission, err := permChecker.HasPermissionString(ctx.Context(), permission, resourceType, resourceID)
			if err != nil {
				logger.Error("Error checking permission", zap.Error(err))
				huma.WriteErr(api, ctx, http.StatusInternalServerError,
					"Permission denied", errors.New(errors.CodeInternalServer, "Internal server error"),
				)
				return
			}

			if !hasPermission {
				huma.WriteErr(api, ctx, http.StatusForbidden,
					"Permission denied", errors.New(errors.CodeForbidden, "Permission denied"),
				)
				return
			}

			// Permission granted, proceed to the next handler
			next(ctx)
		}
	}
}

// HumaRequireAnyPermission creates Huma middleware that ensures the user has at least one of the specified permissions
func HumaRequireAnyPermission(api huma.API, permChecker PermissionChecker, logger logging.Logger) func(permissions []Permission, resourceType ResourceType, resourceIDParam string) func(ctx huma.Context, next func(huma.Context)) {
	return func(permissions []Permission, resourceType ResourceType, resourceIDParam string) func(ctx huma.Context, next func(huma.Context)) {
		return func(ctx huma.Context, next func(huma.Context)) {
			var resourceID string

			// For global resources, no resource ID is needed
			if resourceType != ResourceGlobal {
				resourceID = ctx.Param(resourceIDParam)
				if resourceID == "" {
					huma.WriteErr(api, ctx, http.StatusBadRequest,
						"Resource ID is required", errors.New(errors.CodeForbidden, "Resource ID is required"),
					)
					return
				}
			}

			var hasPermission bool
			var err error

			if resourceID != "" {
				xxid, parseErr := xid.FromString(resourceID)
				if parseErr != nil {
					// If it's not a valid XID, check each permission as string
					hasPermission = false
					for _, permission := range permissions {
						has, checkErr := permChecker.HasPermissionString(ctx.Context(), permission, resourceType, resourceID)
						if checkErr != nil {
							err = checkErr
							break
						}
						if has {
							hasPermission = true
							break
						}
					}
				} else {
					// Check for any permission with XID
					hasPermission, err = permChecker.HasAnyPermission(ctx.Context(), permissions, resourceType, xxid)
				}
			} else {
				// Global resource
				hasPermission, err = permChecker.HasAnyPermission(ctx.Context(), permissions, resourceType, xid.NilID())
			}

			if err != nil {
				logger.Error("Error checking permission", zap.Error(err))
				huma.WriteErr(api, ctx, http.StatusInternalServerError,
					"Permission denied", errors.New(errors.CodeInternalServer, "Internal server error"),
				)
				return
			}

			if !hasPermission {
				huma.WriteErr(api, ctx, http.StatusForbidden,
					"Permission denied", errors.New(errors.CodeForbidden, "Permission denied"),
				)
				return
			}

			// Permission granted, proceed to the next handler
			next(ctx)
		}
	}
}

// HumaRequirePermission is a shorthand function for requiring a specific permission in Huma
func HumaRequirePermission(api huma.API, permChecker PermissionChecker, logger logging.Logger, permission Permission, resourceType ResourceType, resourceIDParam string) func(ctx huma.Context, next func(huma.Context)) {
	return HumaPermissionMiddleware(api, permChecker, logger)(permission, resourceType, resourceIDParam)
}

// HumaRequireOrganizationMember creates Huma middleware that ensures the user is a member of the organization
func HumaRequireOrganizationMember(api huma.API, permChecker PermissionChecker, logger logging.Logger) func(ctx huma.Context, next func(huma.Context)) {
	return HumaRequirePermission(api, permChecker, logger, PermissionViewOrganization, ResourceOrganization, "orgID")
}

// HumaRequireOrganizationAdmin creates Huma middleware that ensures the user is an admin of the organization
func HumaRequireOrganizationAdmin(api huma.API, permChecker PermissionChecker, logger logging.Logger) func(ctx huma.Context, next func(huma.Context)) {
	return HumaRequirePermission(api, permChecker, logger, PermissionUpdateOrganization, ResourceOrganization, "orgID")
}

// HumaRequireOrganizationOwner creates Huma middleware that ensures the user is the owner of the organization
func HumaRequireOrganizationOwner(api huma.API, permChecker PermissionChecker, logger logging.Logger) func(ctx huma.Context, next func(huma.Context)) {
	return HumaRequirePermission(api, permChecker, logger, PermissionDeleteOrganization, ResourceOrganization, "orgID")
}

// HumaRequireSystemAdmin creates Huma middleware that ensures the user is a system administrator
func HumaRequireSystemAdmin(api huma.API, permChecker PermissionChecker, logger logging.Logger) func(ctx huma.Context, next func(huma.Context)) {
	return HumaRequirePermission(api, permChecker, logger, PermissionSystemAdmin, ResourceGlobal, "")
}

// HumaRequireSelfOrAdmin creates Huma middleware that allows access if user is accessing their own resource or is an admin
func HumaRequireSelfOrAdmin(api huma.API, permChecker PermissionChecker, logger logging.Logger, resourceType ResourceType, adminPermission Permission) func(ctx huma.Context, next func(huma.Context)) {
	return HumaRequireAnyPermission(api, permChecker, logger)(
		[]Permission{PermissionViewSelf, adminPermission},
		resourceType,
		"userID",
	)
}
