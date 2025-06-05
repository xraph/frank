package authz

import (
	"context"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/juicycleff/frank/pkg/errors"
	"github.com/juicycleff/frank/pkg/logging"
	"github.com/rs/xid"
	"go.uber.org/zap"
)

// PermissionMiddleware creates middleware for checking permissions
func PermissionMiddleware(permChecker PermissionChecker, logger logging.Logger) func(permission Permission, resourceType ResourceType, resourceIDParam string) func(http.Handler) http.Handler {
	return func(permission Permission, resourceType ResourceType, resourceIDParam string) func(http.Handler) http.Handler {
		return func(next http.Handler) http.Handler {
			return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				ctx := r.Context()

				// Extract resource ID from URL parameters
				resourceID := chi.URLParam(r, resourceIDParam)
				if resourceID == "" && resourceType != ResourceGlobal {
					http.Error(w, "Resource ID is required", http.StatusBadRequest)
					return
				}

				// Check permission
				hasPermission, err := permChecker.HasPermissionString(ctx, permission, resourceType, resourceID)
				if err != nil {
					logger.Error("Error checking permission", zap.Error(err))
					http.Error(w, "Internal server error", http.StatusInternalServerError)
					return
				}

				if !hasPermission {
					http.Error(w, "Permission denied", http.StatusForbidden)
					return
				}

				// Permission granted, proceed to the next handler
				next.ServeHTTP(w, r)
			})
		}
	}
}

// RequirePermission is a shorthand function for requiring a specific permission
func RequirePermission(permChecker PermissionChecker, logger logging.Logger, permission Permission, resourceType ResourceType, resourceIDParam string) func(http.Handler) http.Handler {
	return PermissionMiddleware(permChecker, logger)(permission, resourceType, resourceIDParam)
}

// RequireAnyPermission ensures the user has at least one of the specified permissions
func RequireAnyPermission(permChecker PermissionChecker, logger logging.Logger) func(permissions []Permission, resourceType ResourceType, resourceIDParam string) func(http.Handler) http.Handler {
	return func(permissions []Permission, resourceType ResourceType, resourceIDParam string) func(http.Handler) http.Handler {
		return func(next http.Handler) http.Handler {
			return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				ctx := r.Context()

				// Extract resource ID from URL parameters
				resourceID := chi.URLParam(r, resourceIDParam)
				if resourceID == "" && resourceType != ResourceGlobal {
					http.Error(w, "Resource ID is required", http.StatusBadRequest)
					return
				}

				var hasPermission bool
				var err error

				if resourceID != "" {
					xxid, parseErr := xid.FromString(resourceID)
					if parseErr != nil {
						// If it's not a valid XID, treat as string identifier (like slug)
						// For now, we'll handle this in the permission checker
						hasPermission = false
						for _, permission := range permissions {
							has, checkErr := permChecker.HasPermissionString(ctx, permission, resourceType, resourceID)
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
						hasPermission, err = permChecker.HasAnyPermission(ctx, permissions, resourceType, xxid)
					}
				} else {
					// Global resource
					hasPermission, err = permChecker.HasAnyPermission(ctx, permissions, resourceType, xid.NilID())
				}

				if err != nil {
					logger.Error("Error checking permission", zap.Error(err))
					http.Error(w, "Internal server error", http.StatusInternalServerError)
					return
				}

				if !hasPermission {
					http.Error(w, "Permission denied", http.StatusForbidden)
					return
				}

				// Permission granted, proceed to the next handler
				next.ServeHTTP(w, r)
			})
		}
	}
}

// RequireOrganizationMember creates middleware that ensures the user is a member of the organization
func RequireOrganizationMember(permChecker PermissionChecker, logger logging.Logger) func(http.Handler) http.Handler {
	return RequirePermission(permChecker, logger, PermissionViewOrganization, ResourceOrganization, "orgID")
}

// RequireOrganizationAdmin creates middleware that ensures the user is an admin of the organization
func RequireOrganizationAdmin(permChecker PermissionChecker, logger logging.Logger) func(http.Handler) http.Handler {
	return RequirePermission(permChecker, logger, PermissionUpdateOrganization, ResourceOrganization, "orgID")
}

// RequireOrganizationOwner creates middleware that ensures the user is the owner of the organization
func RequireOrganizationOwner(permChecker PermissionChecker, logger logging.Logger) func(http.Handler) http.Handler {
	return RequirePermission(permChecker, logger, PermissionDeleteOrganization, ResourceOrganization, "orgID")
}

// RequireSystemAdmin creates middleware that ensures the user is a system administrator
func RequireSystemAdmin(permChecker PermissionChecker, logger logging.Logger) func(http.Handler) http.Handler {
	return RequirePermission(permChecker, logger, PermissionSystemAdmin, ResourceGlobal, "")
}

// RequireSelfOrAdmin creates middleware that allows access if user is accessing their own resource or is an admin
func RequireSelfOrAdmin(permChecker PermissionChecker, logger logging.Logger, resourceType ResourceType, adminPermission Permission) func(http.Handler) http.Handler {
	return RequireAnyPermission(permChecker, logger)(
		[]Permission{PermissionViewSelf, adminPermission},
		resourceType,
		"userID",
	)
}

// RequireInternalUser middleware ensures the user is an internal platform user
func RequireInternalUser(permChecker *EnhancedPermissionChecker, logger logging.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := r.Context()

			// Get current user (implement based on your auth)
			userId, err := GetUserIDFromContext(ctx)
			if err != nil {
				logger.Error("Error getting current user", zap.Error(err))
				http.Error(w, "Unauthorized", http.StatusUnauthorized)
				return
			}

			isInternal, err := permChecker.IsInternalUser(ctx, userId)
			if err != nil {
				logger.Error("Error checking user type", zap.Error(err))
				http.Error(w, "Internal server error", http.StatusInternalServerError)
				return
			}

			if !isInternal {
				http.Error(w, "Access denied - internal users only", http.StatusForbidden)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// RequirePlatformAdmin middleware ensures the user is a platform administrator
func RequirePlatformAdmin(permChecker *EnhancedPermissionChecker, logger logging.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := r.Context()

			userId, err := GetUserIDFromContext(ctx)
			if err != nil {
				logger.Error("Error getting current user", zap.Error(err))
				http.Error(w, "Unauthorized", http.StatusUnauthorized)
				return
			}

			isPlatformAdmin, err := permChecker.IsPlatformAdmin(ctx, userId)
			if err != nil {
				logger.Error("Error checking platform admin status", zap.Error(err))
				http.Error(w, "Internal server error", http.StatusInternalServerError)
				return
			}

			if !isPlatformAdmin {
				http.Error(w, "Access denied - platform administrators only", http.StatusForbidden)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// RequireExternalUser middleware ensures the user is an external customer organization user
func RequireExternalUser(permChecker *EnhancedPermissionChecker, logger logging.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := r.Context()

			userId, err := GetUserIDFromContext(ctx)
			if err != nil {
				logger.Error("Error getting current user", zap.Error(err))
				http.Error(w, "Unauthorized", http.StatusUnauthorized)
				return
			}

			isExternal, err := permChecker.IsExternalUser(ctx, userId)
			if err != nil {
				logger.Error("Error checking user type", zap.Error(err))
				http.Error(w, "Internal server error", http.StatusInternalServerError)
				return
			}

			if !isExternal {
				http.Error(w, "Access denied - customer users only", http.StatusForbidden)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// RequireCustomerDataAccess middleware ensures user can access specific customer organization data
func RequireCustomerDataAccess(permChecker *EnhancedPermissionChecker, logger logging.Logger, orgIDParam string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := r.Context()

			userId, err := GetUserIDFromContext(ctx)
			if err != nil {
				logger.Error("Error getting current user", zap.Error(err))
				http.Error(w, "Unauthorized", http.StatusUnauthorized)
				return
			}

			orgID := chi.URLParam(r, orgIDParam)
			if orgID == "" {
				http.Error(w, "Organization ID required", http.StatusBadRequest)
				return
			}

			orgXID, err := xid.FromString(orgID)
			if err != nil {
				http.Error(w, "Invalid organization ID", http.StatusBadRequest)
				return
			}

			canAccess, err := permChecker.CanAccessCustomerData(ctx, userId, orgXID)
			if err != nil {
				logger.Error("Error checking customer data access", zap.Error(err))
				http.Error(w, "Internal server error", http.StatusInternalServerError)
				return
			}

			if !canAccess {
				http.Error(w, "Access denied - insufficient permissions for this organization", http.StatusForbidden)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// RequireAuthServiceEnabled middleware ensures the organization has auth service enabled
func RequireAuthServiceEnabled(permChecker *EnhancedPermissionChecker, logger logging.Logger, orgIDParam string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := r.Context()

			orgID := chi.URLParam(r, orgIDParam)
			if orgID == "" {
				http.Error(w, "Organization ID required", http.StatusBadRequest)
				return
			}

			orgXID, err := xid.FromString(orgID)
			if err != nil {
				http.Error(w, "Invalid organization ID", http.StatusBadRequest)
				return
			}

			// Check if organization has auth service enabled
			org, err := permChecker.client.DB.Organization.Get(ctx, orgXID)
			if err != nil {
				logger.Error("Error getting organization", zap.Error(err))
				http.Error(w, "Organization not found", http.StatusNotFound)
				return
			}

			if !org.AuthServiceEnabled {
				http.Error(w, "Auth service not enabled for this organization", http.StatusForbidden)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// UserTypeAware middleware that adds user context to the request
func UserTypeAware(permChecker *EnhancedPermissionChecker, logger logging.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := r.Context()

			userId, err := GetUserIDFromContext(ctx)
			if err != nil {
				// Not authenticated - continue without user context
				next.ServeHTTP(w, r)
				return
			}

			userType, err := permChecker.GetUserType(ctx, userId)
			if err != nil {
				logger.Error("Error getting user type", zap.Error(err))
				// Continue but log the error
			}

			// Add user type to context for use in handlers
			ctx = context.WithValue(ctx, "user_type", userType)
			ctx = context.WithValue(ctx, "user_id", userId)

			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// Helper functions to get user context from request context
func GetUserTypeFromContext(ctx context.Context) (*UserType, error) {
	userType, ok := ctx.Value("user_type").(UserType)
	if !ok {
		return nil, errors.New(errors.CodeNotFound, "UserType not found")
	}
	return &userType, nil
}

func GetUserIDFromContext(ctx context.Context) (xid.ID, error) {
	userID, ok := ctx.Value("user_id").(xid.ID)
	if !ok {
		return xid.NilID(), errors.New(errors.CodeBadRequest, "User ID required")
	}
	return userID, nil
}
