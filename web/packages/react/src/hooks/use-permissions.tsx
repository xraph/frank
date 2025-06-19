/**
 * @frank-auth/react - usePermissions Hook
 *
 * Comprehensive permissions hook that provides role-based access control (RBAC),
 * permission checking, and authorization utilities for multi-tenant applications.
 */

import { useState, useCallback, useMemo, useEffect } from 'react';

import type {
    Role,
    Permission,
    UserRoleAssignment,
    UserPermissionAssignment,
} from '@frank-auth/client';

import { FrankAuth } from '@frank-auth/sdk';
import { useAuth } from './use-auth';
import { useConfig } from '../provider/config-provider';

import type {
    AuthError,
    PermissionContext,
} from '../provider/types';

// ============================================================================
// Permission Hook Interface
// ============================================================================

export interface UsePermissionsReturn {
    // Permission state
    permissions: string[];
    roles: string[];
    roleAssignments: UserRoleAssignment[];
    permissionAssignments: UserPermissionAssignment[];
    isLoaded: boolean;
    isLoading: boolean;
    error: AuthError | null;

    // Permission checking
    hasPermission: (permission: string, context?: PermissionContext) => boolean;
    hasRole: (role: string, context?: PermissionContext) => boolean;
    hasAnyPermission: (permissions: string[], context?: PermissionContext) => boolean;
    hasAllPermissions: (permissions: string[], context?: PermissionContext) => boolean;
    can: (action: string, resource: string, context?: PermissionContext) => boolean;

    // Context-aware checking
    canInOrganization: (permission: string, organizationId?: string) => boolean;
    canInApplication: (permission: string, applicationId: string) => boolean;
    hasSystemPermission: (permission: string) => boolean;

    // Role checking
    isSystemAdmin: boolean;
    isOrganizationOwner: (organizationId?: string) => boolean;
    isOrganizationAdmin: (organizationId?: string) => boolean;
    isOrganizationMember: (organizationId?: string) => boolean;

    // Permission management
    refreshPermissions: () => Promise<void>;

    // Convenience methods
    requirePermission: (permission: string, context?: PermissionContext) => void;
    requireRole: (role: string, context?: PermissionContext) => void;
    requireAnyPermission: (permissions: string[], context?: PermissionContext) => void;
    requireAllPermissions: (permissions: string[], context?: PermissionContext) => void;

    // Current context
    currentContext: PermissionContext;
    setContext: (context: PermissionContext) => void;
}

// ============================================================================
// Permission Actions and Resources
// ============================================================================

export const PERMISSION_ACTIONS = {
    // Generic CRUD actions
    CREATE: 'create',
    READ: 'read',
    UPDATE: 'update',
    DELETE: 'delete',

    // User management actions
    INVITE: 'invite',
    REMOVE: 'remove',
    SUSPEND: 'suspend',
    ACTIVATE: 'activate',

    // Admin actions
    MANAGE: 'manage',
    CONFIGURE: 'configure',
    AUDIT: 'audit',

    // Special actions
    TRANSFER: 'transfer',
    EXPORT: 'export',
    IMPORT: 'import',
} as const;

export const PERMISSION_RESOURCES = {
    // User resources
    USER: 'user',
    USER_PROFILE: 'user:profile',
    USER_SESSION: 'user:session',
    USER_MFA: 'user:mfa',

    // Organization resources
    ORGANIZATION: 'organization',
    ORGANIZATION_SETTINGS: 'organization:settings',
    ORGANIZATION_MEMBERS: 'organization:members',
    ORGANIZATION_INVITATIONS: 'organization:invitations',
    ORGANIZATION_BILLING: 'organization:billing',
    ORGANIZATION_AUDIT: 'organization:audit',

    // Application resources
    APPLICATION: 'application',
    APPLICATION_SETTINGS: 'application:settings',
    APPLICATION_USERS: 'application:users',
    APPLICATION_SESSIONS: 'application:sessions',

    // System resources
    SYSTEM: 'system',
    SYSTEM_USERS: 'system:users',
    SYSTEM_ORGANIZATIONS: 'system:organizations',
    SYSTEM_SETTINGS: 'system:settings',
    SYSTEM_BILLING: 'system:billing',
    SYSTEM_AUDIT: 'system:audit',
} as const;

export const SYSTEM_ROLES = {
    SUPER_ADMIN: 'system:super_admin',
    ADMIN: 'system:admin',
    SUPPORT: 'system:support',
} as const;

export const ORGANIZATION_ROLES = {
    OWNER: 'organization:owner',
    ADMIN: 'organization:admin',
    MEMBER: 'organization:member',
    BILLING: 'organization:billing',
    SUPPORT: 'organization:support',
} as const;

// ============================================================================
// Main usePermissions Hook
// ============================================================================

/**
 * Comprehensive permissions hook for role-based access control
 *
 * @example Basic permission checking
 * ```tsx
 * import { usePermissions } from '@frank-auth/react';
 *
 * function UserManagement() {
 *   const {
 *     hasPermission,
 *     canInOrganization,
 *     isOrganizationAdmin,
 *     requirePermission
 *   } = usePermissions();
 *
 *   // Simple permission check
 *   if (!hasPermission('organization:members:manage')) {
 *     return <div>Access denied</div>;
 *   }
 *
 *   // Organization-specific check
 *   const canManageMembers = canInOrganization('members:manage');
 *
 *   // Role-based check
 *   const isAdmin = isOrganizationAdmin();
 *
 *   const handleDeleteUser = () => {
 *     // Throws if permission not granted
 *     requirePermission('organization:members:delete');
 *     // Delete user logic...
 *   };
 *
 *   return (
 *     <div>
 *       {canManageMembers && (
 *         <button onClick={handleDeleteUser}>Delete User</button>
 *       )}
 *       {isAdmin && (
 *         <button>Admin Actions</button>
 *       )}
 *     </div>
 *   );
 * }
 * ```
 *
 * @example Context-aware permissions
 * ```tsx
 * function MultiContextComponent() {
 *   const {
 *     can,
 *     hasSystemPermission,
 *     canInApplication,
 *     setContext
 *   } = usePermissions();
 *
 *   // Action-resource based checking
 *   const canCreateUsers = can('create', 'user');
 *   const canDeleteOrg = can('delete', 'organization');
 *
 *   // System-level permissions
 *   const canManageSystem = hasSystemPermission('system:manage');
 *
 *   // Application-specific permissions
 *   const canConfigureApp = canInApplication('configure', 'app_123');
 *
 *   // Switch context
 *   const switchToOrgContext = () => {
 *     setContext({
 *       type: 'organization',
 *       organizationId: 'org_456'
 *     });
 *   };
 *
 *   return (
 *     <div>
 *       {canCreateUsers && <button>Create User</button>}
 *       {canDeleteOrg && <button>Delete Organization</button>}
 *       {canManageSystem && <button>System Settings</button>}
 *       {canConfigureApp && <button>App Configuration</button>}
 *       <button onClick={switchToOrgContext}>Switch Context</button>
 *     </div>
 *   );
 * }
 * ```
 *
 * @example Permission guards
 * ```tsx
 * function PermissionGuardExample() {
 *   const { hasAnyPermission, hasAllPermissions } = usePermissions();
 *
 *   // User needs at least one of these permissions
 *   const canAccess = hasAnyPermission([
 *     'organization:read',
 *     'organization:members:read'
 *   ]);
 *
 *   // User needs all of these permissions
 *   const canFullyManage = hasAllPermissions([
 *     'organization:manage',
 *     'organization:members:manage',
 *     'organization:billing:manage'
 *   ]);
 *
 *   if (!canAccess) {
 *     return <div>You don't have access to this section</div>;
 *   }
 *
 *   return (
 *     <div>
 *       <h1>Organization Dashboard</h1>
 *       {canFullyManage && (
 *         <div>Full management controls available</div>
 *       )}
 *     </div>
 *   );
 * }
 * ```
 */
export function usePermissions(): UsePermissionsReturn {
    const { user, activeOrganization, session } = useAuth();
    const { apiUrl, publishableKey, userType } = useConfig();

    const [permissions, setPermissions] = useState<string[]>([]);
    const [roles, setRoles] = useState<string[]>([]);
    const [roleAssignments, setRoleAssignments] = useState<UserRoleAssignment[]>([]);
    const [permissionAssignments, setPermissionAssignments] = useState<UserPermissionAssignment[]>([]);
    const [isLoading, setIsLoading] = useState(false);
    const [error, setError] = useState<AuthError | null>(null);

    // Current permission context
    const [currentContext, setCurrentContext] = useState<PermissionContext>({
        type: 'system',
        organizationId: activeOrganization?.id,
    });

    // Initialize Frank Auth SDK for permissions
    const frankAuth = useMemo(() => {
        if (!session?.accessToken) return null;
        return new FrankAuth({
            publishableKey,
            apiUrl,
        });
    }, [publishableKey, apiUrl, session?.accessToken]);

    // Error handler
    const handleError = useCallback((err: any) => {
        const authError: AuthError = {
            code: err.code || 'UNKNOWN_ERROR',
            message: err.message || 'An unknown error occurred',
            details: err.details,
            field: err.field,
        };
        setError(authError);
    }, []);

    // Load user permissions and roles
    const loadPermissions = useCallback(async () => {
        if (!frankAuth || !user) return;

        try {
            setIsLoading(true);
            setError(null);

            // Load user roles and permissions
            const [userRoles, userPermissions] = await Promise.all([
                frankAuth.getUserRoles(user.id),
                frankAuth.getUserPermissions(user.id),
            ]);

            setRoleAssignments(userRoles);
            setPermissionAssignments(userPermissions);

            // Extract role names and permission names
            const roleNames = userRoles.map(ra => ra.role.name);
            const permissionNames = userPermissions.map(pa => pa.permission.name);

            // Also include permissions from roles
            const rolePermissions = userRoles.flatMap(ra =>
                ra.role.permissions?.map(p => p.name) || []
            );

            setRoles(roleNames);
            setPermissions([...new Set([...permissionNames, ...rolePermissions])]);

        } catch (err) {
            handleError(err);
        } finally {
            setIsLoading(false);
        }
    }, [frankAuth, user, handleError]);

    // Load permissions when user or organization changes
    useEffect(() => {
        loadPermissions();
    }, [loadPermissions]);

    // Update context when organization changes
    useEffect(() => {
        if (activeOrganization) {
            setCurrentContext(prev => ({
                ...prev,
                organizationId: activeOrganization.id,
            }));
        }
    }, [activeOrganization]);

    // Permission checking functions
    const hasPermission = useCallback((permission: string, context?: PermissionContext): boolean => {
        const checkContext = context || currentContext;

        // Check direct permissions
        const hasDirectPermission = permissionAssignments.some(pa => {
            if (pa.permission.name !== permission) return false;

            // Check context match
            switch (checkContext.type) {
                case 'system':
                    return pa.contextType === 'system';
                case 'organization':
                    return pa.contextType === 'organization' &&
                        pa.resourceId === checkContext.organizationId;
                case 'application':
                    return pa.contextType === 'application' &&
                        pa.resourceId === checkContext.applicationId;
                default:
                    return false;
            }
        });

        if (hasDirectPermission) return true;

        // Check permissions from roles
        const hasRolePermission = roleAssignments.some(ra => {
            // Check context match for role
            let contextMatch = false;
            switch (checkContext.type) {
                case 'system':
                    contextMatch = ra.contextType === 'system';
                    break;
                case 'organization':
                    contextMatch = ra.contextType === 'organization' &&
                        ra.resourceId === checkContext.organizationId;
                    break;
                case 'application':
                    contextMatch = ra.contextType === 'application' &&
                        ra.resourceId === checkContext.applicationId;
                    break;
            }

            if (!contextMatch) return false;

            // Check if role has the permission
            return ra.role.permissions?.some(p => p.name === permission) || false;
        });

        return hasRolePermission;
    }, [permissionAssignments, roleAssignments, currentContext]);

    const hasRole = useCallback((role: string, context?: PermissionContext): boolean => {
        const checkContext = context || currentContext;

        return roleAssignments.some(ra => {
            if (ra.role.name !== role) return false;

            // Check context match
            switch (checkContext.type) {
                case 'system':
                    return ra.contextType === 'system';
                case 'organization':
                    return ra.contextType === 'organization' &&
                        ra.resourceId === checkContext.organizationId;
                case 'application':
                    return ra.contextType === 'application' &&
                        ra.resourceId === checkContext.applicationId;
                default:
                    return false;
            }
        });
    }, [roleAssignments, currentContext]);

    const hasAnyPermission = useCallback((permissionList: string[], context?: PermissionContext): boolean => {
        return permissionList.some(permission => hasPermission(permission, context));
    }, [hasPermission]);

    const hasAllPermissions = useCallback((permissionList: string[], context?: PermissionContext): boolean => {
        return permissionList.every(permission => hasPermission(permission, context));
    }, [hasPermission]);

    const can = useCallback((action: string, resource: string, context?: PermissionContext): boolean => {
        const permission = `${resource}:${action}`;
        return hasPermission(permission, context);
    }, [hasPermission]);

    // Context-aware checking
    const canInOrganization = useCallback((permission: string, organizationId?: string): boolean => {
        const orgId = organizationId || activeOrganization?.id;
        if (!orgId) return false;

        return hasPermission(permission, {
            type: 'organization',
            organizationId: orgId,
        });
    }, [hasPermission, activeOrganization]);

    const canInApplication = useCallback((permission: string, applicationId: string): boolean => {
        return hasPermission(permission, {
            type: 'application',
            applicationId,
        });
    }, [hasPermission]);

    const hasSystemPermission = useCallback((permission: string): boolean => {
        return hasPermission(permission, { type: 'system' });
    }, [hasPermission]);

    // Role checking helpers
    const isSystemAdmin = useMemo(() => {
        return hasRole(SYSTEM_ROLES.SUPER_ADMIN) || hasRole(SYSTEM_ROLES.ADMIN);
    }, [hasRole]);

    const isOrganizationOwner = useCallback((organizationId?: string): boolean => {
        const orgId = organizationId || activeOrganization?.id;
        if (!orgId) return false;

        return hasRole(ORGANIZATION_ROLES.OWNER, {
            type: 'organization',
            organizationId: orgId,
        });
    }, [hasRole, activeOrganization]);

    const isOrganizationAdmin = useCallback((organizationId?: string): boolean => {
        const orgId = organizationId || activeOrganization?.id;
        if (!orgId) return false;

        return hasRole(ORGANIZATION_ROLES.ADMIN, {
            type: 'organization',
            organizationId: orgId,
        }) || isOrganizationOwner(orgId);
    }, [hasRole, isOrganizationOwner, activeOrganization]);

    const isOrganizationMember = useCallback((organizationId?: string): boolean => {
        const orgId = organizationId || activeOrganization?.id;
        if (!orgId) return false;

        return roleAssignments.some(ra =>
            ra.contextType === 'organization' &&
            ra.resourceId === orgId
        );
    }, [roleAssignments, activeOrganization]);

    // Requirement functions (throw if not met)
    const requirePermission = useCallback((permission: string, context?: PermissionContext): void => {
        if (!hasPermission(permission, context)) {
            throw new Error(`Permission required: ${permission}`);
        }
    }, [hasPermission]);

    const requireRole = useCallback((role: string, context?: PermissionContext): void => {
        if (!hasRole(role, context)) {
            throw new Error(`Role required: ${role}`);
        }
    }, [hasRole]);

    const requireAnyPermission = useCallback((permissionList: string[], context?: PermissionContext): void => {
        if (!hasAnyPermission(permissionList, context)) {
            throw new Error(`One of these permissions required: ${permissionList.join(', ')}`);
        }
    }, [hasAnyPermission]);

    const requireAllPermissions = useCallback((permissionList: string[], context?: PermissionContext): void => {
        if (!hasAllPermissions(permissionList, context)) {
            throw new Error(`All of these permissions required: ${permissionList.join(', ')}`);
        }
    }, [hasAllPermissions]);

    // Refresh permissions
    const refreshPermissions = useCallback(async (): Promise<void> => {
        await loadPermissions();
    }, [loadPermissions]);

    // Set context
    const setContext = useCallback((context: PermissionContext): void => {
        setCurrentContext(context);
    }, []);

    return {
        // Permission state
        permissions,
        roles,
        roleAssignments,
        permissionAssignments,
        isLoaded: !!user,
        isLoading,
        error,

        // Permission checking
        hasPermission,
        hasRole,
        hasAnyPermission,
        hasAllPermissions,
        can,

        // Context-aware checking
        canInOrganization,
        canInApplication,
        hasSystemPermission,

        // Role checking
        isSystemAdmin,
        isOrganizationOwner,
        isOrganizationAdmin,
        isOrganizationMember,

        // Permission management
        refreshPermissions,

        // Convenience methods
        requirePermission,
        requireRole,
        requireAnyPermission,
        requireAllPermissions,

        // Current context
        currentContext,
        setContext,
    };
}

// ============================================================================
// Specialized Permission Hooks
// ============================================================================

/**
 * Hook for organization-specific permissions
 */
export function useOrganizationPermissions(organizationId?: string) {
    const {
        canInOrganization,
        isOrganizationOwner,
        isOrganizationAdmin,
        isOrganizationMember,
        hasRole,
        activeOrganization,
    } = usePermissions();

    const orgId = organizationId || activeOrganization?.id;

    return {
        organizationId: orgId,
        isOwner: isOrganizationOwner(orgId),
        isAdmin: isOrganizationAdmin(orgId),
        isMember: isOrganizationMember(orgId),

        // Common organization permissions
        canManageMembers: canInOrganization('organization:members:manage', orgId),
        canInviteMembers: canInOrganization('organization:members:invite', orgId),
        canRemoveMembers: canInOrganization('organization:members:remove', orgId),
        canManageSettings: canInOrganization('organization:settings:manage', orgId),
        canManageBilling: canInOrganization('organization:billing:manage', orgId),
        canViewAudit: canInOrganization('organization:audit:read', orgId),
        canDeleteOrganization: canInOrganization('organization:delete', orgId),

        // Role checking for organization
        hasOrganizationRole: (role: string) => hasRole(role, {
            type: 'organization',
            organizationId: orgId,
        }),
    };
}

/**
 * Hook for system-level permissions
 */
export function useSystemPermissions() {
    const {
        hasSystemPermission,
        isSystemAdmin,
        hasRole,
        userType,
    } = usePermissions();

    // System permissions are only available to internal users
    const canAccessSystem = userType === 'internal';

    return {
        canAccessSystem,
        isSystemAdmin,

        // Common system permissions
        canManageUsers: canAccessSystem && hasSystemPermission('system:users:manage'),
        canManageOrganizations: canAccessSystem && hasSystemPermission('system:organizations:manage'),
        canManageSystem: canAccessSystem && hasSystemPermission('system:manage'),
        canViewSystemAudit: canAccessSystem && hasSystemPermission('system:audit:read'),
        canManageBilling: canAccessSystem && hasSystemPermission('system:billing:manage'),

        // Role checking for system
        hasSystemRole: (role: string) => hasRole(role, { type: 'system' }),
        isSuperAdmin: hasRole(SYSTEM_ROLES.SUPER_ADMIN, { type: 'system' }),
        isSupport: hasRole(SYSTEM_ROLES.SUPPORT, { type: 'system' }),
    };
}

/**
 * Hook for permission-based conditional rendering
 */
export function usePermissionGuard() {
    const {
        hasPermission,
        hasRole,
        hasAnyPermission,
        hasAllPermissions,
        requirePermission,
        requireRole,
    } = usePermissions();

    const PermissionGuard = useCallback(({
                                             permission,
                                             role,
                                             anyPermissions,
                                             allPermissions,
                                             context,
                                             fallback = null,
                                             children,
                                         }: {
        permission?: string;
        role?: string;
        anyPermissions?: string[];
        allPermissions?: string[];
        context?: PermissionContext;
        fallback?: React.ReactNode;
        children: React.ReactNode;
    }) => {
        let hasAccess = true;

        if (permission) {
            hasAccess = hasAccess && hasPermission(permission, context);
        }

        if (role) {
            hasAccess = hasAccess && hasRole(role, context);
        }

        if (anyPermissions) {
            hasAccess = hasAccess && hasAnyPermission(anyPermissions, context);
        }

        if (allPermissions) {
            hasAccess = hasAccess && hasAllPermissions(allPermissions, context);
        }

        return hasAccess ? <>{children}</> : <>{fallback}</>;
    }, [hasPermission, hasRole, hasAnyPermission, hasAllPermissions]);

    return {
        PermissionGuard,
        requirePermission,
        requireRole,
    };
}