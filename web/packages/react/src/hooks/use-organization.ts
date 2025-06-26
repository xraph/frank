/**
 * @frank-auth/react - useOrganization Hook
 *
 * Organization management hook that provides access to organization operations,
 * member management, invitations, and organization-specific settings.
 */

import {useCallback, useEffect, useMemo, useState} from "react";

import type {
    AcceptInvitationRequest,
    CreateOrganizationRequest,
    DeclineInvitationRequest,
    InviteMemberRequest,
    Organization,
    OrganizationSettings,
    UpdateOrganizationRequest,
} from "@frank-auth/client";

import {FrankOrganization} from "@frank-auth/sdk";
import {useAuth} from "./use-auth";
import {useAuth as useAuthProvider} from "../provider/auth-provider";
import {useConfig} from "../provider/config-provider";

import type {
    AuthError,
    CreateOrganizationParams,
    InviteMemberParams,
    OrganizationInvitation,
    OrganizationMembership,
    UpdateOrganizationParams,
} from "../provider/types";

// ============================================================================
// Organization Hook Interface
// ============================================================================

export interface UseOrganizationReturn {
    // Organization state
    organization: Organization | null;
    organizations: Organization[];
    activeOrganization: Organization | null;
    memberships: OrganizationMembership[];
    invitations: OrganizationInvitation[];
    isLoaded: boolean;
    isLoading: boolean;
    error: AuthError | null;

    // Organization management
    createOrganization: (
        params: CreateOrganizationParams,
    ) => Promise<Organization>;
    updateOrganization: (
        organizationId: string,
        params: UpdateOrganizationParams,
    ) => Promise<Organization>;
    deleteOrganization: (organizationId: string) => Promise<void>;
    switchOrganization: (organizationId: string) => Promise<void>;

    // Member management
    inviteMember: (params: InviteMemberParams) => Promise<void>;
    removeMember: (memberId: string) => Promise<void>;
    updateMemberRole: (memberId: string, role: string) => Promise<void>;
    getMembers: () => Promise<OrganizationMember[]>;

    // Invitation management
    acceptInvitation: (invitationId: string) => Promise<void>;
    declineInvitation: (invitationId: string) => Promise<void>;
    cancelInvitation: (invitationId: string) => Promise<void>;
    resendInvitation: (invitationId: string) => Promise<void>;

    // Settings management
    updateSettings: (
        settings: Partial<OrganizationSettings>,
    ) => Promise<OrganizationSettings>;

    // Convenience properties
    organizationId: string | null;
    organizationName: string | null;
    organizationSlug: string | null;
    isOwner: boolean;
    isAdmin: boolean;
    isMember: boolean;
    memberCount: number;
    pendingInvitations: number;

    // Multi-tenant helpers
    hasOrganizations: boolean;
    canCreateOrganization: boolean;
    canSwitchOrganization: boolean;
}

export interface OrganizationMember {
    id: string;
    userId: string;
    organizationId: string;
    role: string;
    status: "active" | "invited" | "suspended";
    joinedAt: Date;
    invitedBy?: string;
    user: {
        id: string;
        firstName?: string;
        lastName?: string;
        email: string;
        profileImageUrl?: string;
    };
}

// ============================================================================
// Main useOrganization Hook
// ============================================================================

/**
 * Organization management hook providing access to all organization functionality
 *
 * @example Basic organization management
 * ```tsx
 * import { useOrganization } from '@frank-auth/react';
 *
 * function OrganizationManager() {
 *   const {
 *     organization,
 *     organizations,
 *     switchOrganization,
 *     createOrganization,
 *     isOwner,
 *     memberCount
 *   } = useOrganization();
 *
 *   return (
 *     <div>
 *       <h2>{organization?.name}</h2>
 *       <p>Members: {memberCount}</p>
 *
 *       {organizations.length > 1 && (
 *         <select onChange={(e) => switchOrganization(e.target.value)}>
 *           {organizations.map((org) => (
 *             <option key={org.id} value={org.id}>
 *               {org.name}
 *             </option>
 *           ))}
 *         </select>
 *       )}
 *
 *       {isOwner && (
 *         <button onClick={() => createOrganization({
 *           name: 'New Organization',
 *           slug: 'new-org'
 *         })}>
 *           Create Organization
 *         </button>
 *       )}
 *     </div>
 *   );
 * }
 * ```
 *
 * @example Member management
 * ```tsx
 * function MemberManager() {
 *   const {
 *     getMembers,
 *     inviteMember,
 *     removeMember,
 *     isAdmin
 *   } = useOrganization();
 *   const [members, setMembers] = useState([]);
 *
 *   useEffect(() => {
 *     getMembers().then(setMembers);
 *   }, [getMembers]);
 *
 *   if (!isAdmin) return <div>Access denied</div>;
 *
 *   return (
 *     <div>
 *       <h3>Members</h3>
 *       {members.map((member) => (
 *         <div key={member.id}>
 *           <span>{member.user.email} ({member.role})</span>
 *           <button onClick={() => removeMember(member.id)}>
 *             Remove
 *           </button>
 *         </div>
 *       ))}
 *       <button onClick={() => inviteMember({
 *         emailAddress: 'new@example.com',
 *         role: 'member'
 *       })}>
 *         Invite Member
 *       </button>
 *     </div>
 *   );
 * }
 * ```
 */
export function useOrganization(): UseOrganizationReturn {
    const {
        organization,
        organizationMemberships,
        activeOrganization,
        switchOrganization: authSwitchOrganization,
        session,
        reload,
    } = useAuth();
    const {frankOrg} = useAuthProvider();

    const {apiUrl, publishableKey, userType} = useConfig();

    const [organizations, setOrganizations] = useState<Organization[]>([]);
    const [invitations, setInvitations] = useState<OrganizationInvitation[]>([]);
    const [isLoading, setIsLoading] = useState(false);
    const [error, setError] = useState<AuthError | null>(null);

    // Initialize Frank Organization SDK
    const frankOrganization = useMemo(() => {
        // if (frankOrg) return frankOrg;
        console.log(
            "Initializing Frank Organization SDK",
            session,
            apiUrl,
            publishableKey,
            userType,
        );

        // if (!session?.accessToken) return null;
        return new FrankOrganization(
            {
                publishableKey,
                apiUrl,
                userType: userType ?? 'end_user',
            },
            session?.accessToken,
        );
    }, [publishableKey, apiUrl, session?.accessToken]);

    // Error handler
    const handleError = useCallback((err: any) => {
        const authError: AuthError = {
            code: err.code || "UNKNOWN_ERROR",
            message: err.message || "An unknown error occurred",
            details: err.details,
            field: err.field,
        };
        setError(authError);
        throw authError;
    }, []);

    // Load organizations and invitations
    const loadOrganizations = useCallback(async () => {
        if (!frankOrganization) return;

        try {
            setIsLoading(true);
            setError(null);

            // Load organizations user belongs to
            const orgsData = await frankOrganization.listOrganizations({
                fields: [],
            });
            setOrganizations((orgsData.data ?? []) as any);

            // Load pending invitations
            // const invitationsData = await frankOrganization.listInvitations();
            // setInvitations(invitationsData?.data ?? []);
        } catch (err) {
            console.error("Failed to load organizations:", err);
            setError({
                code: "ORGANIZATIONS_LOAD_FAILED",
                message: "Failed to load organizations",
            });
        } finally {
            setIsLoading(false);
        }
    }, [frankOrganization]);

    useEffect(() => {
        loadOrganizations();
    }, [loadOrganizations]);

    // Organization management methods
    const createOrganization = useCallback(
        async (params: CreateOrganizationParams): Promise<Organization> => {
            if (!frankOrganization)
                throw new Error("Organization service not available");

            try {
                setIsLoading(true);
                setError(null);

                const createRequest: CreateOrganizationRequest = {
                    name: params.name,
                    slug: params.slug,
                    // description: params.description,
                    logoUrl: params.logoUrl,
                    websiteUrl: params.websiteUrl,
                    settings: params.settings,
                    plan: params.planId ?? 'free',

                    // createTrialPeriod: true,
                    // enableAuthService: true,
                    // endUserLimit: 10000000,
                    // externalUserLimit: 0,
                    // orgType: "platform",
                    // plan: "",
                };

                const newOrganization =
                    await frankOrganization.createOrganization(createRequest);

                // Refresh organizations list
                await loadOrganizations();
                await reload(); // Refresh auth state

                return newOrganization;
            } catch (err) {
                return handleError(err);
            } finally {
                setIsLoading(false);
            }
        },
        [frankOrganization, loadOrganizations, reload, handleError],
    );

    const updateOrganization = useCallback(
        async (
            organizationId: string,
            params: UpdateOrganizationParams,
        ): Promise<Organization> => {
            if (!frankOrganization)
                throw new Error("Organization service not available");

            try {
                setIsLoading(true);
                setError(null);

                const updateRequest: UpdateOrganizationRequest = {
                    name: params.name,
                    slug: params.slug,
                    description: params.description,
                    logoUrl: params.logoUrl,
                    websiteUrl: params.websiteUrl,
                    settings: params.settings,
                };

                const updatedOrganization = await frankOrganization.updateOrganization(
                    organizationId,
                    updateRequest,
                );

                // Refresh organizations list and auth state
                await loadOrganizations();
                await reload();

                return updatedOrganization;
            } catch (err) {
                return handleError(err);
            } finally {
                setIsLoading(false);
            }
        },
        [frankOrganization, loadOrganizations, reload, handleError],
    );

    const deleteOrganization = useCallback(
        async (organizationId: string): Promise<void> => {
            if (!frankOrganization)
                throw new Error("Organization service not available");

            try {
                setIsLoading(true);
                setError(null);

                await frankOrganization.deleteOrganization(organizationId, {
                    notifyMembers: true,
                    confirm: true,
                    dataRetention: 0,
                });

                // Refresh organizations list and auth state
                await loadOrganizations();
                await reload();
            } catch (err) {
                handleError(err);
            } finally {
                setIsLoading(false);
            }
        },
        [frankOrganization, loadOrganizations, reload, handleError],
    );

    const switchOrganization = useCallback(
        async (organizationId: string): Promise<void> => {
            await authSwitchOrganization(organizationId);
            await loadOrganizations(); // Refresh data for new organization
        },
        [authSwitchOrganization, loadOrganizations],
    );

    // Member management methods
    const inviteMember = useCallback(
        async (params: InviteMemberParams): Promise<void> => {
            if (!frankOrganization || !activeOrganization)
                throw new Error("Organization service not available");

            try {
                setIsLoading(true);
                setError(null);

                const inviteRequest: InviteMemberRequest = {
                    emailAddress: params.emailAddress,
                    role: params.role,
                    redirectUrl: params.redirectUrl,
                    publicMetadata: params.publicMetadata,
                    privateMetadata: params.privateMetadata,
                };

                await frankOrganization.addMember(activeOrganization.id, inviteRequest);

                // Refresh invitations
                await loadOrganizations();
            } catch (err) {
                handleError(err);
            } finally {
                setIsLoading(false);
            }
        },
        [frankOrganization, activeOrganization, loadOrganizations, handleError],
    );

    const removeMember = useCallback(
        async (memberId: string): Promise<void> => {
            if (!frankOrganization || !activeOrganization)
                throw new Error("Organization service not available");

            try {
                setIsLoading(true);
                setError(null);

                await frankOrganization.removeMember(activeOrganization.id, memberId, {
                    notifyUser: true,
                });

                // Refresh organizations data
                await loadOrganizations();
            } catch (err) {
                handleError(err);
            } finally {
                setIsLoading(false);
            }
        },
        [frankOrganization, activeOrganization, loadOrganizations, handleError],
    );

    const updateMemberRole = useCallback(
        async (memberId: string, role: string): Promise<void> => {
            if (!frankOrganization || !activeOrganization)
                throw new Error("Organization service not available");

            try {
                setIsLoading(true);
                setError(null);

                await frankOrganization.updateMemberRole(
                    activeOrganization.id,
                    memberId,
                    {
                        roleId: role,
                    },
                );

                // Refresh organizations data
                await loadOrganizations();
            } catch (err) {
                handleError(err);
            } finally {
                setIsLoading(false);
            }
        },
        [frankOrganization, activeOrganization, loadOrganizations, handleError],
    );

    const getMembers = useCallback(async (): Promise<OrganizationMember[]> => {
        if (!frankOrganization || !activeOrganization)
            throw new Error("Organization service not available");

        try {
            const res = await frankOrganization.listMembers(activeOrganization.id);
            return (res.data ?? []).map(
                (item) =>
                    ({
                        id: item.userId,
                        userId: item.userId,
                        organizationId: item.organizationId,
                        role: item.role,
                        status: item.status,
                        joinedAt: item.joinedAt,
                        invitedBy: item.invitedBy,
                    }) as OrganizationMember,
            );
        } catch (err) {
            handleError(err);
            return [];
        }
    }, [frankOrganization, activeOrganization, handleError]);

    // Invitation management methods
    const acceptInvitation = useCallback(
        async (
            token: string,
            opts?: {
                firstName?: string;
                lastName?: string;
                password?: string;
            },
        ): Promise<void> => {
            if (!frankOrganization)
                throw new Error("Organization service not available");

            try {
                setIsLoading(true);
                setError(null);

                const acceptRequest: AcceptInvitationRequest = {
                    ...(opts ?? {}),
                    token,
                    acceptTerms: true,
                };
                await frankOrganization.acceptInvitation(acceptRequest);

                // Refresh organizations and invitations
                await loadOrganizations();
                await reload(); // User now belongs to new organization
            } catch (err) {
                handleError(err);
            } finally {
                setIsLoading(false);
            }
        },
        [frankOrganization, loadOrganizations, reload, handleError],
    );

    const declineInvitation = useCallback(
        async (token: string): Promise<void> => {
            if (!frankOrganization)
                throw new Error("Organization service not available");

            try {
                setIsLoading(true);
                setError(null);

                const declineRequest: DeclineInvitationRequest = {
                    token: token,
                };
                await frankOrganization.declineInvitation(declineRequest);

                // Refresh invitations
                await loadOrganizations();
            } catch (err) {
                handleError(err);
            } finally {
                setIsLoading(false);
            }
        },
        [frankOrganization, loadOrganizations, handleError],
    );

    const cancelInvitation = useCallback(
        async (invitationId: string): Promise<void> => {
            if (!frankOrganization)
                throw new Error("Organization service not available");

            try {
                setIsLoading(true);
                setError(null);

                await frankOrganization.cancelInvitation(invitationId);

                // Refresh invitations
                await loadOrganizations();
            } catch (err) {
                handleError(err);
            } finally {
                setIsLoading(false);
            }
        },
        [frankOrganization, loadOrganizations, handleError],
    );

    const resendInvitation = useCallback(
        async (invitationId: string): Promise<void> => {
            if (!frankOrganization)
                throw new Error("Organization service not available");

            try {
                setIsLoading(true);
                setError(null);

                await frankOrganization.resendInvitation(invitationId);
            } catch (err) {
                handleError(err);
            } finally {
                setIsLoading(false);
            }
        },
        [frankOrganization, handleError],
    );

    // Settings management
    const updateSettings = useCallback(
        async (
            settings: Partial<OrganizationSettings>,
        ): Promise<OrganizationSettings> => {
            if (!frankOrganization || !activeOrganization)
                throw new Error("Organization service not available");

            try {
                setIsLoading(true);
                setError(null);

                const updatedSettings =
                    await frankOrganization.updateOrganizationSettings(
                        activeOrganization.id,
                        settings,
                    );

                // Refresh organization data
                await loadOrganizations();
                await reload();

                return updatedSettings;
            } catch (err) {
                return handleError(err);
            } finally {
                setIsLoading(false);
            }
        },
        [
            frankOrganization,
            activeOrganization,
            loadOrganizations,
            reload,
            handleError,
        ],
    );

    // Convenience properties
    const organizationId = useMemo(
        () => activeOrganization?.id || null,
        [activeOrganization],
    );
    const organizationName = useMemo(
        () => activeOrganization?.name || null,
        [activeOrganization],
    );
    const organizationSlug = useMemo(
        () => activeOrganization?.slug || null,
        [activeOrganization],
    );

    // Role-based properties
    const currentMembership = useMemo(() => {
        if (!activeOrganization) return null;
        return organizationMemberships.find(
            (m) => m.organization.id === activeOrganization.id,
        );
    }, [activeOrganization, organizationMemberships]);

    const isOwner = useMemo(
        () => currentMembership?.role === "owner",
        [currentMembership],
    );
    const isAdmin = useMemo(
        () => ["owner", "admin"].includes(currentMembership?.role || ""),
        [currentMembership],
    );
    const isMember = useMemo(() => !!currentMembership, [currentMembership]);

    // Organization statistics
    const memberCount = useMemo(
        () => activeOrganization?.memberCount || 0,
        [activeOrganization],
    );
    const pendingInvitations = useMemo(
        () => invitations.filter((inv) => inv.status === "pending").length,
        [invitations],
    );

    // Multi-tenant helpers
    const hasOrganizations = useMemo(
        () => organizations.length > 0,
        [organizations],
    );
    const canCreateOrganization = useMemo(() => {
        // Internal users can always create organizations
        if (userType === "internal") return true;
        // External users can create organizations if they're owners of at least one
        if (userType === "external") {
            return organizationMemberships.some((m) => m.role === "owner");
        }
        // End users cannot create organizations
        return false;
    }, [userType, organizationMemberships]);

    const canSwitchOrganization = useMemo(
        () => organizations.length > 1,
        [organizations],
    );

    return {
        // Organization state
        organization,
        organizations,
        activeOrganization,
        memberships: organizationMemberships,
        invitations,
        isLoaded: !!frankOrganization,
        isLoading,
        error,

        // Organization management
        createOrganization,
        updateOrganization,
        deleteOrganization,
        switchOrganization,

        // Member management
        inviteMember,
        removeMember,
        updateMemberRole,
        getMembers,

        // Invitation management
        acceptInvitation,
        declineInvitation,
        cancelInvitation,
        resendInvitation,

        // Settings management
        updateSettings,

        // Convenience properties
        organizationId,
        organizationName,
        organizationSlug,
        isOwner,
        isAdmin,
        isMember,
        memberCount,
        pendingInvitations,

        // Multi-tenant helpers
        hasOrganizations,
        canCreateOrganization,
        canSwitchOrganization,
    };
}

// ============================================================================
// Specialized Organization Hooks
// ============================================================================

/**
 * Hook for organization membership and role information
 */
export function useOrganizationMembership() {
    const {
        activeOrganization,
        memberships,
        isOwner,
        isAdmin,
        isMember,
        memberCount,
    } = useOrganization();

    const currentMembership = useMemo(() => {
        if (!activeOrganization) return null;
        return memberships.find((m) => m.organization.id === activeOrganization.id);
    }, [activeOrganization, memberships]);

    return {
        organization: activeOrganization,
        membership: currentMembership,
        role: currentMembership?.role || null,
        isOwner,
        isAdmin,
        isMember,
        memberCount,
        joinedAt: currentMembership?.joinedAt || null,
        status: currentMembership?.status || null,
    };
}

/**
 * Hook for organization invitations management
 */
export function useOrganizationInvitations() {
    const {
        invitations,
        acceptInvitation,
        declineInvitation,
        cancelInvitation,
        resendInvitation,
        inviteMember,
        isAdmin,
        isLoading,
        error,
    } = useOrganization();

    const pendingInvitations = useMemo(
        () => invitations.filter((inv) => inv.status === "pending"),
        [invitations],
    );

    const expiredInvitations = useMemo(
        () => invitations.filter((inv) => inv.status === "expired"),
        [invitations],
    );

    return {
        invitations,
        pendingInvitations,
        expiredInvitations,
        acceptInvitation,
        declineInvitation,
        cancelInvitation: isAdmin ? cancelInvitation : undefined,
        resendInvitation: isAdmin ? resendInvitation : undefined,
        inviteMember: isAdmin ? inviteMember : undefined,
        canManageInvitations: isAdmin,
        isLoading,
        error,
    };
}

/**
 * Hook for organization switching
 */
export function useOrganizationSwitcher() {
    const {
        organizations,
        activeOrganization,
        switchOrganization,
        canSwitchOrganization,
        isLoading,
    } = useOrganization();

    return {
        organizations,
        activeOrganization,
        switchOrganization,
        canSwitchOrganization,
        isLoading,
        hasMultipleOrganizations: organizations.length > 1,
    };
}
