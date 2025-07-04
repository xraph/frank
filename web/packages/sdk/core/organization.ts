import {
    type AcceptInvitationRequest,
    type AcceptInvitationResponse,
    type BulkCreateInvitationsRequest,
    type BulkInvitationResponse,
    type BulkMemberRoleUpdate,
    type BulkMembershipOperationResponse,
    type BulkMemberStatusUpdate,
    type BulkRemoveMembersInputBody,
    type CancelInvitationRequest,
    type CreateInvitationRequest,
    type CreateMembershipRequest,
    type CreateMembershipResponse,
    type CreateOrganizationRequest,
    type DeclineInvitationRequest,
    type DeleteOrganizationRequest,
    type DomainResponse,
    type DomainsResponse,
    type DomainVerificationRequest,
    type DomainVerificationResponse,
    type EnableOrganizationFeatureResponse,
    type ExportOrganizationDataResponse,
    type FeatureSummary,
    type GetOrganizationInvoicesRequest,
    type Invitation,
    InvitationsApi,
    type InvitationSummary,
    type InvitationValidationRequest,
    type InvitationValidationResponse,
    type ListInvitationsRequest,
    type ListOrganizationMembersRequest,
    type ListOrganizationsRequest,
    type MemberMetrics,
    type Membership,
    MembershipApi,
    type MembershipStats,
    type MemberSummary,
    type Organization,
    type OrganizationBilling,
    OrganizationsApi,
    type OrganizationSettings,
    type OrganizationSummary,
    type OrganizationUsage,
    type OrgStats,
    type OrgType,
    type PaginatedOutputInvitationSummary,
    type PaginatedOutputInvoice,
    type PaginatedOutputMembershipActivity,
    type PaginatedOutputMemberSummary,
    type PaginatedOutputOrganizationSummary,
    type RemoveMemberRequest,
    type ResendInvitationRequest,
    type SimpleMessage,
    type TransferOwnershipResponse,
    type TransferUserOwnershipRequest,
    type UpdateMemberRoleInputBody,
    type UpdateMembershipRequest,
    type UpdateMemberStatusInputBody,
    type UpdateOrganizationRequest,
    type UpdateOrganizationSettingsRequest,
    type UserSummary,
} from '@frank-auth/client';

import {type FrankAuthConfig, FrankAuthError} from './index';
import {handleError} from './errors';
import {BaseSDK} from './base';

/**
 * FrankOrganizationAPI - Organization Management SDK
 *
 * Provides comprehensive organization management capabilities including:
 * - Organization CRUD operations
 * - Member management and invitations
 * - Domain verification and management
 * - Billing and subscription management
 * - Feature management and statistics
 * - Settings and configuration
 *
 * Supports multi-tenant architecture with organization-scoped operations
 */
export class OrganizationSDK extends BaseSDK {
    private organizationsApi: OrganizationsApi;
    private membershipApi: MembershipApi;
    private invitationsApi: InvitationsApi;

    constructor(config: FrankAuthConfig, accessToken?: string) {
        super(config, accessToken)

        this.organizationsApi = new OrganizationsApi(super.config);
        this.membershipApi = new MembershipApi(super.config);
        this.invitationsApi = new InvitationsApi(super.config);
    }

    /**
     * Update access token (called by FrankAuth when token changes)
     */
    setAccessToken(token: string | null): void {
        this.accessToken = token;
    }

    // ================================
    // Organization CRUD Operations
    // ================================

    /**
     * Create a new organization
     */
    async createOrganization(request: CreateOrganizationRequest): Promise<Organization> {
        return this.executeApiCall(async () => {
            return await this.organizationsApi.createOrganization(
                {createOrganizationRequest: request},
                this.mergeHeaders()
            );
        });
    }

    /**
     * Get organization by ID
     */
    async getOrganization(id: string): Promise<Organization> {
        return this.executeApiCall(async () => {
            return await this.organizationsApi.getOrganization(
                {id},
                this.mergeHeaders()
            );
        });
    }

    /**
     * Update organization
     */
    async updateOrganization(id: string, request: UpdateOrganizationRequest): Promise<Organization> {
        return this.executeApiCall(async () => {
            return await this.organizationsApi.updateOrganization(
                {id, updateOrganizationRequest: request},
                this.mergeHeaders()
            );
        });
    }

    /**
     * Delete organization and all associated data
     */
    async deleteOrganization(id: string, request: DeleteOrganizationRequest): Promise<void> {
        return this.executeApiCall(async () => {
            await this.organizationsApi.deleteOrganization(
                {id, deleteOrganizationRequest: request},
                this.mergeHeaders()
            );
        });
    }

    /**
     * List organizations with filtering and pagination
     */
    async listOrganizations(options?: ListOrganizationsRequest): Promise<PaginatedOutputOrganizationSummary> {
        return this.executeApiCall(async () => {
            return await this.organizationsApi.listOrganizations(
                {...(options ?? {fields: null})},
                this.mergeHeaders()
            );
        });
    }

    // ================================
    // Organization Settings & Configuration
    // ================================

    /**
     * Get organization settings
     */
    async getOrganizationSettings(id: string): Promise<OrganizationSettings> {
        return this.executeApiCall(async () => {
            return await this.organizationsApi.getOrganizationSettings(
                {id},
                this.mergeHeaders()
            );
        });
    }

    /**
     * Update organization settings
     */
    async updateOrganizationSettings(
        id: string,
        request: UpdateOrganizationSettingsRequest
    ): Promise<OrganizationSettings> {
        return this.executeApiCall(async () => {
            return await this.organizationsApi.updateOrganizationSettings(
                {id, updateOrganizationSettingsRequest: request},
                this.mergeHeaders()
            );
        });
    }

    // ================================
    // Domain Management
    // ================================

    /**
     * List organization domains
     */
    async listOrganizationDomains(id: string): Promise<DomainsResponse> {
        return this.executeApiCall(async () => {
            return await this.organizationsApi.listOrganizationDomains(
                {id},
                this.mergeHeaders()
            );
        });
    }

    /**
     * Add domain to organization
     */
    async addOrganizationDomain(
        id: string,
        request: DomainVerificationRequest
    ): Promise<DomainResponse> {
        return this.executeApiCall(async () => {
            return await this.organizationsApi.addOrganizationDomain(
                {id, domainVerificationRequest: request},
                this.mergeHeaders()
            );
        });
    }

    /**
     * Verify organization domain
     */
    async verifyOrganizationDomain(id: string, domain: string): Promise<DomainVerificationResponse> {
        return this.executeApiCall(async () => {
            return await this.organizationsApi.verifyOrganizationDomain(
                {id, domain},
                this.mergeHeaders()
            );
        });
    }

    /**
     * Remove domain from organization
     */
    async removeOrganizationDomain(id: string, domain: string): Promise<void> {
        return this.executeApiCall(async () => {
            await this.organizationsApi.removeOrganizationDomain(
                {id, domain},
                this.mergeHeaders()
            );
        });
    }

    // ================================
    // Feature Management
    // ================================

    /**
     * List organization features
     */
    async listOrganizationFeatures(id: string): Promise<FeatureSummary[]> {
        return this.executeApiCall(async () => {
            return await this.organizationsApi.listOrganizationFeatures(
                {id},
                this.mergeHeaders()
            );
        });
    }

    /**
     * Enable organization feature
     */
    async enableOrganizationFeature(id: string, feature: string): Promise<EnableOrganizationFeatureResponse> {
        return this.executeApiCall(async () => {
            return await this.organizationsApi.enableOrganizationFeature(
                {id, feature},
                this.mergeHeaders()
            );
        });
    }

    /**
     * Disable organization feature
     */
    async disableOrganizationFeature(id: string, feature: string): Promise<void> {
        return this.executeApiCall(async () => {
            await this.organizationsApi.disableOrganizationFeature(
                {id, feature},
                this.mergeHeaders()
            );
        });
    }

    // ================================
    // Statistics & Analytics
    // ================================

    /**
     * Get organization statistics
     */
    async getOrganizationStats(id: string): Promise<OrgStats> {
        return this.executeApiCall(async () => {
            return await this.organizationsApi.getOrganizationStats(
                {id},
                this.mergeHeaders()
            );
        });
    }

    /**
     * Get organization usage metrics
     */
    async getOrganizationUsage(id: string): Promise<OrganizationUsage> {
        return this.executeApiCall(async () => {
            return await this.organizationsApi.getOrganizationUsage(
                {id},
                this.mergeHeaders()
            );
        });
    }

    // ================================
    // Billing & Subscription Management
    // ================================

    /**
     * Get organization billing information
     */
    async getOrganizationBilling(id: string): Promise<OrganizationBilling> {
        return this.executeApiCall(async () => {
            return await this.organizationsApi.getOrganizationBilling(
                {id},
                this.mergeHeaders()
            );
        });
    }

    /**
     * Get organization invoices with filtering
     */
    async getOrganizationInvoices(id: string, options?: Omit<GetOrganizationInvoicesRequest, 'id'>): Promise<PaginatedOutputInvoice> {
        return this.executeApiCall(async () => {
            return await this.organizationsApi.getOrganizationInvoices(
                {id, ...(options ?? {fields: null})},
                this.mergeHeaders()
            );
        });
    }

    // ================================
    // Ownership Management
    // ================================

    /**
     * Get organization ownership information
     */
    async getOrganizationOwnership(id: string): Promise<UserSummary> {
        return this.executeApiCall(async () => {
            return await this.organizationsApi.getOrganizationOwnership(
                {id},
                this.mergeHeaders()
            );
        });
    }

    /**
     * Transfer organization ownership
     */
    async transferOrganizationOwnership(
        id: string,
        request: TransferUserOwnershipRequest
    ): Promise<TransferOwnershipResponse> {
        return this.executeApiCall(async () => {
            return await this.organizationsApi.transferOrganizationOwnership(
                {id, transferUserOwnershipRequest: request},
                this.mergeHeaders()
            );
        });
    }

    // ================================
    // Data Export & Compliance
    // ================================

    /**
     * Export organization data for compliance/backup
     */
    async exportOrganizationData(id: string): Promise<ExportOrganizationDataResponse> {
        return this.executeApiCall(async () => {
            return await this.organizationsApi.exportOrganizationData(
                {id},
                this.mergeHeaders()
            );
        });
    }

    // ================================
    // Organization Membership Management
    // ================================

    /**
     * List organization members with filtering and pagination
     */
    async listMembers(orgId: string, options?: Omit<ListOrganizationMembersRequest, 'orgId'>): Promise<PaginatedOutputMemberSummary> {
        return this.executeApiCall(async () => {
            return await this.membershipApi.listOrganizationMembers(
                {orgId, ...(options ?? {fields: null})},
                this.mergeHeaders()
            );
        });
    }

    /**
     * Get detailed member information
     */
    async getMember(organizationId: string, userId: string): Promise<Membership> {
        return this.executeApiCall(async () => {
            return await this.membershipApi.getMember(
                {orgId: organizationId, userId},
                this.mergeHeaders()
            );
        });
    }

    /**
     * Add existing user as organization member
     */
    async addMember(organizationId: string, request: CreateMembershipRequest): Promise<CreateMembershipResponse> {
        return this.executeApiCall(async () => {
            return await this.membershipApi.addMember(
                {orgId: organizationId, createMembershipRequest: request},
                this.mergeHeaders()
            );
        });
    }

    /**
     * Update member information
     */
    async updateMember(organizationId: string, userId: string, request: UpdateMembershipRequest): Promise<Membership> {
        return this.executeApiCall(async () => {
            return await this.membershipApi.updateMember(
                {orgId: organizationId, userId, updateMembershipRequest: request},
                this.mergeHeaders()
            );
        });
    }

    /**
     * Update member role
     */
    async updateMemberRole(organizationId: string, userId: string, request: UpdateMemberRoleInputBody): Promise<Membership> {
        return this.executeApiCall(async () => {
            return await this.membershipApi.updateMemberRole(
                {orgId: organizationId, userId, updateMemberRoleInputBody: request},
                this.mergeHeaders()
            );
        });
    }

    /**
     * Update member status (active, inactive, suspended)
     */
    async updateMemberStatus(organizationId: string, userId: string, request: UpdateMemberStatusInputBody): Promise<Membership> {
        return this.executeApiCall(async () => {
            return await this.membershipApi.updateMemberStatus(
                {orgId: organizationId, userId, updateMemberStatusInputBody: request},
                this.mergeHeaders()
            );
        });
    }

    /**
     * Remove member from organization
     */
    async removeMember(organizationId: string, userId: string, request: RemoveMemberRequest): Promise<void> {
        return this.executeApiCall(async () => {
            await this.membershipApi.removeMember(
                {orgId: organizationId, userId, removeMemberRequest: request},
                this.mergeHeaders()
            );
        });
    }

    /**
     * Bulk remove multiple members
     */
    async bulkRemoveMembers(organizationId: string, request: BulkRemoveMembersInputBody): Promise<BulkMembershipOperationResponse> {
        return this.executeApiCall(async () => {
            return await this.membershipApi.bulkRemoveMembers(
                {orgId: organizationId, bulkRemoveMembersInputBody: request},
                this.mergeHeaders()
            );
        });
    }

    /**
     * Bulk update member roles
     */
    async bulkUpdateMemberRoles(organizationId: string, updates: BulkMemberRoleUpdate[]): Promise<BulkMembershipOperationResponse> {
        return this.executeApiCall(async () => {
            return await this.membershipApi.bulkUpdateMemberRoles(
                {orgId: organizationId, bulkMemberRoleUpdate: updates},
                this.mergeHeaders()
            );
        });
    }

    /**
     * Bulk update member status
     */
    async bulkUpdateMemberStatus(organizationId: string, updates: BulkMemberStatusUpdate[]): Promise<BulkMembershipOperationResponse> {
        return this.executeApiCall(async () => {
            return await this.membershipApi.bulkUpdateMemberStatus(
                {orgId: organizationId, bulkMemberStatusUpdate: updates},
                this.mergeHeaders()
            );
        });
    }

    // ================================
    // Member Permission Management
    // ================================

    /**
     * Check if member has specific permission
     */
    async checkMemberPermission(organizationId: string, userId: string, permission: string): Promise<{
        [key: string]: any
    }> {
        return this.executeApiCall(async () => {
            return await this.membershipApi.checkMemberPermission(
                {orgId: organizationId, userId, permission},
                this.mergeHeaders()
            );
        });
    }

    /**
     * Get all permissions for a member
     */
    async getMemberPermissions(organizationId: string, userId: string): Promise<{ [key: string]: any }> {
        return this.executeApiCall(async () => {
            return await this.membershipApi.getMemberPermissions(
                {orgId: organizationId, userId},
                this.mergeHeaders()
            );
        });
    }

    // ================================
    // Member Contact Management
    // ================================

    /**
     * Set member as billing contact
     */
    async setBillingContact(organizationId: string, userId: string): Promise<SimpleMessage> {
        return this.executeApiCall(async () => {
            return await this.membershipApi.setBillingContact(
                {orgId: organizationId, userId},
                this.mergeHeaders()
            );
        });
    }

    /**
     * Remove member as billing contact
     */
    async removeBillingContact(organizationId: string, userId: string): Promise<void> {
        return this.executeApiCall(async () => {
            await this.membershipApi.removeBillingContact(
                {orgId: organizationId, userId},
                this.mergeHeaders()
            );
        });
    }

    /**
     * Set member as primary contact
     */
    async setPrimaryContact(organizationId: string, userId: string): Promise<SimpleMessage> {
        return this.executeApiCall(async () => {
            return await this.membershipApi.setPrimaryContact(
                {orgId: organizationId, userId},
                this.mergeHeaders()
            );
        });
    }

    // ================================
    // Membership Analytics & Statistics
    // ================================

    /**
     * Get comprehensive membership statistics
     */
    async getMembershipStats(organizationId: string): Promise<MembershipStats> {
        return this.executeApiCall(async () => {
            return await this.membershipApi.getMembershipStats(
                {orgId: organizationId},
                this.mergeHeaders()
            );
        });
    }

    /**
     * Get member metrics for specific time period
     */
    async getMemberMetrics(organizationId: string, period?: string): Promise<MemberMetrics> {
        return this.executeApiCall(async () => {
            return await this.membershipApi.getMemberMetrics(
                {orgId: organizationId, period},
                this.mergeHeaders()
            );
        });
    }

    /**
     * Get recent member activity
     */
    async getMemberActivity(organizationId: string, days?: number): Promise<PaginatedOutputMembershipActivity> {
        return this.executeApiCall(async () => {
            return await this.membershipApi.getMemberActivity(
                {orgId: organizationId, days},
                this.mergeHeaders()
            );
        });
    }

    // ================================
    // Organization Invitation Management
    // ================================

    /**
     * Create and send organization invitation
     */
    async createInvitation(organizationId: string, request: CreateInvitationRequest): Promise<Invitation> {
        return this.executeApiCall(async () => {
            return await this.invitationsApi.createInvitation(
                {orgId: organizationId, createInvitationRequest: request},
                this.mergeHeaders()
            );
        });
    }

    /**
     * Create multiple invitations at once
     */
    async bulkCreateInvitations(organizationId: string, request: BulkCreateInvitationsRequest): Promise<BulkInvitationResponse> {
        return this.executeApiCall(async () => {
            return await this.invitationsApi.bulkInvitations(
                {orgId: organizationId, bulkCreateInvitationsRequest: request},
                this.mergeHeaders()
            );
        });
    }

    /**
     * List organization invitations with filtering
     */
    async listInvitations(orgId: string, options?: Omit<ListInvitationsRequest, 'orgId'>): Promise<PaginatedOutputInvitationSummary> {
        return this.executeApiCall(async () => {
            return await this.invitationsApi.listInvitations(
                {orgId, ...(options ?? {fields: null})},
                this.mergeHeaders()
            );
        });
    }

    /**
     * Get invitation details
     */
    async getInvitation(organizationId: string, invitationId: string): Promise<Invitation> {
        return this.executeApiCall(async () => {
            return await this.invitationsApi.getInvitation(
                {orgId: organizationId, invitationId},
                this.mergeHeaders()
            );
        });
    }

    /**
     * Cancel pending invitation
     */
    async cancelInvitation(organizationId: string, invitationId: string, request: CancelInvitationRequest): Promise<SimpleMessage> {
        return this.executeApiCall(async () => {
            return await this.invitationsApi.cancelInvitation(
                {orgId: organizationId, invitationId, cancelInvitationRequest: request},
                this.mergeHeaders()
            );
        });
    }

    /**
     * Resend invitation email
     */
    async resendInvitation(organizationId: string, invitationId: string, request: ResendInvitationRequest): Promise<SimpleMessage> {
        return this.executeApiCall(async () => {
            return await this.invitationsApi.resendInvitation(
                {orgId: organizationId, invitationId, resendInvitationRequest: request},
                this.mergeHeaders()
            );
        });
    }

    /**
     * Accept organization invitation (typically called by invitee)
     */
    async acceptInvitation(request: AcceptInvitationRequest): Promise<AcceptInvitationResponse> {
        return this.executeApiCall(async () => {
            return await this.invitationsApi.acceptInvitation(
                {acceptInvitationRequest: request},
                this.mergeHeaders()
            );
        });
    }

    /**
     * Decline organization invitation (typically called by invitee)
     */
    async declineInvitation(request: DeclineInvitationRequest): Promise<SimpleMessage> {
        return this.executeApiCall(async () => {
            return await this.invitationsApi.declineInvitation(
                {declineInvitationRequest: request},
                this.mergeHeaders()
            );
        });
    }

    /**
     * Validate invitation token without accepting
     */
    async validateInvitation(request: InvitationValidationRequest): Promise<InvitationValidationResponse> {
        return this.executeApiCall(async () => {
            return await this.invitationsApi.validateInvitation(
                {invitationValidationRequest: request},
                this.mergeHeaders()
            );
        });
    }

    // ================================
    // Utility Methods
    // ================================

    /**
     * Check if user is organization owner
     */
    async isOrganizationOwner(organizationId: string, userId?: string): Promise<boolean> {
        return this.executeApiCall(async () => {
            const ownership = await this.getOrganizationOwnership(organizationId);
            return userId ? ownership.id === userId : true; // If no userId provided, assume current user
        }, false).catch(() => false); // Return false if we can't get ownership info
    }

    /**
     * Get organization by slug
     */
    async getOrganizationBySlug(slug: string, options?: ListOrganizationsRequest): Promise<Organization | null> {
        return this.executeApiCall(async () => {
            const response = await this.listOrganizations({
                search: slug,
                ...(options ?? {fields: null}),
            });

            const organizations = response.data || [];
            const org = organizations.find(o => o.slug === slug);

            return org ? await this.getOrganization(org.id) : null;
        });
    }

    /**
     * Check if organization has feature enabled
     */
    async hasFeatureEnabled(organizationId: string, featureName: string): Promise<boolean> {
        return this.executeApiCall(async () => {
            const features = await this.listOrganizationFeatures(organizationId);
            const feature = features.find(f => f.name === featureName);
            return feature?.enabled ?? false;
        }, false).catch(() => false);
    }

    /**
     * Get organization summary for listings
     */
    async getOrganizationSummary(id: string): Promise<OrganizationSummary> {
        return this.executeApiCall(async () => {
            const organization = await this.getOrganization(id);

            // Convert full organization to summary format
            return {
                id: organization.id,
                name: organization.name,
                slug: organization.slug,
                logoUrl: organization.logoUrl,
                plan: organization.plan,
                active: organization.active,
                orgType: organization.orgType,
                memberCount: organization.stats?.totalMembers || 0,
                role: ''
            };
        });
    }

    // ================================
    // Advanced Utility Methods
    // ================================

    /**
     * Get active members count
     */
    async getActiveMembersCount(organizationId: string): Promise<number> {
        return this.executeApiCall(async () => {
            const stats = await this.getMembershipStats(organizationId);
            return stats.activeMembers;
        }, false).catch(() => 0);
    }

    /**
     * Get pending invitations count
     */
    async getPendingInvitationsCount(organizationId: string): Promise<number> {
        return this.executeApiCall(async () => {
            const invitations = await this.listInvitations(organizationId, {
                fields: null,
                status: 'pending',
                limit: 1,
            });
            return invitations.pagination.totalCount || 0;
        }, false).catch(() => 0);
    }

    /**
     * Check if user is member of organization
     */
    async isMember(organizationId: string, userId: string): Promise<boolean> {
        return this.executeApiCall(async () => {
            await this.getMember(organizationId, userId);
            return true;
        }, false).catch(() => false);
    }

    /**
     * Check if user has specific role in organization
     */
    async hasRole(organizationId: string, userId: string, roleName: string): Promise<boolean> {
        return this.executeApiCall(async () => {
            const member = await this.getMember(organizationId, userId);
            return member.role?.name === roleName;
        }, false).catch(() => false);
    }

    /**
     * Get members by role
     */
    async getMembersByRole(organizationId: string, roleName: string): Promise<MemberSummary[]> {
        return this.executeApiCall(async () => {
            const members = await this.listMembers(organizationId, {fields: null, limit: 1000});
            return (members.data || []).filter(member => member.roleName === roleName);
        }, false).catch(() => []);
    }

    /**
     * Get organization owners
     */
    async getOwners(organizationId: string): Promise<MemberSummary[]> {
        return this.executeApiCall(async () => {
            const members = await this.listMembers(organizationId, {fields: null, limit: 1000});
            return (members.data || []).filter(member => member.isOwner);
        }, false).catch(() => []);
    }

    /**
     * Get billing contacts
     */
    async getBillingContacts(organizationId: string, options?: Omit<ListOrganizationMembersRequest, "orgId">): Promise<MemberSummary[]> {
        return this.executeApiCall(async () => {
            const members = await this.listMembers(organizationId, options);
            return (members.data || []).filter(member => member.isBilling);
        }, false).catch(() => []);
    }

    /**
     * Invite user by email with role
     */
    async inviteUserByEmail(
        organizationId: string,
        email: string,
        roleId: string,
        options?: {
            message?: string;
            redirectUrl?: string;
            customFields?: object;
        }
    ): Promise<Invitation> {
        return this.executeApiCall(async () => {
            return await this.createInvitation(organizationId, {
                email,
                roleId,
                message: options?.message,
                redirectUrl: options?.redirectUrl,
                customFields: options?.customFields,
                sendEmail: true,
            });
        });
    }

    /**
     * Invite multiple users at once
     */
    async inviteMultipleUsers(
        organizationId: string,
        invitations: Array<{ email: string; roleId: string; message?: string }>
    ): Promise<BulkInvitationResponse> {
        return this.executeApiCall(async () => {
            return await this.bulkCreateInvitations(organizationId, {
                invitations: invitations.map(inv => ({
                    email: inv.email,
                    roleId: inv.roleId,
                    message: inv.message,
                })),
                sendEmails: true,
            });
        });
    }

    /**
     * Get organization health metrics
     */
    async getOrganizationHealth(organizationId: string): Promise<{
        totalMembers: number;
        activeMembers: number;
        pendingInvitations: number;
        recentActivity: number;
        memberGrowthRate: number;
        inviteAcceptanceRate: number;
    }> {
        return this.executeApiCall(async () => {
            const [stats, invitations] = await Promise.all([
                this.getMembershipStats(organizationId),
                this.listInvitations(organizationId, {fields: null, status: 'pending', limit: 1}),
            ]);

            const inviteAcceptanceRate = stats.recentInvites > 0
                ? (stats.recentJoins / stats.recentInvites) * 100
                : 0;

            return {
                totalMembers: stats.totalMembers,
                activeMembers: stats.activeMembers,
                pendingInvitations: invitations.pagination.totalCount || 0,
                recentActivity: stats.recentJoins,
                memberGrowthRate: stats.growthRate,
                inviteAcceptanceRate: Math.round(inviteAcceptanceRate * 100) / 100,
            };
        });
    }
}

// ================================
// Type Exports for Convenience
// ================================

export type {
    // Core Organization Types
    Organization,
    OrganizationSummary,
    CreateOrganizationRequest,
    UpdateOrganizationRequest,
    DeleteOrganizationRequest,
    OrganizationSettings,
    UpdateOrganizationSettingsRequest,
    OrganizationBilling,
    OrganizationUsage,
    OrgStats,
    FeatureSummary,
    DomainResponse,
    DomainVerificationRequest,
    DomainVerificationResponse,
    DomainsResponse,
    TransferUserOwnershipRequest,
    TransferOwnershipResponse,
    ExportOrganizationDataResponse,
    EnableOrganizationFeatureResponse,
    PaginatedOutputOrganizationSummary,
    PaginatedOutputInvoice,
    UserSummary,
    OrgType,

    // Membership Types
    Membership,
    MemberSummary,
    MembershipStats,
    MemberMetrics,
    PaginatedOutputMemberSummary,
    PaginatedOutputMembershipActivity,
    CreateMembershipRequest,
    CreateMembershipResponse,
    UpdateMembershipRequest,
    UpdateMemberRoleInputBody,
    UpdateMemberStatusInputBody,
    RemoveMemberRequest,
    BulkMemberRoleUpdate,
    BulkMemberStatusUpdate,
    BulkRemoveMembersInputBody,
    BulkMembershipOperationResponse,

    // Invitation Types
    Invitation,
    InvitationSummary,
    PaginatedOutputInvitationSummary,
    CreateInvitationRequest,
    AcceptInvitationRequest,
    AcceptInvitationResponse,
    DeclineInvitationRequest,
    CancelInvitationRequest,
    ResendInvitationRequest,
    BulkCreateInvitationsRequest,
    BulkInvitationResponse,
    InvitationValidationRequest,
    InvitationValidationResponse,

    // Utility Types
    SimpleMessage,
};