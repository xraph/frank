import {
    AcceptInvitationRequest,
    AcceptInvitationResponse,
    BulkCreateInvitationsRequest,
    BulkInvitationResponse,
    BulkMemberRoleUpdate,
    BulkMembershipOperationResponse,
    BulkMemberStatusUpdate,
    BulkRemoveMembersInputBody,
    CancelInvitationRequest,
    Configuration,
    CreateInvitationRequest,
    CreateMembershipRequest,
    CreateMembershipResponse,
    CreateOrganizationRequest,
    DeclineInvitationRequest,
    DeleteOrganizationRequest,
    DomainResponse,
    DomainsResponse,
    DomainVerificationRequest,
    DomainVerificationResponse,
    EnableOrganizationFeatureResponse,
    ExportOrganizationDataResponse,
    FeatureSummary,
    Invitation,
    InvitationsApi,
    InvitationSummary,
    InvitationValidationRequest,
    InvitationValidationResponse,
    MemberMetrics,
    Membership,
    MembershipApi,
    MembershipStats,
    MemberSummary,
    Organization,
    OrganizationBilling,
    OrganizationsApi,
    OrganizationSettings,
    OrganizationSummary,
    OrganizationUsage,
    OrgStats,
    OrgType,
    PaginatedOutputInvitationSummary,
    PaginatedOutputInvoice,
    PaginatedOutputMembershipActivity,
    PaginatedOutputMemberSummary,
    PaginatedOutputOrganizationSummary,
    RemoveMemberRequest,
    ResendInvitationRequest,
    SimpleMessage,
    TransferOwnershipResponse,
    TransferUserOwnershipRequest,
    UpdateMemberRoleInputBody,
    UpdateMembershipRequest,
    UpdateMemberStatusInputBody,
    UpdateOrganizationRequest,
    UpdateOrganizationSettingsRequest,
    UserSummary,
} from '@frank-auth/client';

import {FrankAuthConfig, FrankAuthError} from './index';
import {handleError} from './errors';

/**
 * FrankOrganization - Organization Management SDK
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
export class FrankOrganization {
    private config: FrankAuthConfig;
    private organizationsApi: OrganizationsApi;
    private membershipApi: MembershipApi;
    private invitationsApi: InvitationsApi;
    private accessToken: string | null = null;

    constructor(config: FrankAuthConfig, accessToken?: string) {
        this.config = config;
        this.accessToken = accessToken || null;

        const configuration = new Configuration({
            basePath: config.apiUrl,
            accessToken: () => this.accessToken || '',
            credentials: 'include',
            headers: {
                'X-Publishable-Key': config.publishableKey,
            },
        });

        this.organizationsApi = new OrganizationsApi(configuration);
        this.membershipApi = new MembershipApi(configuration);
        this.invitationsApi = new InvitationsApi(configuration);
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
        try {
            return await this.organizationsApi.createOrganization({
                createOrganizationRequest: request
            });
        } catch (error) {
            throw await handleError(error)
        }
    }

    /**
     * Get organization by ID
     */
    async getOrganization(id: string): Promise<Organization> {
        try {
            return await this.organizationsApi.getOrganization({ id });
        } catch (error) {
            throw await handleError(error)
        }
    }

    /**
     * Update organization
     */
    async updateOrganization(id: string, request: UpdateOrganizationRequest): Promise<Organization> {
        try {
            return await this.organizationsApi.updateOrganization({
                id,
                updateOrganizationRequest: request
            });
        } catch (error) {
            throw await handleError(error)
        }
    }

    /**
     * Delete organization and all associated data
     */
    async deleteOrganization(id: string, request: DeleteOrganizationRequest): Promise<void> {
        try {
            await this.organizationsApi.deleteOrganization({
                id,
                deleteOrganizationRequest: request
            });
        } catch (error) {
            throw await handleError(error)
        }
    }

    /**
     * List organizations with filtering and pagination
     */
    async listOrganizations(options?: {
        after?: string;
        before?: string;
        first?: number;
        last?: number;
        limit?: number;
        offset?: number;
        fields?: string[];
        orderBy?: string[];
        page?: number;
        orgType?: OrgType;
        plan?: string;
        active?: boolean;
        search?: string;
        ownerId?: string;
        hasTrial?: boolean;
        ssoEnabled?: boolean;
    }): Promise<PaginatedOutputOrganizationSummary> {
        try {
            return await this.organizationsApi.listOrganizations({
                after: options?.after,
                before: options?.before,
                first: options?.first,
                last: options?.last,
                limit: options?.limit,
                offset: options?.offset,
                fields: options?.fields,
                orderBy: options?.orderBy,
                page: options?.page,
                orgType: options?.orgType,
                plan: options?.plan,
                active: options?.active,
                search: options?.search,
                ownerId: options?.ownerId,
                hasTrial: options?.hasTrial,
                ssoEnabled: options?.ssoEnabled,
            });
        } catch (error) {
            throw await handleError(error)
        }
    }

    // ================================
    // Organization Settings & Configuration
    // ================================

    /**
     * Get organization settings
     */
    async getOrganizationSettings(id: string): Promise<OrganizationSettings> {
        try {
            return await this.organizationsApi.getOrganizationSettings({ id });
        } catch (error) {
            throw await handleError(error)
        }
    }

    /**
     * Update organization settings
     */
    async updateOrganizationSettings(
        id: string,
        request: UpdateOrganizationSettingsRequest
    ): Promise<OrganizationSettings> {
        try {
            return await this.organizationsApi.updateOrganizationSettings({
                id,
                updateOrganizationSettingsRequest: request
            });
        } catch (error) {
            throw await handleError(error)
        }
    }

    // ================================
    // Domain Management
    // ================================

    /**
     * List organization domains
     */
    async listOrganizationDomains(id: string): Promise<DomainsResponse> {
        try {
            return await this.organizationsApi.listOrganizationDomains({ id });
        } catch (error) {
            throw await handleError(error)
        }
    }

    /**
     * Add domain to organization
     */
    async addOrganizationDomain(
        id: string,
        request: DomainVerificationRequest
    ): Promise<DomainResponse> {
        try {
            return await this.organizationsApi.addOrganizationDomain({
                id,
                domainVerificationRequest: request
            });
        } catch (error) {
            throw await handleError(error)
        }
    }

    /**
     * Verify organization domain
     */
    async verifyOrganizationDomain(id: string, domain: string): Promise<DomainVerificationResponse> {
        try {
            return await this.organizationsApi.verifyOrganizationDomain({ id, domain });
        } catch (error) {
            throw await handleError(error)
        }
    }

    /**
     * Remove domain from organization
     */
    async removeOrganizationDomain(id: string, domain: string): Promise<void> {
        try {
            await this.organizationsApi.removeOrganizationDomain({ id, domain });
        } catch (error) {
            throw await handleError(error)
        }
    }

    // ================================
    // Feature Management
    // ================================

    /**
     * List organization features
     */
    async listOrganizationFeatures(id: string): Promise<FeatureSummary[]> {
        try {
            return await this.organizationsApi.listOrganizationFeatures({ id });
        } catch (error) {
            throw await handleError(error)
        }
    }

    /**
     * Enable organization feature
     */
    async enableOrganizationFeature(id: string, feature: string): Promise<EnableOrganizationFeatureResponse> {
        try {
            return await this.organizationsApi.enableOrganizationFeature({ id, feature });
        } catch (error) {
            throw await handleError(error)
        }
    }

    /**
     * Disable organization feature
     */
    async disableOrganizationFeature(id: string, feature: string): Promise<void> {
        try {
            await this.organizationsApi.disableOrganizationFeature({ id, feature });
        } catch (error) {
            throw await handleError(error)
        }
    }

    // ================================
    // Statistics & Analytics
    // ================================

    /**
     * Get organization statistics
     */
    async getOrganizationStats(id: string): Promise<OrgStats> {
        try {
            return await this.organizationsApi.getOrganizationStats({ id });
        } catch (error) {
            throw await handleError(error)
        }
    }

    /**
     * Get organization usage metrics
     */
    async getOrganizationUsage(id: string): Promise<OrganizationUsage> {
        try {
            return await this.organizationsApi.getOrganizationUsage({ id });
        } catch (error) {
            throw await handleError(error)
        }
    }

    // ================================
    // Billing & Subscription Management
    // ================================

    /**
     * Get organization billing information
     */
    async getOrganizationBilling(id: string): Promise<OrganizationBilling> {
        try {
            return await this.organizationsApi.getOrganizationBilling({ id });
        } catch (error) {
            throw await handleError(error)
        }
    }

    /**
     * Get organization invoices with filtering
     */
    async getOrganizationInvoices(id: string, options?: {
        after?: string;
        before?: string;
        first?: number;
        last?: number;
        limit?: number;
        offset?: number;
        fields?: string[];
        orderBy?: string[];
        page?: number;
        status?: 'paid' | 'unpaid' | 'draft' | 'void';
        startDate?: Date;
        endDate?: Date;
        dueBefore?: Date;
        minAmount?: number;
        maxAmount?: number;
    }): Promise<PaginatedOutputInvoice> {
        try {
            return await this.organizationsApi.getOrganizationInvoices({
                id,
                after: options?.after,
                before: options?.before,
                first: options?.first,
                last: options?.last,
                limit: options?.limit,
                offset: options?.offset,
                fields: options?.fields,
                orderBy: options?.orderBy,
                page: options?.page,
                status: options?.status as any,
                startDate: options?.startDate,
                endDate: options?.endDate,
                dueBefore: options?.dueBefore,
                minAmount: options?.minAmount,
                maxAmount: options?.maxAmount,
            });
        } catch (error) {
            throw await handleError(error)
        }
    }

    // ================================
    // Ownership Management
    // ================================

    /**
     * Get organization ownership information
     */
    async getOrganizationOwnership(id: string): Promise<UserSummary> {
        try {
            return await this.organizationsApi.getOrganizationOwnership({ id });
        } catch (error) {
            throw await handleError(error)
        }
    }

    /**
     * Transfer organization ownership
     */
    async transferOrganizationOwnership(
        id: string,
        request: TransferUserOwnershipRequest
    ): Promise<TransferOwnershipResponse> {
        try {
            return await this.organizationsApi.transferOrganizationOwnership({
                id,
                transferUserOwnershipRequest: request
            });
        } catch (error) {
            throw await handleError(error)
        }
    }

    // ================================
    // Data Export & Compliance
    // ================================

    /**
     * Export organization data for compliance/backup
     */
    async exportOrganizationData(id: string): Promise<ExportOrganizationDataResponse> {
        try {
            return await this.organizationsApi.exportOrganizationData({ id });
        } catch (error) {
            throw await handleError(error)
        }
    }

    // ================================
    // Organization Membership Management
    // ================================

    /**
     * List organization members with filtering and pagination
     */
    async listMembers(organizationId: string, options?: {
        after?: string;
        before?: string;
        first?: number;
        last?: number;
        limit?: number;
        offset?: number;
        fields?: string[];
        orderBy?: string[];
        page?: number;
    }): Promise<PaginatedOutputMemberSummary> {
        try {
            return await this.membershipApi.listOrganizationMembers({
                orgId: organizationId,
                after: options?.after,
                before: options?.before,
                first: options?.first,
                last: options?.last,
                limit: options?.limit,
                offset: options?.offset,
                fields: options?.fields,
                orderBy: options?.orderBy,
                page: options?.page,
            });
        } catch (error) {
            throw await handleError(error)
        }
    }

    /**
     * Get detailed member information
     */
    async getMember(organizationId: string, userId: string): Promise<Membership> {
        try {
            return await this.membershipApi.getMember({
                orgId: organizationId,
                userId,
            });
        } catch (error) {
            throw await handleError(error)
        }
    }

    /**
     * Add existing user as organization member
     */
    async addMember(organizationId: string, request: CreateMembershipRequest): Promise<CreateMembershipResponse> {
        try {
            return await this.membershipApi.addMember({
                orgId: organizationId,
                createMembershipRequest: request,
            });
        } catch (error) {
            throw await handleError(error)
        }
    }

    /**
     * Update member information
     */
    async updateMember(organizationId: string, userId: string, request: UpdateMembershipRequest): Promise<Membership> {
        try {
            return await this.membershipApi.updateMember({
                orgId: organizationId,
                userId,
                updateMembershipRequest: request,
            });
        } catch (error) {
            throw await handleError(error)
        }
    }

    /**
     * Update member role
     */
    async updateMemberRole(organizationId: string, userId: string, request: UpdateMemberRoleInputBody): Promise<Membership> {
        try {
            return await this.membershipApi.updateMemberRole({
                orgId: organizationId,
                userId,
                updateMemberRoleInputBody: request,
            });
        } catch (error) {
            throw await handleError(error)
        }
    }

    /**
     * Update member status (active, inactive, suspended)
     */
    async updateMemberStatus(organizationId: string, userId: string, request: UpdateMemberStatusInputBody): Promise<Membership> {
        try {
            return await this.membershipApi.updateMemberStatus({
                orgId: organizationId,
                userId,
                updateMemberStatusInputBody: request,
            });
        } catch (error) {
            throw await handleError(error)
        }
    }

    /**
     * Remove member from organization
     */
    async removeMember(organizationId: string, userId: string, request: RemoveMemberRequest): Promise<void> {
        try {
            await this.membershipApi.removeMember({
                orgId: organizationId,
                userId,
                removeMemberRequest: request,
            });
        } catch (error) {
            throw await handleError(error)
        }
    }

    /**
     * Bulk remove multiple members
     */
    async bulkRemoveMembers(organizationId: string, request: BulkRemoveMembersInputBody): Promise<BulkMembershipOperationResponse> {
        try {
            return await this.membershipApi.bulkRemoveMembers({
                orgId: organizationId,
                bulkRemoveMembersInputBody: request,
            });
        } catch (error) {
            throw await handleError(error)
        }
    }

    /**
     * Bulk update member roles
     */
    async bulkUpdateMemberRoles(organizationId: string, updates: BulkMemberRoleUpdate[]): Promise<BulkMembershipOperationResponse> {
        try {
            return await this.membershipApi.bulkUpdateMemberRoles({
                orgId: organizationId,
                bulkMemberRoleUpdate: updates,
            });
        } catch (error) {
            throw await handleError(error)
        }
    }

    /**
     * Bulk update member status
     */
    async bulkUpdateMemberStatus(organizationId: string, updates: BulkMemberStatusUpdate[]): Promise<BulkMembershipOperationResponse> {
        try {
            return await this.membershipApi.bulkUpdateMemberStatus({
                orgId: organizationId,
                bulkMemberStatusUpdate: updates,
            });
        } catch (error) {
            throw await handleError(error)
        }
    }

    // ================================
    // Member Permission Management
    // ================================

    /**
     * Check if member has specific permission
     */
    async checkMemberPermission(organizationId: string, userId: string, permission: string): Promise<{ [key: string]: any }> {
        try {
            return await this.membershipApi.checkMemberPermission({
                orgId: organizationId,
                userId,
                permission,
            });
        } catch (error) {
            throw await handleError(error)
        }
    }

    /**
     * Get all permissions for a member
     */
    async getMemberPermissions(organizationId: string, userId: string): Promise<{ [key: string]: any }> {
        try {
            return await this.membershipApi.getMemberPermissions({
                orgId: organizationId,
                userId,
            });
        } catch (error) {
            throw await handleError(error)
        }
    }

    // ================================
    // Member Contact Management
    // ================================

    /**
     * Set member as billing contact
     */
    async setBillingContact(organizationId: string, userId: string): Promise<SimpleMessage> {
        try {
            return await this.membershipApi.setBillingContact({
                orgId: organizationId,
                userId,
            });
        } catch (error) {
            throw await handleError(error)
        }
    }

    /**
     * Remove member as billing contact
     */
    async removeBillingContact(organizationId: string, userId: string): Promise<void> {
        try {
            await this.membershipApi.removeBillingContact({
                orgId: organizationId,
                userId,
            });
        } catch (error) {
            throw await handleError(error)
        }
    }

    /**
     * Set member as primary contact
     */
    async setPrimaryContact(organizationId: string, userId: string): Promise<SimpleMessage> {
        try {
            return await this.membershipApi.setPrimaryContact({
                orgId: organizationId,
                userId,
            });
        } catch (error) {
            throw await handleError(error)
        }
    }

    // ================================
    // Membership Analytics & Statistics
    // ================================

    /**
     * Get comprehensive membership statistics
     */
    async getMembershipStats(organizationId: string): Promise<MembershipStats> {
        try {
            return await this.membershipApi.getMembershipStats({
                orgId: organizationId,
            });
        } catch (error) {
            throw await handleError(error)
        }
    }

    /**
     * Get member metrics for specific time period
     */
    async getMemberMetrics(organizationId: string, period?: string): Promise<MemberMetrics> {
        try {
            return await this.membershipApi.getMemberMetrics({
                orgId: organizationId,
                period,
            });
        } catch (error) {
            throw await handleError(error)
        }
    }

    /**
     * Get recent member activity
     */
    async getMemberActivity(organizationId: string, days?: number): Promise<PaginatedOutputMembershipActivity> {
        try {
            return await this.membershipApi.getMemberActivity({
                orgId: organizationId,
                days,
            });
        } catch (error) {
            throw await handleError(error)
        }
    }

    // ================================
    // Organization Invitation Management
    // ================================

    /**
     * Create and send organization invitation
     */
    async createInvitation(organizationId: string, request: CreateInvitationRequest): Promise<Invitation> {
        try {
            return await this.invitationsApi.createInvitation({
                orgId: organizationId,
                createInvitationRequest: request,
            });
        } catch (error) {
            throw await handleError(error)
        }
    }

    /**
     * Create multiple invitations at once
     */
    async bulkCreateInvitations(organizationId: string, request: BulkCreateInvitationsRequest): Promise<BulkInvitationResponse> {
        try {
            return await this.invitationsApi.bulkInvitations({
                orgId: organizationId,
                bulkCreateInvitationsRequest: request,
            });
        } catch (error) {
            throw await handleError(error)
        }
    }

    /**
     * List organization invitations with filtering
     */
    async listInvitations(organizationId: string, options?: {
        after?: string;
        before?: string;
        first?: number;
        last?: number;
        limit?: number;
        offset?: number;
        fields?: string[];
        orderBy?: string[];
        page?: number;
        status?: 'pending' | 'accepted' | 'declined' | 'expired' | 'cancelled';
        email?: string;
        roleId?: string;
        invitedBy?: string;
        search?: string;
        includeExpired?: boolean;
        startDate?: Date;
        endDate?: Date;
    }): Promise<PaginatedOutputInvitationSummary> {
        try {
            return await this.invitationsApi.listInvitations({
                orgId: organizationId,
                after: options?.after,
                before: options?.before,
                first: options?.first,
                last: options?.last,
                limit: options?.limit,
                offset: options?.offset,
                fields: options?.fields,
                orderBy: options?.orderBy,
                page: options?.page,
                status: options?.status as any,
                email: options?.email,
                roleId: options?.roleId,
                invitedBy: options?.invitedBy,
                search: options?.search,
                includeExpired: options?.includeExpired,
                startDate: options?.startDate,
                endDate: options?.endDate,
            });
        } catch (error) {
            throw await handleError(error)
        }
    }

    /**
     * Get invitation details
     */
    async getInvitation(organizationId: string, invitationId: string): Promise<Invitation> {
        try {
            return await this.invitationsApi.getInvitation({
                orgId: organizationId,
                invitationId,
            });
        } catch (error) {
            throw await handleError(error)
        }
    }

    /**
     * Cancel pending invitation
     */
    async cancelInvitation(organizationId: string, invitationId: string, request: CancelInvitationRequest): Promise<SimpleMessage> {
        try {
            return await this.invitationsApi.cancelInvitation({
                orgId: organizationId,
                invitationId,
                cancelInvitationRequest: request,
            });
        } catch (error) {
            throw await handleError(error)
        }
    }

    /**
     * Resend invitation email
     */
    async resendInvitation(organizationId: string, invitationId: string, request: ResendInvitationRequest): Promise<SimpleMessage> {
        try {
            return await this.invitationsApi.resendInvitation({
                orgId: organizationId,
                invitationId,
                resendInvitationRequest: request,
            });
        } catch (error) {
            throw await handleError(error)
        }
    }

    /**
     * Accept organization invitation (typically called by invitee)
     */
    async acceptInvitation(request: AcceptInvitationRequest): Promise<AcceptInvitationResponse> {
        try {
            return await this.invitationsApi.acceptInvitation({
                acceptInvitationRequest: request,
            });
        } catch (error) {
            throw await handleError(error)
        }
    }

    /**
     * Decline organization invitation (typically called by invitee)
     */
    async declineInvitation(request: DeclineInvitationRequest): Promise<SimpleMessage> {
        try {
            return await this.invitationsApi.declineInvitation({
                declineInvitationRequest: request,
            });
        } catch (error) {
            throw await handleError(error)
        }
    }

    /**
     * Validate invitation token without accepting
     */
    async validateInvitation(request: InvitationValidationRequest): Promise<InvitationValidationResponse> {
        try {
            return await this.invitationsApi.validateInvitation({
                invitationValidationRequest: request,
            });
        } catch (error) {
            throw await handleError(error)
        }
    }

    // ================================
    // Utility Methods
    // ================================

    /**
     * Check if user is organization owner
     */
    async isOrganizationOwner(organizationId: string, userId?: string): Promise<boolean> {
        try {
            const ownership = await this.getOrganizationOwnership(organizationId);
            return userId ? ownership.id === userId : true; // If no userId provided, assume current user
        } catch (error) {
            return false; // If we can't get ownership info, assume not owner
        }
    }

    /**
     * Get organization by slug
     */
    async getOrganizationBySlug(slug: string): Promise<Organization | null> {
        try {
            const response = await this.listOrganizations({
                search: slug,
                limit: 1
            });

            const organizations = response.data || [];
            const org = organizations.find(o => o.slug === slug);

            return org ? await this.getOrganization(org.id) : null;
        } catch (error) {
            throw await handleError(error)
        }
    }

    /**
     * Check if organization has feature enabled
     */
    async hasFeatureEnabled(organizationId: string, featureName: string): Promise<boolean> {
        try {
            const features = await this.listOrganizationFeatures(organizationId);
            const feature = features.find(f => f.name === featureName);
            return feature?.enabled ?? false;
        } catch (error) {
            return false;
        }
    }

    /**
     * Get organization summary for listings
     */
    async getOrganizationSummary(id: string): Promise<OrganizationSummary> {
        try {
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
            };
        } catch (error) {
            throw await handleError(error)
        }
    }

    // ================================
    // Advanced Utility Methods
    // ================================

    /**
     * Get active members count
     */
    async getActiveMembersCount(organizationId: string): Promise<number> {
        try {
            const stats = await this.getMembershipStats(organizationId);
            return stats.activeMembers;
        } catch (error) {
            return 0;
        }
    }

    /**
     * Get pending invitations count
     */
    async getPendingInvitationsCount(organizationId: string): Promise<number> {
        try {
            const invitations = await this.listInvitations(organizationId, {
                status: 'pending',
                limit: 1,
            });
            return invitations.pagination.totalCount || 0;
        } catch (error) {
            return 0;
        }
    }

    /**
     * Check if user is member of organization
     */
    async isMember(organizationId: string, userId: string): Promise<boolean> {
        try {
            await this.getMember(organizationId, userId);
            return true;
        } catch (error) {
            return false;
        }
    }

    /**
     * Check if user has specific role in organization
     */
    async hasRole(organizationId: string, userId: string, roleName: string): Promise<boolean> {
        try {
            const member = await this.getMember(organizationId, userId);
            return member.role?.name === roleName;
        } catch (error) {
            return false;
        }
    }

    /**
     * Get members by role
     */
    async getMembersByRole(organizationId: string, roleName: string): Promise<MemberSummary[]> {
        try {
            const members = await this.listMembers(organizationId, { limit: 1000 });
            return (members.data || []).filter(member => member.roleName === roleName);
        } catch (error) {
            return [];
        }
    }

    /**
     * Get organization owners
     */
    async getOwners(organizationId: string): Promise<MemberSummary[]> {
        try {
            const members = await this.listMembers(organizationId, { limit: 1000 });
            return (members.data || []).filter(member => member.isOwner);
        } catch (error) {
            return [];
        }
    }

    /**
     * Get billing contacts
     */
    async getBillingContacts(organizationId: string): Promise<MemberSummary[]> {
        try {
            const members = await this.listMembers(organizationId, { limit: 1000 });
            return (members.data || []).filter(member => member.isBilling);
        } catch (error) {
            return [];
        }
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
        try {
            return await this.createInvitation(organizationId, {
                email,
                roleId,
                message: options?.message,
                redirectUrl: options?.redirectUrl,
                customFields: options?.customFields,
                sendEmail: true,
            });
        } catch (error) {
            throw await handleError(error)
        }
    }

    /**
     * Invite multiple users at once
     */
    async inviteMultipleUsers(
        organizationId: string,
        invitations: Array<{ email: string; roleId: string; message?: string }>
    ): Promise<BulkInvitationResponse> {
        try {
            return await this.bulkCreateInvitations(organizationId, {
                invitations: invitations.map(inv => ({
                    email: inv.email,
                    roleId: inv.roleId,
                    message: inv.message,

                })),
                sendEmails: true,
            });
        } catch (error) {
            throw await handleError(error)
        }
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
        try {
            const [stats, invitations] = await Promise.all([
                this.getMembershipStats(organizationId),
                this.listInvitations(organizationId, { status: 'pending', limit: 1 }),
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
        } catch (error) {
            throw await handleError(error)
        }
    }

    // ================================
    // Error Handling
    // ================================

    private handleError(error: any): FrankAuthError {
        if (error instanceof FrankAuthError) {
            return error;
        }

        // Handle HTTP errors
        if (error?.response) {
            const status = error.response.status;
            const message = error.response.data?.message || error.message || 'Organization operation failed';

            return new FrankAuthError(message, status, {
                originalError: error,
                response: error.response.data,
            });
        }

        // Handle network errors
        if (error?.request) {
            return new FrankAuthError('Network error during organization operation', "INTERNAL_ERROR", {
                originalError: error,
                statusCode: 0
            });
        }

        // Handle other errors
        return new FrankAuthError(
            error?.message || 'Unknown error during organization operation',
            "INTERNAL_ERROR",
            { originalError: error, statusCode: 500 }
        );
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