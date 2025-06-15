package commands

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/juicycleff/frank/ent"
	"github.com/juicycleff/frank/ent/organization"
	"github.com/juicycleff/frank/pkg/model"
	organization2 "github.com/juicycleff/frank/pkg/services/organization"
	"github.com/rs/xid"
	"github.com/spf13/cobra"
	"go.uber.org/zap"
)

// OrganizationCommands handles organization-related CLI commands
type OrganizationCommands struct {
	base *BaseCommand
}

// NewOrganizationCommands creates a new OrganizationCommands instance
func NewOrganizationCommands(base *BaseCommand) *OrganizationCommands {
	return &OrganizationCommands{
		base: base,
	}
}

// Organization represents an organization in the system
type Organization struct {
	ID        xid.ID    `json:"id"`
	Name      string    `json:"name"`
	Slug      string    `json:"slug"`
	Domain    string    `json:"domain,omitempty"`
	OrgType   string    `json:"orgType"`
	Active    bool      `json:"active"`
	Plan      string    `json:"plan,omitempty"`
	CreatedAt time.Time `json:"createdAt"`
	UpdatedAt time.Time `json:"updatedAt"`
}

// AddCommands adds organization commands to the root command
func (oc *OrganizationCommands) AddCommands(rootCmd *cobra.Command, base *BaseCommand) {
	orgCmd := &cobra.Command{
		Use:   "org",
		Short: "Organization management commands",
		Long:  "Commands for managing organizations in the Frank Auth platform",
	}

	// List organizations
	listOrgsCmd := &cobra.Command{
		Use:   "list",
		Short: "List all organizations",
		RunE:  oc.listOrganizations,
	}
	listOrgsCmd.Flags().String("type", "", "filter by organization type (platform, customer)")
	listOrgsCmd.Flags().Bool("active", true, "filter by active status")
	listOrgsCmd.Flags().Int("limit", 50, "limit number of results")

	// Create organization
	createOrgCmd := &cobra.Command{
		Use:   "create",
		Short: "Create a new organization",
		RunE:  oc.createOrganization,
	}
	createOrgCmd.Flags().String("name", "", "organization name (required)")
	createOrgCmd.Flags().String("slug", "", "organization slug (auto-generated if not provided)")
	createOrgCmd.Flags().String("domain", "", "organization domain")
	createOrgCmd.Flags().String("type", "customer", "organization type (platform, customer)")
	createOrgCmd.Flags().String("plan", "free", "subscription plan")
	createOrgCmd.Flags().String("owner-email", "", "owner email (required)")
	createOrgCmd.MarkFlagRequired("name")
	createOrgCmd.MarkFlagRequired("owner-email")

	// Get organization
	getOrgCmd := &cobra.Command{
		Use:   "get [org-id|slug]",
		Short: "Get organization by ID or slug",
		Args:  cobra.ExactArgs(1),
		RunE:  oc.getOrganization,
	}

	// Update organization
	updateOrgCmd := &cobra.Command{
		Use:   "update [org-id|slug]",
		Short: "Update organization information",
		Args:  cobra.ExactArgs(1),
		RunE:  oc.updateOrganization,
	}
	updateOrgCmd.Flags().String("name", "", "new name")
	updateOrgCmd.Flags().String("domain", "", "new domain")
	updateOrgCmd.Flags().String("plan", "", "new plan")
	updateOrgCmd.Flags().Bool("active", true, "active status")

	// Delete organization
	deleteOrgCmd := &cobra.Command{
		Use:   "delete [org-id|slug]",
		Short: "Delete organization",
		Args:  cobra.ExactArgs(1),
		RunE:  oc.deleteOrganization,
	}
	deleteOrgCmd.Flags().Bool("hard", false, "hard delete (permanent)")

	// List members
	listMembersCmd := &cobra.Command{
		Use:   "members [org-id|slug]",
		Short: "List organization members",
		Args:  cobra.ExactArgs(1),
		RunE:  oc.listMembers,
	}

	// Add member
	addMemberCmd := &cobra.Command{
		Use:   "add-member [org-id|slug] [user-email]",
		Short: "Add member to organization",
		Args:  cobra.ExactArgs(2),
		RunE:  oc.addMember,
	}
	addMemberCmd.Flags().String("role", "member", "member role")

	// Remove member
	removeMemberCmd := &cobra.Command{
		Use:   "remove-member [org-id|slug] [user-email]",
		Short: "Remove member from organization",
		Args:  cobra.ExactArgs(2),
		RunE:  oc.removeMember,
	}

	orgCmd.AddCommand(listOrgsCmd, createOrgCmd, getOrgCmd, updateOrgCmd, deleteOrgCmd, listMembersCmd, addMemberCmd, removeMemberCmd)
	rootCmd.AddCommand(orgCmd)
}

func (oc *OrganizationCommands) listOrganizations(cmd *cobra.Command, args []string) error {
	orgType, _ := cmd.Flags().GetString("type")
	active, _ := cmd.Flags().GetBool("active")
	limit, _ := cmd.Flags().GetInt("limit")

	oc.base.LogDebug("Starting organization list operation",
		zap.String("orgType", orgType),
		zap.Bool("active", active),
		zap.Int("limit", limit),
	)

	query := oc.base.Container.DB().Organization.Query()

	if orgType != "" {
		query = query.Where(organization.OrgTypeEQ(model.OrgType(orgType)))
	}

	if active {
		query = query.Where(organization.ActiveEQ(true))
	}

	orgs, err := query.Limit(limit).Order(ent.Desc(organization.FieldCreatedAt)).All(oc.base.Ctx)
	if err != nil {
		oc.base.LogError("Failed to query organizations", err,
			zap.String("orgType", orgType),
			zap.Bool("active", active),
			zap.Int("limit", limit),
		)
		return fmt.Errorf("failed to query organizations: %w", err)
	}

	// Convert to output format
	var output []Organization
	for _, org := range orgs {
		output = append(output, Organization{
			ID:        org.ID,
			Name:      org.Name,
			Slug:      org.Slug,
			Domain:    org.Domain,
			OrgType:   string(org.OrgType),
			Active:    org.Active,
			Plan:      org.Plan,
			CreatedAt: org.CreatedAt,
			UpdatedAt: org.UpdatedAt,
		})
	}

	outputJSON, err := json.MarshalIndent(output, "", "  ")
	if err != nil {
		oc.base.LogError("Failed to marshal organizations", err, zap.Int("orgCount", len(orgs)))
		return fmt.Errorf("failed to marshal organizations: %w", err)
	}

	fmt.Println(string(outputJSON))
	oc.base.LogInfo("Listed organizations successfully", zap.Int("count", len(orgs)))
	return nil
}

func (oc *OrganizationCommands) createOrganization(cmd *cobra.Command, args []string) error {
	name, _ := cmd.Flags().GetString("name")
	slug, _ := cmd.Flags().GetString("slug")
	domain, _ := cmd.Flags().GetString("domain")
	orgType, _ := cmd.Flags().GetString("type")
	plan, _ := cmd.Flags().GetString("plan")
	ownerEmail, _ := cmd.Flags().GetString("owner-email")

	if name == "" {
		return fmt.Errorf("organization name is required")
	}

	if ownerEmail == "" {
		return fmt.Errorf("owner email is required")
	}

	// Generate slug if not provided
	if slug == "" {
		slug = strings.ToLower(strings.ReplaceAll(name, " ", "-"))
	}

	oc.base.LogDebug("Starting organization creation",
		zap.String("name", name),
		zap.String("slug", slug),
		zap.String("orgType", orgType),
		zap.String("plan", plan),
		zap.String("ownerEmail", ownerEmail),
	)

	orgService := oc.base.Container.OrganizationService()

	createReq := &model.CreateOrganizationRequest{
		Name:       name,
		Slug:       slug,
		Domain:     &domain,
		OrgType:    model.OrgType(orgType),
		Plan:       plan,
		OwnerEmail: ownerEmail,
	}

	newOrg, err := orgService.CreateOrganization(oc.base.Ctx, *createReq)
	if err != nil {
		oc.base.LogError("Failed to create organization", err,
			zap.String("name", name),
			zap.String("slug", slug),
			zap.String("ownerEmail", ownerEmail),
		)
		return fmt.Errorf("failed to create organization: %w", err)
	}

	oc.base.LogInfo("Organization created successfully",
		zap.String("id", newOrg.ID.String()),
		zap.String("name", name),
		zap.String("slug", slug),
		zap.String("owner", ownerEmail),
	)

	fmt.Printf("Organization created successfully: %s\n", newOrg.ID)
	return nil
}

func (oc *OrganizationCommands) getOrganization(cmd *cobra.Command, args []string) error {
	identifier := args[0]

	oc.base.LogDebug("Getting organization", zap.String("identifier", identifier))
	orgId, err := xid.FromString(identifier)
	if err != nil {
		return fmt.Errorf("invalid org identifier: %w", err)
	}

	orgService := oc.base.Container.OrganizationService()
	org, err := orgService.GetOrganization(oc.base.Ctx, orgId)
	if err != nil {
		oc.base.LogError("Failed to get organization", err, zap.String("identifier", identifier))
		return fmt.Errorf("failed to get organization: %w", err)
	}

	output := Organization{
		ID:        org.ID,
		Name:      org.Name,
		Slug:      org.Slug,
		Domain:    org.Domain,
		OrgType:   string(org.OrgType),
		Active:    org.Active,
		Plan:      org.Plan,
		CreatedAt: org.CreatedAt,
		UpdatedAt: org.UpdatedAt,
	}

	outputJSON, err := json.MarshalIndent(output, "", "  ")
	if err != nil {
		oc.base.LogError("Failed to marshal organization", err, zap.String("orgID", org.ID.String()))
		return fmt.Errorf("failed to marshal organization: %w", err)
	}

	fmt.Println(string(outputJSON))
	oc.base.LogDebug("Organization retrieved successfully", zap.String("identifier", identifier))
	return nil
}

func (oc *OrganizationCommands) updateOrganization(cmd *cobra.Command, args []string) error {
	identifier := args[0]

	updateReq := &model.UpdateOrganizationRequest{}
	hasChanges := false

	if name, _ := cmd.Flags().GetString("name"); name != "" {
		updateReq.Name = &name
		hasChanges = true
	}

	if domain, _ := cmd.Flags().GetString("domain"); domain != "" {
		updateReq.Domain = &domain
		hasChanges = true
	}

	if plan, _ := cmd.Flags().GetString("plan"); plan != "" {
		updateReq.Plan = &plan
		hasChanges = true
	}

	if cmd.Flags().Changed("active") {
		active, _ := cmd.Flags().GetBool("active")
		updateReq.Active = &active
		hasChanges = true
	}

	if !hasChanges {
		return fmt.Errorf("no fields to update")
	}

	oc.base.LogDebug("Updating organization",
		zap.String("identifier", identifier),
		zap.Bool("hasChanges", hasChanges),
	)

	orgId, err := xid.FromString(identifier)
	if err != nil {
		return fmt.Errorf("invalid org identifier: %w", err)
	}

	orgService := oc.base.Container.OrganizationService()
	_, err = orgService.UpdateOrganization(oc.base.Ctx, orgId, *updateReq)
	if err != nil {
		oc.base.LogError("Failed to update organization", err, zap.String("identifier", identifier))
		return fmt.Errorf("failed to update organization: %w", err)
	}

	oc.base.LogInfo("Organization updated successfully", zap.String("identifier", identifier))
	fmt.Printf("Organization updated successfully: %s\n", identifier)
	return nil
}

func (oc *OrganizationCommands) deleteOrganization(cmd *cobra.Command, args []string) error {
	identifier := args[0]
	hard, _ := cmd.Flags().GetBool("hard")

	oc.base.LogDebug("Deleting organization",
		zap.String("identifier", identifier),
		zap.Bool("hard", hard),
	)

	orgService := oc.base.Container.OrganizationService()

	orgId, err := xid.FromString(identifier)
	if err != nil {
		return fmt.Errorf("invalid org identifier: %w", err)
	}

	if hard {
		err := orgService.DeleteOrganization(oc.base.Ctx, orgId, model.DeleteOrganizationRequest{})
		if err != nil {
			oc.base.LogError("Failed to delete organization", err,
				zap.String("identifier", identifier),
				zap.Bool("hard", hard),
			)
			return fmt.Errorf("failed to delete organization: %w", err)
		}
	} else {
		// Soft delete by deactivating
		_, err := orgService.UpdateOrganization(oc.base.Ctx, orgId, model.UpdateOrganizationRequest{
			Active: boolPtr(false),
		})
		if err != nil {
			oc.base.LogError("Failed to soft delete organization", err, zap.String("identifier", identifier))
			return fmt.Errorf("failed to soft delete organization: %w", err)
		}
	}

	deleteType := "soft"
	if hard {
		deleteType = "hard"
	}

	oc.base.LogInfo("Organization deleted successfully",
		zap.String("identifier", identifier),
		zap.String("type", deleteType),
	)
	fmt.Printf("Organization deleted successfully (%s delete): %s\n", deleteType, identifier)
	return nil
}

func (oc *OrganizationCommands) listMembers(cmd *cobra.Command, args []string) error {
	orgIdentifier := args[0]

	oc.base.LogDebug("Listing organization members", zap.String("orgIdentifier", orgIdentifier))

	orgService := oc.base.Container.MembershipService()
	orgId, err := xid.FromString(orgIdentifier)
	if err != nil {
		return fmt.Errorf("invalid org identifier: %w", err)
	}

	members, err := orgService.ListOrganizationMembers(oc.base.Ctx, orgId, model.ListMembershipsParams{})
	if err != nil {
		oc.base.LogError("Failed to list members", err, zap.String("orgIdentifier", orgIdentifier))
		return fmt.Errorf("failed to list members: %w", err)
	}

	outputJSON, err := json.MarshalIndent(members.Data, "", "  ")
	if err != nil {
		oc.base.LogError("Failed to marshal members", err,
			zap.String("orgIdentifier", orgIdentifier),
			zap.Int("memberCount", members.Pagination.TotalCount),
		)
		return fmt.Errorf("failed to marshal members: %w", err)
	}

	fmt.Println(string(outputJSON))
	oc.base.LogInfo("Listed organization members successfully",
		zap.String("org", orgIdentifier),
		zap.Int("count", members.Pagination.TotalCount),
	)
	return nil
}

func (oc *OrganizationCommands) addMember(cmd *cobra.Command, args []string) error {
	orgIdentifier := args[0]
	userId := args[1]
	role, _ := cmd.Flags().GetString("role")

	oc.base.LogDebug("Adding member to organization",
		zap.String("orgIdentifier", orgIdentifier),
		zap.String("userEmail", userId),
		zap.String("role", role),
	)

	orgId, err := xid.FromString(orgIdentifier)
	if err != nil {
		return fmt.Errorf("invalid org identifier: %w", err)
	}

	uid, err := xid.FromString(userId)
	if err != nil {
		return fmt.Errorf("invalid user identifier: %w", err)
	}

	rid, err := xid.FromString(role)
	if err != nil {
		return fmt.Errorf("invalid role identifier: %w", err)
	}

	orgService := oc.base.Container.MembershipService()
	_, err = orgService.AddMember(oc.base.Ctx, organization2.AddMemberInput{
		OrganizationID: orgId,
		UserID:         uid,
		RoleID:         rid,
	})
	if err != nil {
		oc.base.LogError("Failed to add member", err,
			zap.String("orgIdentifier", orgIdentifier),
			zap.String("userId", userId),
			zap.String("role", role),
		)
		return fmt.Errorf("failed to add member: %w", err)
	}

	oc.base.LogInfo("Member added successfully",
		zap.String("org", orgIdentifier),
		zap.String("user", userId),
		zap.String("role", role),
	)
	fmt.Printf("Member added successfully: %s to %s with role %s\n", userId, orgIdentifier, role)
	return nil
}

func (oc *OrganizationCommands) removeMember(cmd *cobra.Command, args []string) error {
	orgIdentifier := args[0]
	userId := args[1]

	oc.base.LogDebug("Removing member from organization",
		zap.String("orgIdentifier", orgIdentifier),
		zap.String("userId", userId),
	)

	orgService := oc.base.Container.MembershipService()

	orgId, err := xid.FromString(orgIdentifier)
	if err != nil {
		return fmt.Errorf("invalid org identifier: %w", err)
	}

	uid, err := xid.FromString(userId)
	if err != nil {
		return fmt.Errorf("invalid user identifier: %w", err)
	}

	err = orgService.RemoveMember(oc.base.Ctx, orgId, uid, "")
	if err != nil {
		oc.base.LogError("Failed to remove member", err,
			zap.String("orgIdentifier", orgIdentifier),
			zap.String("userId", userId),
		)
		return fmt.Errorf("failed to remove member: %w", err)
	}

	oc.base.LogInfo("Member removed successfully",
		zap.String("org", orgIdentifier),
		zap.String("user", userId),
	)
	fmt.Printf("Member removed successfully: %s from %s\n", userId, orgIdentifier)
	return nil
}
