package commands

import (
	"encoding/json"
	"fmt"

	"github.com/juicycleff/frank/ent"
	"github.com/juicycleff/frank/ent/role"
	user2 "github.com/juicycleff/frank/ent/user"
	"github.com/juicycleff/frank/ent/userrole"
	"github.com/juicycleff/frank/internal/services/rbac"
	"github.com/rs/xid"
	"github.com/spf13/cobra"
	"go.uber.org/zap"
)

// RBACCommands handles RBAC-related CLI commands
type RBACCommands struct {
	base *BaseCommand
}

// NewRBACCommands creates a new RBACCommands instance
func NewRBACCommands(base *BaseCommand) *RBACCommands {
	return &RBACCommands{
		base: base,
	}
}

// AddCommands adds RBAC commands to the root command
func (rc *RBACCommands) AddCommands(rootCmd *cobra.Command, base *BaseCommand) {
	rbacCmd := &cobra.Command{
		Use:   "rbac",
		Short: "Role-based access control commands",
		Long:  "Commands for managing roles, permissions, and user assignments",
	}

	// List roles
	listRolesCmd := &cobra.Command{
		Use:   "list-roles",
		Short: "List all roles",
		RunE:  rc.listRoles,
	}

	// Create role
	createRoleCmd := &cobra.Command{
		Use:   "create-role",
		Short: "Create a new role",
		RunE:  rc.createRole,
	}
	createRoleCmd.Flags().String("name", "", "role name (required)")
	createRoleCmd.Flags().String("display-name", "", "role display name")
	createRoleCmd.Flags().String("description", "", "role description")
	createRoleCmd.Flags().String("type", "application", "role type (system, organization, application)")
	createRoleCmd.MarkFlagRequired("name")

	// Assign role
	assignRoleCmd := &cobra.Command{
		Use:   "assign-role [user-email] [role-name]",
		Short: "Assign role to user",
		Args:  cobra.ExactArgs(2),
		RunE:  rc.assignRole,
	}
	assignRoleCmd.Flags().String("context", "system", "role context (system, organization)")
	assignRoleCmd.Flags().String("context-id", "", "context ID (required for organization context)")

	// Remove role
	removeRoleCmd := &cobra.Command{
		Use:   "remove-role [user-email] [role-name]",
		Short: "Remove role from user",
		Args:  cobra.ExactArgs(2),
		RunE:  rc.removeRole,
	}

	// List user roles
	listUserRolesCmd := &cobra.Command{
		Use:   "user-roles [user-email]",
		Short: "List roles assigned to user",
		Args:  cobra.ExactArgs(1),
		RunE:  rc.listUserRoles,
	}

	rbacCmd.AddCommand(listRolesCmd, createRoleCmd, assignRoleCmd, removeRoleCmd, listUserRolesCmd)
	rootCmd.AddCommand(rbacCmd)
}

func (rc *RBACCommands) listRoles(cmd *cobra.Command, args []string) error {
	rc.base.LogDebug("Listing all roles")

	db := rc.base.Container.DB()
	roles, err := db.Role.Query().Order(ent.Asc("name")).All(rc.base.Ctx)
	if err != nil {
		rc.base.LogError("Failed to query roles", err)
		return fmt.Errorf("failed to query roles: %w", err)
	}

	outputJSON, err := json.MarshalIndent(roles, "", "  ")
	if err != nil {
		rc.base.LogError("Failed to marshal roles", err, zap.Int("roleCount", len(roles)))
		return fmt.Errorf("failed to marshal roles: %w", err)
	}

	fmt.Println(string(outputJSON))
	rc.base.LogInfo("Listed roles successfully", zap.Int("count", len(roles)))
	return nil
}

func (rc *RBACCommands) createRole(cmd *cobra.Command, args []string) error {
	name, _ := cmd.Flags().GetString("name")
	displayName, _ := cmd.Flags().GetString("display-name")
	description, _ := cmd.Flags().GetString("description")
	roleType, _ := cmd.Flags().GetString("type")

	if displayName == "" {
		displayName = name
	}

	rc.base.LogDebug("Creating role",
		zap.String("name", name),
		zap.String("displayName", displayName),
		zap.String("description", description),
		zap.String("roleType", roleType),
	)

	rbacService := rc.base.Container.RBACService()
	role, err := rbacService.CreateRole(rc.base.Ctx, rbac.CreateRoleInput{
		Name:        name,
		DisplayName: displayName,
		Description: description,
		RoleType:    role.RoleType(roleType),
	})
	if err != nil {
		rc.base.LogError("Failed to create role", err,
			zap.String("name", name),
			zap.String("roleType", roleType),
		)
		return fmt.Errorf("failed to create role: %w", err)
	}

	rc.base.LogInfo("Role created successfully",
		zap.String("id", role.ID.String()),
		zap.String("name", name),
		zap.String("roleType", roleType),
	)
	fmt.Printf("Role created successfully: %s\n", role.ID)
	return nil
}

func (rc *RBACCommands) assignRole(cmd *cobra.Command, args []string) error {
	userEmail := args[0]
	roleName := args[1]
	contextType, _ := cmd.Flags().GetString("context")
	contextID, _ := cmd.Flags().GetString("context-id")

	rc.base.LogDebug("Assigning role to user",
		zap.String("userEmail", userEmail),
		zap.String("roleName", roleName),
		zap.String("contextType", contextType),
		zap.String("contextID", contextID),
	)

	// Get user
	userService := rc.base.Container.UserService()
	user, err := userService.GetUserByIdentifier(rc.base.Ctx, userEmail, user2.UserTypeEndUser)
	if err != nil {
		rc.base.LogError("User not found", err, zap.String("userEmail", userEmail))
		return fmt.Errorf("user not found: %s", userEmail)
	}

	cid, err := xid.FromString(contextID)
	if err != nil {
		return fmt.Errorf("invalid context identifier: %w", err)
	}

	roleId, err := xid.FromString(roleName)
	if err != nil {
		return fmt.Errorf("invalid role identifier: %w", err)
	}

	rbacService := rc.base.Container.RBACService()
	_, err = rbacService.AssignRoleToUser(rc.base.Ctx, rbac.AssignRoleToUserInput{
		UserID:      user.ID,
		RoleID:      roleId,
		ContextType: userrole.ContextType(contextType),
		ContextID:   &cid,
	})
	if err != nil {
		rc.base.LogError("Failed to assign role", err,
			zap.String("userEmail", userEmail),
			zap.String("roleName", roleName),
			zap.String("contextType", contextType),
		)
		return fmt.Errorf("failed to assign role: %w", err)
	}

	rc.base.LogInfo("Role assigned successfully",
		zap.String("user", userEmail),
		zap.String("role", roleName),
		zap.String("context", contextType),
	)
	fmt.Printf("Role %s assigned to user %s\n", roleName, userEmail)
	return nil
}

func (rc *RBACCommands) removeRole(cmd *cobra.Command, args []string) error {
	userEmail := args[0]
	roleName := args[1]

	rc.base.LogDebug("Removing role from user",
		zap.String("userEmail", userEmail),
		zap.String("roleName", roleName),
	)

	// Get user
	userService := rc.base.Container.UserService()
	user, err := userService.GetUserByIdentifier(rc.base.Ctx, userEmail, user2.UserTypeEndUser)
	if err != nil {
		rc.base.LogError("User not found", err, zap.String("userEmail", userEmail))
		return fmt.Errorf("user not found: %s", userEmail)
	}

	rid, err := xid.FromString(roleName)
	if err != nil {
		return fmt.Errorf("invalid role identifier: %w", err)
	}

	rbacService := rc.base.Container.RBACService()
	err = rbacService.RemoveRoleFromUser(rc.base.Ctx, user.ID, rid, userrole.ContextTypeApplication, nil)
	if err != nil {
		rc.base.LogError("Failed to remove role", err,
			zap.String("userEmail", userEmail),
			zap.String("roleName", roleName),
		)
		return fmt.Errorf("failed to remove role: %w", err)
	}

	rc.base.LogInfo("Role removed successfully",
		zap.String("user", userEmail),
		zap.String("role", roleName),
	)
	fmt.Printf("Role %s removed from user %s\n", roleName, userEmail)
	return nil
}

func (rc *RBACCommands) listUserRoles(cmd *cobra.Command, args []string) error {
	userEmail := args[0]

	rc.base.LogDebug("Listing user roles", zap.String("userEmail", userEmail))

	// Get user
	userService := rc.base.Container.UserService()
	user, err := userService.GetUserByIdentifier(rc.base.Ctx, userEmail, user2.UserTypeEndUser)
	if err != nil {
		rc.base.LogError("User not found", err, zap.String("userEmail", userEmail))
		return fmt.Errorf("user not found: %s", userEmail)
	}

	rbacService := rc.base.Container.RBACService()
	roles, err := rbacService.ListUserRoles(rc.base.Ctx, user.ID, userrole.ContextTypeApplication, nil)
	if err != nil {
		rc.base.LogError("Failed to get user roles", err,
			zap.String("userEmail", userEmail),
			zap.String("userID", user.ID.String()),
		)
		return fmt.Errorf("failed to get user roles: %w", err)
	}

	outputJSON, err := json.MarshalIndent(roles, "", "  ")
	if err != nil {
		rc.base.LogError("Failed to marshal roles", err,
			zap.String("userEmail", userEmail),
			zap.Int("roleCount", len(roles)),
		)
		return fmt.Errorf("failed to marshal roles: %w", err)
	}

	fmt.Println(string(outputJSON))
	rc.base.LogInfo("Listed user roles successfully",
		zap.String("user", userEmail),
		zap.Int("count", len(roles)),
	)
	return nil
}
