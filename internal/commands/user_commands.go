package commands

import (
	"fmt"
	"strings"

	"github.com/rs/xid"
	"github.com/spf13/cobra"
	"github.com/xraph/frank/ent"
	"github.com/xraph/frank/ent/membership"
	"github.com/xraph/frank/ent/organization"
	"github.com/xraph/frank/ent/user"
	"github.com/xraph/frank/pkg/model"
	"go.uber.org/zap"
)

// UserCommands handles user-related CLI commands
type UserCommands struct {
	base *BaseCommand
}

// NewUserCommands creates a new UserCommands instance
func NewUserCommands(base *BaseCommand) *UserCommands {
	return &UserCommands{
		base: base,
	}
}

// User represents a user in the system
type User = model.User

// AddCommands adds user commands to the root command
func (uc *UserCommands) AddCommands(rootCmd *cobra.Command, base *BaseCommand) {
	userCmd := &cobra.Command{
		Use:   "user",
		Short: "User management commands",
		Long:  "Commands for managing users in the Frank Auth platform",
	}

	// List users
	listUsersCmd := &cobra.Command{
		Use:   "list",
		Short: "List all users",
		RunE:  uc.listUsers,
	}
	listUsersCmd.Flags().String("type", "", "filter by user type (internal, external)")
	listUsersCmd.Flags().String("org", "", "filter by organization ID")
	listUsersCmd.Flags().Bool("active", true, "filter by active status")
	listUsersCmd.Flags().Int("limit", 50, "limit number of results")
	listUsersCmd.Flags().Bool("json", false, "output as JSON instead of table")

	// Create user
	createUserCmd := &cobra.Command{
		Use:   "create",
		Short: "Create a new user",
		RunE:  uc.createUser,
	}
	createUserCmd.Flags().String("email", "", "user email (required)")
	createUserCmd.Flags().String("username", "", "username")
	createUserCmd.Flags().String("first-name", "", "first name")
	createUserCmd.Flags().String("last-name", "", "last name")
	createUserCmd.Flags().String("password", "", "password (if not provided, user will need to set via email)")
	createUserCmd.Flags().String("type", "external", "user type (internal, external)")
	createUserCmd.Flags().Bool("verified", false, "mark email as verified")
	createUserCmd.Flags().Bool("admin", false, "create as admin user")
	createUserCmd.Flags().Bool("json", false, "output as JSON instead of table")
	createUserCmd.MarkFlagRequired("email")

	// Get user
	getUserCmd := &cobra.Command{
		Use:   "get [user-id|email]",
		Short: "Get user by ID or email",
		Args:  cobra.ExactArgs(1),
		RunE:  uc.getUser,
	}
	getUserCmd.Flags().Bool("json", false, "output as JSON instead of details view")

	// Update user
	updateUserCmd := &cobra.Command{
		Use:   "update [user-id|email]",
		Short: "Update user information",
		Args:  cobra.ExactArgs(1),
		RunE:  uc.updateUser,
	}
	updateUserCmd.Flags().String("email", "", "new email")
	updateUserCmd.Flags().String("username", "", "new username")
	updateUserCmd.Flags().String("first-name", "", "new first name")
	updateUserCmd.Flags().String("last-name", "", "new last name")
	updateUserCmd.Flags().Bool("active", true, "active status")
	updateUserCmd.Flags().Bool("blocked", false, "blocked status")
	updateUserCmd.Flags().Bool("verified", true, "email verified status")

	// Delete user
	deleteUserCmd := &cobra.Command{
		Use:   "delete [user-id|email]",
		Short: "Delete user (soft delete)",
		Args:  cobra.ExactArgs(1),
		RunE:  uc.deleteUser,
	}
	deleteUserCmd.Flags().Bool("hard", false, "hard delete (permanent)")

	// Set password
	setPasswordCmd := &cobra.Command{
		Use:   "set-password [user-id|email]",
		Short: "Set user password",
		Args:  cobra.ExactArgs(1),
		RunE:  uc.setPassword,
	}
	setPasswordCmd.Flags().String("password", "", "new password (if not provided, will prompt)")
	setPasswordCmd.Flags().Bool("temporary", false, "mark as temporary password")

	// Block/Unblock user
	blockUserCmd := &cobra.Command{
		Use:   "block [user-id|email]",
		Short: "Block user account",
		Args:  cobra.ExactArgs(1),
		RunE:  uc.blockUser,
	}

	unblockUserCmd := &cobra.Command{
		Use:   "unblock [user-id|email]",
		Short: "Unblock user account",
		Args:  cobra.ExactArgs(1),
		RunE:  uc.unblockUser,
	}

	userCmd.AddCommand(listUsersCmd, createUserCmd, getUserCmd, updateUserCmd, deleteUserCmd, setPasswordCmd, blockUserCmd, unblockUserCmd)
	rootCmd.AddCommand(userCmd)
}

func (uc *UserCommands) listUsers(cmd *cobra.Command, args []string) error {
	userType, _ := cmd.Flags().GetString("type")
	orgID, _ := cmd.Flags().GetString("org")
	active, _ := cmd.Flags().GetBool("active")
	limit, _ := cmd.Flags().GetInt("limit")
	jsonOutput, _ := cmd.Flags().GetBool("json")

	// Set JSON mode if requested
	uc.base.UseJSON = jsonOutput

	uc.base.LogDebug("Starting user list operation",
		zap.String("userType", userType),
		zap.String("orgID", orgID),
		zap.Bool("active", active),
		zap.Int("limit", limit),
	)

	query := uc.base.Container.DB().User.Query()

	if userType != "" {
		query = query.Where(user.UserTypeEQ(model.UserType(userType)))
	}

	if active {
		query = query.Where(user.ActiveEQ(true))
	}

	if orgID != "" {
		oid, err := xid.FromString(orgID)
		if err != nil {
			query = query.Where(user.HasMembershipsWith(
				membership.HasOrganizationWith(organization.Slug(orgID)),
			))
		} else {
			query = query.Where(user.HasMembershipsWith(
				membership.OrganizationID(oid),
			))
		}
	}

	users, err := query.Limit(limit).Order(ent.Desc(user.FieldCreatedAt)).All(uc.base.Ctx)
	if err != nil {
		uc.base.LogError("Failed to query users", err,
			zap.String("userType", userType),
			zap.String("orgID", orgID),
			zap.Bool("active", active),
			zap.Int("limit", limit),
		)
		return fmt.Errorf("failed to query users: %w", err)
	}

	// Prepare table data
	headers := []string{"ID", "Email", "Username", "Name", "Type", "Status", "Verified", "Created"}
	var rows [][]string

	for _, u := range users {
		status := "Active"
		if u.Blocked {
			status = "Blocked"
		} else if !u.Active {
			status = "Inactive"
		}

		verified := "No"
		if u.EmailVerified {
			verified = "Yes"
		}

		name := strings.TrimSpace(fmt.Sprintf("%s %s", u.FirstName, u.LastName))
		if name == "" {
			name = "-"
		}

		rows = append(rows, []string{
			u.ID.String()[:8] + "...", // Truncate ID for display
			u.Email,
			u.Username,
			name,
			string(u.UserType),
			status,
			verified,
			u.CreatedAt.Format("2006-01-02"),
		})
	}

	uc.base.LogInfo("Listed users successfully", zap.Int("count", len(users)))

	title := fmt.Sprintf("Users (%d total)", len(users))
	if userType != "" {
		title += fmt.Sprintf(" - Type: %s", userType)
	}
	if orgID != "" {
		title += fmt.Sprintf(" - Org: %s", orgID)
	}

	return uc.base.ShowTable(title, headers, rows)
}

func (uc *UserCommands) createUser(cmd *cobra.Command, args []string) error {
	email, _ := cmd.Flags().GetString("email")
	username, _ := cmd.Flags().GetString("username")
	firstName, _ := cmd.Flags().GetString("first-name")
	lastName, _ := cmd.Flags().GetString("last-name")
	password, _ := cmd.Flags().GetString("password")
	userType, _ := cmd.Flags().GetString("type")
	verified, _ := cmd.Flags().GetBool("verified")
	isAdmin, _ := cmd.Flags().GetBool("admin")
	jsonOutput, _ := cmd.Flags().GetBool("json")

	// Set JSON mode if requested
	uc.base.UseJSON = jsonOutput

	if email == "" {
		return fmt.Errorf("email is required")
	}

	uc.base.LogDebug("Starting user creation",
		zap.String("email", email),
		zap.String("username", username),
		zap.String("userType", userType),
		zap.Bool("verified", verified),
		zap.Bool("isAdmin", isAdmin),
	)

	userService := uc.base.Container.UserService()

	createReq := &model.CreateUserRequest{
		Email:         email,
		Username:      &username,
		FirstName:     &firstName,
		LastName:      &lastName,
		UserType:      model.UserType(userType),
		EmailVerified: verified,
		Active:        true,
	}

	if password != "" {
		createReq.Password = password
	}

	newUser, err := userService.CreateUser(uc.base.Ctx, *createReq)
	if err != nil {
		uc.base.LogError("Failed to create user", err,
			zap.String("email", email),
			zap.String("userType", userType),
		)
		return fmt.Errorf("failed to create user: %w", err)
	}

	// Assign admin role if requested
	if isAdmin {
		rbacService := uc.base.Container.RoleService()
		err = rbacService.AssignSystemRole(uc.base.Ctx, newUser.ID, "platform_admin")
		if err != nil {
			uc.base.LogWarn("Failed to assign admin role", zap.Error(err), zap.String("userID", newUser.ID.String()))
		}
	}

	uc.base.LogInfo("User created successfully",
		zap.String("id", newUser.ID.String()),
		zap.String("email", email),
		zap.String("type", userType),
		zap.Bool("admin", isAdmin),
	)

	message := fmt.Sprintf("User created successfully!\n\nID: %s\nEmail: %s\nType: %s\nAdmin: %t",
		newUser.ID.String(), email, userType, isAdmin)

	return uc.base.ShowMessage("User Created", message, false)
}

func (uc *UserCommands) getUser(cmd *cobra.Command, args []string) error {
	identifier := args[0]
	jsonOutput, _ := cmd.Flags().GetBool("json")

	// Set JSON mode if requested
	uc.base.UseJSON = jsonOutput

	uc.base.LogDebug("Getting user", zap.String("identifier", identifier))

	userId, err := xid.FromString(identifier)
	if err != nil {
		return fmt.Errorf("invalid user identifier: %w", err)
	}

	userService := uc.base.Container.UserService()
	user, err := userService.GetUser(uc.base.Ctx, userId)
	if err != nil {
		uc.base.LogError("Failed to get user", err, zap.String("identifier", identifier))
		return fmt.Errorf("failed to get user: %w", err)
	}

	// Prepare detailed view data
	data := map[string]interface{}{
		"id":             user.ID.String(),
		"email":          user.Email,
		"username":       user.Username,
		"first_name":     user.FirstName,
		"last_name":      user.LastName,
		"user_type":      user.UserType,
		"email_verified": user.EmailVerified,
		"active":         user.Active,
		"blocked":        user.Blocked,
		"created_at":     user.CreatedAt,
		"updated_at":     user.UpdatedAt,
	}

	if user.LastLogin != nil {
		data["last_login"] = *user.LastLogin
	} else {
		data["last_login"] = "Never"
	}

	uc.base.LogDebug("User retrieved successfully", zap.String("identifier", identifier))

	return uc.base.ShowDetails(fmt.Sprintf("User Details - %s", user.Email), data)
}

func (uc *UserCommands) updateUser(cmd *cobra.Command, args []string) error {
	identifier := args[0]

	updateReq := &model.UpdateUserRequest{}
	hasChanges := false

	if email, _ := cmd.Flags().GetString("email"); email != "" {
		updateReq.Email = &email
		hasChanges = true
	}

	if username, _ := cmd.Flags().GetString("username"); username != "" {
		updateReq.Username = &username
		hasChanges = true
	}

	if firstName, _ := cmd.Flags().GetString("first-name"); firstName != "" {
		updateReq.FirstName = &firstName
		hasChanges = true
	}

	if lastName, _ := cmd.Flags().GetString("last-name"); lastName != "" {
		updateReq.LastName = &lastName
		hasChanges = true
	}

	if cmd.Flags().Changed("active") {
		active, _ := cmd.Flags().GetBool("active")
		updateReq.Active = &active
		hasChanges = true
	}

	if cmd.Flags().Changed("blocked") {
		blocked, _ := cmd.Flags().GetBool("blocked")
		updateReq.Blocked = &blocked
		hasChanges = true
	}

	if cmd.Flags().Changed("verified") {
		// verified, _ := cmd.Flags().GetBool("verified")
		// updateReq.EmailVerified = &verified
		hasChanges = true
	}

	if !hasChanges {
		return fmt.Errorf("no fields to update")
	}

	userId, err := xid.FromString(identifier)
	if err != nil {
		return fmt.Errorf("invalid user identifier: %w", err)
	}

	uc.base.LogDebug("Updating user", zap.String("identifier", identifier), zap.Bool("hasChanges", hasChanges))

	userService := uc.base.Container.UserService()
	_, err = userService.UpdateUser(uc.base.Ctx, userId, *updateReq)
	if err != nil {
		uc.base.LogError("Failed to update user", err, zap.String("identifier", identifier))
		return fmt.Errorf("failed to update user: %w", err)
	}

	uc.base.LogInfo("User updated successfully", zap.String("identifier", identifier))

	message := fmt.Sprintf("User updated successfully: %s", identifier)
	return uc.base.ShowMessage("Success", message, false)
}

func (uc *UserCommands) deleteUser(cmd *cobra.Command, args []string) error {
	identifier := args[0]
	hard, _ := cmd.Flags().GetBool("hard")

	userId, err := xid.FromString(identifier)
	if err != nil {
		return fmt.Errorf("invalid user identifier: %w", err)
	}

	uc.base.LogDebug("Deleting user", zap.String("identifier", identifier), zap.Bool("hard", hard))

	userService := uc.base.Container.UserService()

	if hard {
		err := userService.DeleteUser(uc.base.Ctx, userId, model.DeleteUserRequest{})
		if err != nil {
			uc.base.LogError("Failed to delete user", err, zap.String("identifier", identifier), zap.Bool("hard", hard))
			return fmt.Errorf("failed to delete user: %w", err)
		}
	} else {
		// Soft delete by blocking and deactivating
		_, err := userService.UpdateUser(uc.base.Ctx, userId, model.UpdateUserRequest{
			Active:  boolPtr(false),
			Blocked: boolPtr(true),
		})
		if err != nil {
			uc.base.LogError("Failed to soft delete user", err, zap.String("identifier", identifier))
			return fmt.Errorf("failed to soft delete user: %w", err)
		}
	}

	deleteType := "soft"
	if hard {
		deleteType = "hard"
	}

	uc.base.LogInfo("User deleted successfully",
		zap.String("identifier", identifier),
		zap.String("type", deleteType),
	)

	message := fmt.Sprintf("User deleted successfully (%s delete): %s", deleteType, identifier)
	return uc.base.ShowMessage("Success", message, false)
}

func (uc *UserCommands) setPassword(cmd *cobra.Command, args []string) error {
	identifier := args[0]
	password, _ := cmd.Flags().GetString("password")
	temporary, _ := cmd.Flags().GetBool("temporary")

	if password == "" {
		fmt.Print("Enter new password: ")
		fmt.Scanln(&password)
	}

	if password == "" {
		return fmt.Errorf("password cannot be empty")
	}

	uc.base.LogDebug("Setting user password",
		zap.String("identifier", identifier),
		zap.Bool("temporary", temporary),
	)

	userId, err := xid.FromString(identifier)
	if err != nil {
		return fmt.Errorf("invalid user identifier: %w", err)
	}

	passwordService := uc.base.Container.PasswordService()
	err = passwordService.SetPassword(uc.base.Ctx, userId, model.SetPasswordRequest{
		Password:  password,
		Temporary: temporary,
	})
	if err != nil {
		uc.base.LogError("Failed to set password", err,
			zap.String("identifier", identifier),
			zap.Bool("temporary", temporary),
		)
		return fmt.Errorf("failed to set password: %w", err)
	}

	uc.base.LogInfo("Password set successfully",
		zap.String("identifier", identifier),
		zap.Bool("temporary", temporary),
	)

	message := fmt.Sprintf("Password set successfully for user: %s", identifier)
	return uc.base.ShowMessage("Success", message, false)
}

func (uc *UserCommands) blockUser(cmd *cobra.Command, args []string) error {
	identifier := args[0]

	userId, err := xid.FromString(identifier)
	if err != nil {
		return fmt.Errorf("invalid user identifier: %w", err)
	}

	userService := uc.base.Container.UserService()
	_, err = userService.UpdateUser(uc.base.Ctx, userId, model.UpdateUserRequest{
		Blocked: boolPtr(true),
	})
	if err != nil {
		uc.base.LogError("Failed to block user", err, zap.String("identifier", identifier))
		return fmt.Errorf("failed to block user: %w", err)
	}

	uc.base.LogInfo("User blocked successfully", zap.String("identifier", identifier))

	message := fmt.Sprintf("User blocked successfully: %s", identifier)
	return uc.base.ShowMessage("Success", message, false)
}

func (uc *UserCommands) unblockUser(cmd *cobra.Command, args []string) error {
	identifier := args[0]

	userId, err := xid.FromString(identifier)
	if err != nil {
		return fmt.Errorf("invalid user identifier: %w", err)
	}

	userService := uc.base.Container.UserService()
	_, err = userService.UpdateUser(uc.base.Ctx, userId, model.UpdateUserRequest{
		Blocked: boolPtr(false),
	})
	if err != nil {
		uc.base.LogError("Failed to unblock user", err, zap.String("identifier", identifier))
		return fmt.Errorf("failed to unblock user: %w", err)
	}

	uc.base.LogInfo("User unblocked successfully", zap.String("identifier", identifier))

	message := fmt.Sprintf("User unblocked successfully: %s", identifier)
	return uc.base.ShowMessage("Success", message, false)
}

// Helper functions
func boolPtr(b bool) *bool {
	return &b
}
