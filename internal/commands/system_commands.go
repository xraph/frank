package commands

import (
	"fmt"
	"time"

	"github.com/rs/xid"
	"github.com/spf13/cobra"
	"github.com/xraph/frank/ent/audit"
	"github.com/xraph/frank/ent/oauthtoken"
	"github.com/xraph/frank/ent/organization"
	"github.com/xraph/frank/ent/session"
	"github.com/xraph/frank/ent/user"
	"github.com/xraph/frank/pkg/crypto"
	"github.com/xraph/frank/pkg/model"
	"go.uber.org/zap"
)

// SystemCommands handles system-related CLI commands
type SystemCommands struct {
	base *BaseCommand
}

// NewSystemCommands creates a new SystemCommands instance
func NewSystemCommands(base *BaseCommand) *SystemCommands {
	return &SystemCommands{
		base: base,
	}
}

// AddCommands adds system commands to the root command
func (sc *SystemCommands) AddCommands(rootCmd *cobra.Command, base *BaseCommand) {
	systemCmd := &cobra.Command{
		Use:   "system",
		Short: "System management commands",
		Long:  "Commands for system administration and monitoring",
	}

	// System status
	statusCmd := &cobra.Command{
		Use:   "status",
		Short: "Show system status",
		RunE:  sc.systemStatus,
	}
	statusCmd.Flags().Bool("json", false, "output as JSON instead of formatted view")

	// System stats
	statsCmd := &cobra.Command{
		Use:   "stats",
		Short: "Show system statistics",
		RunE:  sc.systemStats,
	}
	statsCmd.Flags().Bool("json", false, "output as JSON instead of formatted view")

	// Health check
	healthCmd := &cobra.Command{
		Use:   "health",
		Short: "Check system health",
		RunE:  sc.systemHealth,
	}
	healthCmd.Flags().Bool("json", false, "output as JSON instead of formatted view")

	// Clean up expired sessions
	cleanupCmd := &cobra.Command{
		Use:   "cleanup",
		Short: "Clean up expired sessions and tokens",
		RunE:  sc.cleanup,
	}
	cleanupCmd.Flags().Bool("dry-run", false, "show what would be cleaned up without actually doing it")
	cleanupCmd.Flags().Bool("json", false, "output as JSON instead of formatted view")

	// Generate API key
	generateAPIKeyCmd := &cobra.Command{
		Use:   "generate-api-key [user-email]",
		Short: "Generate API key for user",
		Args:  cobra.ExactArgs(1),
		RunE:  sc.generateAPIKey,
	}
	generateAPIKeyCmd.Flags().String("name", "", "API key name")
	generateAPIKeyCmd.Flags().Int("expires-days", 365, "API key expiration in days (0 for no expiration)")
	generateAPIKeyCmd.Flags().Bool("json", false, "output as JSON instead of formatted view")

	systemCmd.AddCommand(statusCmd, statsCmd, healthCmd, cleanupCmd, generateAPIKeyCmd)
	rootCmd.AddCommand(systemCmd)
}

func (sc *SystemCommands) systemStatus(cmd *cobra.Command, args []string) error {
	jsonOutput, _ := cmd.Flags().GetBool("json")
	sc.base.UseJSON = jsonOutput

	sc.base.LogDebug("Checking system status")

	status := map[string]interface{}{
		"timestamp": time.Now().Format("2006-01-02 15:04:05"),
		"database":  "connected",
		"services":  "operational",
	}

	// Check container health
	if err := sc.base.Container.Health(sc.base.Ctx); err != nil {
		status["database"] = "disconnected"
		status["services"] = "degraded"
		status["error"] = err.Error()
		sc.base.LogWarn("Container health check failed", zap.Error(err))
	}

	// Get basic stats
	db := sc.base.Container.DB()
	userCount, err := db.User.Query().Where(user.ActiveEQ(true)).Count(sc.base.Ctx)
	if err != nil {
		sc.base.LogWarn("Failed to get user count", zap.Error(err))
		userCount = -1
	}

	orgCount, err := db.Organization.Query().Where(organization.ActiveEQ(true)).Count(sc.base.Ctx)
	if err != nil {
		sc.base.LogWarn("Failed to get organization count", zap.Error(err))
		orgCount = -1
	}

	status["active_users"] = userCount
	status["active_organizations"] = orgCount
	status["version"] = "1.0.0" // You can get this from your build info

	sc.base.LogInfo("System status retrieved",
		zap.Int("activeUsers", userCount),
		zap.Int("activeOrganizations", orgCount),
	)

	return sc.base.ShowStats("System Status", status)
}

func (sc *SystemCommands) systemStats(cmd *cobra.Command, args []string) error {
	jsonOutput, _ := cmd.Flags().GetBool("json")
	sc.base.UseJSON = jsonOutput

	sc.base.LogDebug("Retrieving system statistics")

	db := sc.base.Container.DB()
	stats := map[string]interface{}{}

	// User stats
	totalUsers, _ := db.User.Query().Count(sc.base.Ctx)
	activeUsers, _ := db.User.Query().Where(user.ActiveEQ(true)).Count(sc.base.Ctx)
	internalUsers, _ := db.User.Query().Where(user.UserTypeEQ(model.UserTypeInternal)).Count(sc.base.Ctx)
	externalUsers, _ := db.User.Query().Where(user.UserTypeEQ(model.UserTypeExternal)).Count(sc.base.Ctx)

	stats["users"] = map[string]int{
		"total":    totalUsers,
		"active":   activeUsers,
		"internal": internalUsers,
		"external": externalUsers,
	}

	// Organization stats
	totalOrgs, _ := db.Organization.Query().Count(sc.base.Ctx)
	activeOrgs, _ := db.Organization.Query().Where(organization.ActiveEQ(true)).Count(sc.base.Ctx)
	platformOrgs, _ := db.Organization.Query().Where(organization.OrgTypeEQ(model.OrgTypePlatform)).Count(sc.base.Ctx)
	customerOrgs, _ := db.Organization.Query().Where(organization.OrgTypeEQ(model.OrgTypeCustomer)).Count(sc.base.Ctx)

	stats["organizations"] = map[string]int{
		"total":    totalOrgs,
		"active":   activeOrgs,
		"platform": platformOrgs,
		"customer": customerOrgs,
	}

	// Session stats
	activeSessions, _ := db.Session.Query().Where(session.ExpiresAtGT(time.Now())).Count(sc.base.Ctx)
	expiredSessions, _ := db.Session.Query().Where(session.ExpiresAtLTE(time.Now())).Count(sc.base.Ctx)

	stats["sessions"] = map[string]int{
		"active":  activeSessions,
		"expired": expiredSessions,
	}

	// Audit stats
	auditCount, _ := db.Audit.Query().Count(sc.base.Ctx)
	recentAudits, _ := db.Audit.Query().Where(audit.CreatedAtGT(time.Now().AddDate(0, 0, -7))).Count(sc.base.Ctx)

	stats["audit_logs"] = map[string]int{
		"total":       auditCount,
		"last_7_days": recentAudits,
	}

	sc.base.LogInfo("System statistics retrieved",
		zap.Int("totalUsers", totalUsers),
		zap.Int("totalOrgs", totalOrgs),
		zap.Int("activeSessions", activeSessions),
	)

	return sc.base.ShowStats("System Statistics", stats)
}

func (sc *SystemCommands) systemHealth(cmd *cobra.Command, args []string) error {
	jsonOutput, _ := cmd.Flags().GetBool("json")
	sc.base.UseJSON = jsonOutput

	sc.base.LogDebug("Performing system health check")

	health := map[string]interface{}{
		"overall_status": "healthy",
		"timestamp":      time.Now().Format("2006-01-02 15:04:05"),
	}

	checks := map[string]interface{}{}

	// Check container health
	if err := sc.base.Container.Health(sc.base.Ctx); err != nil {
		health["overall_status"] = "unhealthy"
		checks["container"] = map[string]interface{}{
			"status": "❌ failed",
			"error":  err.Error(),
		}
		sc.base.LogWarn("Container health check failed", zap.Error(err))
	} else {
		checks["container"] = map[string]interface{}{
			"status": "✅ passed",
		}
	}

	// Check database connectivity
	db := sc.base.Container.DB()
	if _, err := db.User.Query().Limit(1).Count(sc.base.Ctx); err != nil {
		health["overall_status"] = "unhealthy"
		checks["database"] = map[string]interface{}{
			"status": "❌ failed",
			"error":  err.Error(),
		}
		sc.base.LogWarn("Database health check failed", zap.Error(err))
	} else {
		checks["database"] = map[string]interface{}{
			"status": "✅ passed",
		}
	}

	// Check Redis if available
	if redis := sc.base.Container.Redis(); redis != nil {
		if err := redis.Ping(sc.base.Ctx).Err(); err != nil {
			checks["redis"] = map[string]interface{}{
				"status": "❌ failed",
				"error":  err.Error(),
			}
			sc.base.LogWarn("Redis health check failed", zap.Error(err))
		} else {
			checks["redis"] = map[string]interface{}{
				"status": "✅ passed",
			}
		}
	} else {
		checks["redis"] = map[string]interface{}{
			"status": "⚠️  not configured",
		}
	}

	health["checks"] = checks

	isHealthy := health["overall_status"] == "healthy"
	sc.base.LogInfo("System health check completed", zap.Bool("healthy", isHealthy))

	return sc.base.ShowStats("System Health Check", health)
}

func (sc *SystemCommands) cleanup(cmd *cobra.Command, args []string) error {
	dryRun, _ := cmd.Flags().GetBool("dry-run")
	jsonOutput, _ := cmd.Flags().GetBool("json")
	sc.base.UseJSON = jsonOutput

	sc.base.LogDebug("Starting system cleanup", zap.Bool("dryRun", dryRun))

	db := sc.base.Container.DB()
	cleaned := map[string]interface{}{}

	// Clean expired sessions
	expiredSessions, err := db.Session.Query().Where(session.ExpiresAtLTE(time.Now())).Count(sc.base.Ctx)
	if err == nil && expiredSessions > 0 {
		if !dryRun {
			_, err := db.Session.Delete().Where(session.ExpiresAtLTE(time.Now())).Exec(sc.base.Ctx)
			if err != nil {
				sc.base.LogError("Failed to clean expired sessions", err)
				return fmt.Errorf("failed to clean expired sessions: %w", err)
			}
		}
		cleaned["expired_sessions"] = expiredSessions
	}

	// Clean expired tokens
	expiredTokens, err := db.OAuthToken.Query().Where(oauthtoken.ExpiresAtLTE(time.Now())).Count(sc.base.Ctx)
	if err == nil && expiredTokens > 0 {
		if !dryRun {
			_, err := db.OAuthToken.Delete().Where(oauthtoken.ExpiresAtLTE(time.Now())).Exec(sc.base.Ctx)
			if err != nil {
				sc.base.LogError("Failed to clean expired tokens", err)
				return fmt.Errorf("failed to clean expired tokens: %w", err)
			}
		}
		cleaned["expired_tokens"] = expiredTokens
	}

	// Clean old audit logs (older than 1 year)
	oldAuditLogs, err := db.Audit.Query().Where(audit.CreatedAtLT(time.Now().AddDate(-1, 0, 0))).Count(sc.base.Ctx)
	if err == nil && oldAuditLogs > 0 {
		if !dryRun {
			_, err := db.Audit.Delete().Where(audit.CreatedAtLT(time.Now().AddDate(-1, 0, 0))).Exec(sc.base.Ctx)
			if err != nil {
				sc.base.LogError("Failed to clean old audit logs", err)
				return fmt.Errorf("failed to clean old audit logs: %w", err)
			}
		}
		cleaned["old_audit_logs"] = oldAuditLogs
	}

	action := "cleaned"
	if dryRun {
		action = "would clean"
	}

	result := map[string]interface{}{
		"action":    action,
		"timestamp": time.Now().Format("2006-01-02 15:04:05"),
		"results":   cleaned,
	}

	sc.base.LogInfo("Cleanup completed",
		zap.String("action", action),
		zap.Any("results", cleaned),
		zap.Bool("dryRun", dryRun),
	)

	title := "System Cleanup Results"
	if dryRun {
		title += " (Dry Run)"
	}

	return sc.base.ShowStats(title, result)
}

func (sc *SystemCommands) generateAPIKey(cmd *cobra.Command, args []string) error {
	userEmail := args[0]
	name, _ := cmd.Flags().GetString("name")
	expiresDays, _ := cmd.Flags().GetInt("expires-days")
	jsonOutput, _ := cmd.Flags().GetBool("json")
	sc.base.UseJSON = jsonOutput

	sc.base.LogDebug("Generating API key",
		zap.String("userEmail", userEmail),
		zap.String("name", name),
		zap.Int("expiresDays", expiresDays),
	)

	// Get user
	userService := sc.base.Container.UserService()
	user, err := userService.GetUserByIdentifier(sc.base.Ctx, userEmail, model.UserTypeEndUser)
	if err != nil {
		sc.base.LogError("User not found", err, zap.String("userEmail", userEmail))
		return fmt.Errorf("user not found: %s", userEmail)
	}

	// Generate API key
	apiKey, err := crypto.GenerateAPIKey()
	if err != nil {
		sc.base.LogError("Failed to generate API key", err)
		return fmt.Errorf("failed to generate API key: %w", err)
	}

	hashedKey, err := sc.base.Container.Crypto().PasswordHasher().HashPassword(apiKey)
	if err != nil {
		sc.base.LogError("Failed to hash API key", err)
		return fmt.Errorf("failed to hash API key: %w", err)
	}

	// Calculate expiration
	var expiresAt *time.Time
	if expiresDays > 0 {
		expires := time.Now().AddDate(0, 0, expiresDays)
		expiresAt = &expires
	}

	if name == "" {
		name = fmt.Sprintf("CLI Generated - %s", time.Now().Format("2006-01-02"))
	}

	// Save API key to database
	keyID := xid.New()
	_, err = sc.base.Container.DB().ApiKey.Create().
		SetUserID(user.ID).
		SetName(name).
		SetHashedKey(hashedKey).
		SetNillableExpiresAt(expiresAt).
		Save(sc.base.Ctx)
	if err != nil {
		sc.base.LogError("Failed to save API key", err,
			zap.String("keyID", keyID.String()),
			zap.String("userEmail", userEmail),
		)
		return fmt.Errorf("failed to save API key: %w", err)
	}

	result := map[string]interface{}{
		"id":         keyID.String(),
		"user_email": userEmail,
		"name":       name,
		"api_key":    apiKey,
		"created_at": time.Now().Format("2006-01-02 15:04:05"),
	}

	if expiresAt != nil {
		result["expires_at"] = expiresAt.Format("2006-01-02 15:04:05")
		result["expires_in_days"] = expiresDays
	} else {
		result["expires_at"] = "Never"
		result["expires_in_days"] = "Never"
	}

	sc.base.LogInfo("API key generated successfully",
		zap.String("keyID", keyID.String()),
		zap.String("user", userEmail),
		zap.String("name", name),
		zap.Int("expiresDays", expiresDays),
	)

	// Show the result with a warning about saving the key
	if jsonOutput {
		return sc.base.ShowStats("API Key Generated", result)
	}

	// For non-JSON output, show a detailed view with warning
	data := map[string]interface{}{
		"key_id":     result["id"],
		"user_email": result["user_email"],
		"name":       result["name"],
		"created_at": result["created_at"],
		"expires_at": result["expires_at"],
		"expires_in": result["expires_in_days"],
		"⚠️ WARNING": "Save this API key securely - it cannot be retrieved again!",
		"🔑 API_KEY":  result["api_key"],
	}

	return sc.base.ShowDetails("API Key Generated Successfully", data)
}
