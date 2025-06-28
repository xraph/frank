package commands

import (
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/spf13/cobra"
	"github.com/xraph/frank/ent"
	"github.com/xraph/frank/ent/audit"
	"github.com/xraph/frank/pkg/model"
	"go.uber.org/zap"
)

// AuditCommands handles audit-related CLI commands
type AuditCommands struct {
	base *BaseCommand
}

// NewAuditCommands creates a new AuditCommands instance
func NewAuditCommands(base *BaseCommand) *AuditCommands {
	return &AuditCommands{
		base: base,
	}
}

// AddCommands adds audit commands to the root command
func (ac *AuditCommands) AddCommands(rootCmd *cobra.Command, base *BaseCommand) {
	auditCmd := &cobra.Command{
		Use:   "audit",
		Short: "Audit and compliance commands",
		Long:  "Commands for audit logging and compliance reporting",
	}

	// List audit logs
	listLogsCmd := &cobra.Command{
		Use:   "logs",
		Short: "List audit logs",
		RunE:  ac.listAuditLogs,
	}
	listLogsCmd.Flags().String("user", "", "filter by user ID or email")
	listLogsCmd.Flags().String("action", "", "filter by action")
	listLogsCmd.Flags().String("resource", "", "filter by resource type")
	listLogsCmd.Flags().String("since", "", "filter logs since date (YYYY-MM-DD)")
	listLogsCmd.Flags().Int("limit", 100, "limit number of results")
	listLogsCmd.Flags().Bool("json", false, "output as JSON instead of table")

	// Export audit logs
	exportLogsCmd := &cobra.Command{
		Use:   "export [output-file]",
		Short: "Export audit logs to file",
		Args:  cobra.ExactArgs(1),
		RunE:  ac.exportAuditLogs,
	}
	exportLogsCmd.Flags().String("format", "json", "export format (json, csv)")
	exportLogsCmd.Flags().String("since", "", "export logs since date (YYYY-MM-DD)")
	exportLogsCmd.Flags().String("until", "", "export logs until date (YYYY-MM-DD)")

	// Audit stats
	statsCmd := &cobra.Command{
		Use:   "stats",
		Short: "Show audit statistics",
		RunE:  ac.auditStats,
	}
	statsCmd.Flags().String("period", "7d", "period for statistics (1d, 7d, 30d, 90d)")
	statsCmd.Flags().Bool("json", false, "output as JSON instead of formatted view")

	auditCmd.AddCommand(listLogsCmd, exportLogsCmd, statsCmd)
	rootCmd.AddCommand(auditCmd)
}

func (ac *AuditCommands) listAuditLogs(cmd *cobra.Command, args []string) error {
	userFilter, _ := cmd.Flags().GetString("user")
	actionFilter, _ := cmd.Flags().GetString("action")
	resourceFilter, _ := cmd.Flags().GetString("resource")
	sinceFilter, _ := cmd.Flags().GetString("since")
	limit, _ := cmd.Flags().GetInt("limit")
	jsonOutput, _ := cmd.Flags().GetBool("json")

	ac.base.UseJSON = jsonOutput

	ac.base.LogDebug("Listing audit logs",
		zap.String("userFilter", userFilter),
		zap.String("actionFilter", actionFilter),
		zap.String("resourceFilter", resourceFilter),
		zap.String("sinceFilter", sinceFilter),
		zap.Int("limit", limit),
	)

	db := ac.base.Container.DB()
	query := db.Audit.Query()

	if userFilter != "" {
		// Try to find user by email or ID
		user, err := ac.base.Container.UserService().GetUserByIdentifier(ac.base.Ctx, userFilter, model.UserTypeEndUser)
		if err == nil {
			query = query.Where(audit.UserIDEQ(user.ID))
		}
	}

	if actionFilter != "" {
		query = query.Where(audit.ActionContainsFold(actionFilter))
	}

	if resourceFilter != "" {
		query = query.Where(audit.ResourceTypeContainsFold(resourceFilter))
	}

	if sinceFilter != "" {
		since, err := time.Parse("2006-01-02", sinceFilter)
		if err != nil {
			ac.base.LogError("Invalid date format for since", err, zap.String("sinceFilter", sinceFilter))
			return fmt.Errorf("invalid date format for since: %w", err)
		}
		query = query.Where(audit.CreatedAtGTE(since))
	}

	logs, err := query.
		Limit(limit).
		Order(ent.Desc("created_at")).
		All(ac.base.Ctx)
	if err != nil {
		ac.base.LogError("Failed to query audit logs", err)
		return fmt.Errorf("failed to query audit logs: %w", err)
	}

	// Prepare table data
	headers := []string{"Timestamp", "User", "Action", "Resource", "Resource ID", "IP Address", "Status"}
	var rows [][]string

	for _, log := range logs {
		// Truncate long values for table display
		userID := log.UserID.String()
		if len(userID) > 12 {
			userID = userID[:8] + "..."
		}

		resourceID := log.ResourceID.String()
		if len(resourceID) > 15 {
			resourceID = resourceID[:12] + "..."
		}

		action := log.Action
		if len(action) > 20 {
			action = action[:17] + "..."
		}

		status := "✅ Success"
		if log.Status != "" && log.Status != "success" {
			status = "❌ " + log.Status
		}

		rows = append(rows, []string{
			log.CreatedAt.Format("01-02 15:04:05"),
			userID,
			action,
			log.ResourceType,
			resourceID,
			log.IPAddress,
			status,
		})
	}

	ac.base.LogInfo("Listed audit logs successfully", zap.Int("count", len(logs)))

	title := fmt.Sprintf("Audit Logs (%d entries)", len(logs))
	if userFilter != "" {
		title += fmt.Sprintf(" - User: %s", userFilter)
	}
	if actionFilter != "" {
		title += fmt.Sprintf(" - Action: %s", actionFilter)
	}
	if resourceFilter != "" {
		title += fmt.Sprintf(" - Resource: %s", resourceFilter)
	}
	if sinceFilter != "" {
		title += fmt.Sprintf(" - Since: %s", sinceFilter)
	}

	return ac.base.ShowTable(title, headers, rows)
}

func (ac *AuditCommands) exportAuditLogs(cmd *cobra.Command, args []string) error {
	outputFile := args[0]
	format, _ := cmd.Flags().GetString("format")
	sinceFilter, _ := cmd.Flags().GetString("since")
	untilFilter, _ := cmd.Flags().GetString("until")

	ac.base.LogDebug("Exporting audit logs",
		zap.String("outputFile", outputFile),
		zap.String("format", format),
		zap.String("sinceFilter", sinceFilter),
		zap.String("untilFilter", untilFilter),
	)

	db := ac.base.Container.DB()
	query := db.Audit.Query()

	if sinceFilter != "" {
		since, err := time.Parse("2006-01-02", sinceFilter)
		if err != nil {
			ac.base.LogError("Invalid date format for since", err, zap.String("sinceFilter", sinceFilter))
			return fmt.Errorf("invalid date format for since: %w", err)
		}
		query = query.Where(audit.CreatedAtGTE(since))
	}

	if untilFilter != "" {
		until, err := time.Parse("2006-01-02", untilFilter)
		if err != nil {
			ac.base.LogError("Invalid date format for until", err, zap.String("untilFilter", untilFilter))
			return fmt.Errorf("invalid date format for until: %w", err)
		}
		query = query.Where(audit.CreatedAtLTE(until))
	}

	logs, err := query.Order(ent.Desc("created_at")).All(ac.base.Ctx)
	if err != nil {
		ac.base.LogError("Failed to query audit logs for export", err)
		return fmt.Errorf("failed to query audit logs: %w", err)
	}

	file, err := os.Create(outputFile)
	if err != nil {
		ac.base.LogError("Failed to create output file", err, zap.String("outputFile", outputFile))
		return fmt.Errorf("failed to create output file: %w", err)
	}
	defer file.Close()

	switch format {
	case "json":
		encoder := json.NewEncoder(file)
		encoder.SetIndent("", "  ")
		if err := encoder.Encode(logs); err != nil {
			ac.base.LogError("Failed to encode JSON", err)
			return fmt.Errorf("failed to encode JSON: %w", err)
		}
	case "csv":
		// Simple CSV export - would need a proper CSV library for production
		file.WriteString("ID,UserID,Action,ResourceType,ResourceID,IPAddress,UserAgent,CreatedAt,Status\n")
		for _, log := range logs {
			status := "success"
			if log.Status != "" {
				status = log.Status
			}
			file.WriteString(fmt.Sprintf("%s,%s,%s,%s,%s,%s,%s,%s,%s\n",
				log.ID, log.UserID, log.Action, log.ResourceType,
				log.ResourceID, log.IPAddress, log.UserAgent,
				log.CreatedAt.Format(time.RFC3339), status))
		}
	default:
		ac.base.LogError("Unsupported export format", nil, zap.String("format", format))
		return fmt.Errorf("unsupported format: %s", format)
	}

	ac.base.LogInfo("Audit logs exported successfully",
		zap.String("file", outputFile),
		zap.String("format", format),
		zap.Int("count", len(logs)),
	)

	message := fmt.Sprintf("Successfully exported %d audit logs to %s (%s format)",
		len(logs), outputFile, format)
	return ac.base.ShowMessage("Export Complete", message, false)
}

func (ac *AuditCommands) auditStats(cmd *cobra.Command, args []string) error {
	period, _ := cmd.Flags().GetString("period")
	jsonOutput, _ := cmd.Flags().GetBool("json")

	ac.base.UseJSON = jsonOutput

	ac.base.LogDebug("Retrieving audit statistics", zap.String("period", period))

	// Parse period
	var since time.Time
	switch period {
	case "1d":
		since = time.Now().AddDate(0, 0, -1)
	case "7d":
		since = time.Now().AddDate(0, 0, -7)
	case "30d":
		since = time.Now().AddDate(0, 0, -30)
	case "90d":
		since = time.Now().AddDate(0, 0, -90)
	default:
		return fmt.Errorf("invalid period: %s (valid: 1d, 7d, 30d, 90d)", period)
	}

	db := ac.base.Container.DB()
	stats := map[string]interface{}{}

	// Total logs in period
	totalLogs, _ := db.Audit.Query().Where(audit.CreatedAtGTE(since)).Count(ac.base.Ctx)
	stats["total_logs"] = totalLogs

	// Top actions
	// This would need a proper group by query in a real implementation
	loginLogs, _ := db.Audit.Query().
		Where(audit.CreatedAtGTE(since)).
		Where(audit.ActionContains("login")).
		Count(ac.base.Ctx)

	createLogs, _ := db.Audit.Query().
		Where(audit.CreatedAtGTE(since)).
		Where(audit.ActionContains("create")).
		Count(ac.base.Ctx)

	updateLogs, _ := db.Audit.Query().
		Where(audit.CreatedAtGTE(since)).
		Where(audit.ActionContains("update")).
		Count(ac.base.Ctx)

	deleteLogs, _ := db.Audit.Query().
		Where(audit.CreatedAtGTE(since)).
		Where(audit.ActionContains("delete")).
		Count(ac.base.Ctx)

	stats["top_actions"] = map[string]int{
		"login":  loginLogs,
		"create": createLogs,
		"update": updateLogs,
		"delete": deleteLogs,
	}

	// Resource types
	userLogs, _ := db.Audit.Query().
		Where(audit.CreatedAtGTE(since)).
		Where(audit.ResourceTypeEQ("user")).
		Count(ac.base.Ctx)

	orgLogs, _ := db.Audit.Query().
		Where(audit.CreatedAtGTE(since)).
		Where(audit.ResourceTypeEQ("organization")).
		Count(ac.base.Ctx)

	sessionLogs, _ := db.Audit.Query().
		Where(audit.CreatedAtGTE(since)).
		Where(audit.ResourceTypeEQ("session")).
		Count(ac.base.Ctx)

	stats["resource_types"] = map[string]int{
		"user":         userLogs,
		"organization": orgLogs,
		"session":      sessionLogs,
	}

	// Daily breakdown for the period
	dailyStats := map[string]int{}
	for i := 0; i < int(time.Since(since).Hours()/24); i++ {
		day := time.Now().AddDate(0, 0, -i)
		dayStart := time.Date(day.Year(), day.Month(), day.Day(), 0, 0, 0, 0, day.Location())
		dayEnd := dayStart.Add(24 * time.Hour)

		count, _ := db.Audit.Query().
			Where(audit.CreatedAtGTE(dayStart)).
			Where(audit.CreatedAtLT(dayEnd)).
			Count(ac.base.Ctx)

		dailyStats[day.Format("01-02")] = count
	}
	stats["daily_breakdown"] = dailyStats

	stats["period"] = period
	stats["date_range"] = map[string]string{
		"from": since.Format("2006-01-02"),
		"to":   time.Now().Format("2006-01-02"),
	}

	ac.base.LogInfo("Audit statistics retrieved",
		zap.String("period", period),
		zap.Int("totalLogs", totalLogs),
	)

	title := fmt.Sprintf("Audit Statistics - Last %s", period)
	return ac.base.ShowStats(title, stats)
}
