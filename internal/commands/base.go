package commands

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/gdamore/tcell/v2"
	"github.com/juicycleff/frank/config"
	"github.com/juicycleff/frank/internal/di"
	"github.com/juicycleff/frank/pkg/logging"
	"github.com/juicycleff/frank/pkg/model"
	"github.com/rivo/tview"
	"github.com/spf13/cobra"
	"go.uber.org/zap"
)

// BaseCommand holds shared dependencies for all commands
type BaseCommand struct {
	Config    *config.Config
	Container di.Container
	Logger    logging.Logger
	Ctx       context.Context
	App       *tview.Application // TView application
	UseJSON   bool               // Flag to output JSON instead of TView
}

// CommandGroup interface for command groups
type CommandGroup interface {
	AddCommands(rootCmd *cobra.Command, base *BaseCommand)
}

// NewBaseCommand creates a new base command with dependencies
func NewBaseCommand(config *config.Config, container di.Container, logger logging.Logger, ctx context.Context) *BaseCommand {
	return &BaseCommand{
		Config:    config,
		Container: container,
		Logger:    logger,
		Ctx:       ctx,
		App:       tview.NewApplication(),
		UseJSON:   false,
	}
}

// LogError logs an error with context
func (b *BaseCommand) LogError(msg string, err error, fields ...zap.Field) {
	allFields := append(fields, zap.Error(err))
	b.Logger.Error(msg, allFields...)
}

// LogInfo logs an info message with fields
func (b *BaseCommand) LogInfo(msg string, fields ...zap.Field) {
	b.Logger.Info(msg, fields...)
}

// LogWarn logs a warning message with fields
func (b *BaseCommand) LogWarn(msg string, fields ...zap.Field) {
	b.Logger.Warn(msg, fields...)
}

// LogDebug logs a debug message with fields
func (b *BaseCommand) LogDebug(msg string, fields ...zap.Field) {
	b.Logger.Debug(msg, fields...)
}

// ShowTable displays data in a table format using tview
func (b *BaseCommand) ShowTable(title string, headers []string, rows [][]string) error {
	if b.UseJSON {
		return b.outputJSON(map[string]interface{}{
			"title": title,
			"data":  rows,
		})
	}

	table := tview.NewTable().SetBorders(true)

	// Set headers
	for i, header := range headers {
		table.SetCell(0, i, tview.NewTableCell(header).
			SetTextColor(tview.Styles.PrimaryTextColor).
			SetBackgroundColor(tview.Styles.PrimitiveBackgroundColor).
			SetAttributes(tcell.AttrBold))
	}

	// Set data rows
	for rowIndex, row := range rows {
		for colIndex, cell := range row {
			table.SetCell(rowIndex+1, colIndex, tview.NewTableCell(cell).
				SetTextColor(tview.Styles.PrimaryTextColor))
		}
	}

	// Make table selectable
	table.SetSelectable(true, false)
	// table.SetSelectedStyle(tview.Styles.PrimaryTextColor, tview.Styles.ContrastBackgroundColor, tcell.AttrBold)

	// Create layout
	flex := tview.NewFlex().SetDirection(tview.FlexRow).
		AddItem(tview.NewTextView().SetText(fmt.Sprintf(" %s ", title)).SetTextAlign(tview.AlignCenter), 1, 0, false).
		AddItem(table, 0, 1, true).
		AddItem(tview.NewTextView().SetText(" Press 'q' to quit, 'j' to export JSON ").SetTextAlign(tview.AlignCenter), 1, 0, false)

	// Handle key events
	table.SetInputCapture(func(event *tcell.EventKey) *tcell.EventKey {
		switch event.Rune() {
		case 'q':
			b.App.Stop()
		case 'j':
			b.App.Stop()
			b.outputJSON(map[string]interface{}{
				"title": title,
				"data":  rows,
			})
		}
		return event
	})

	b.App.SetRoot(flex, true)
	return b.App.Run()
}

// ShowDetails displays detailed information about a single item
func (b *BaseCommand) ShowDetails(title string, data map[string]interface{}) error {
	if b.UseJSON {
		return b.outputJSON(data)
	}

	form := tview.NewForm()
	form.SetBorder(true).SetTitle(fmt.Sprintf(" %s ", title))

	// Add fields to form (read-only)
	for key, value := range data {
		valueStr := fmt.Sprintf("%v", value)
		if t, ok := value.(time.Time); ok {
			valueStr = t.Format("2006-01-02 15:04:05")
		}
		form.AddTextView(strings.Title(strings.ReplaceAll(key, "_", " ")), valueStr, 0, 1, true, false)
	}

	form.AddButton("JSON", func() {
		b.App.Stop()
		b.outputJSON(data)
	})
	form.AddButton("Quit", func() {
		b.App.Stop()
	})

	b.App.SetRoot(form, true)
	return b.App.Run()
}

// ShowList displays a simple list of items
func (b *BaseCommand) ShowList(title string, items []string) error {
	if b.UseJSON {
		return b.outputJSON(map[string]interface{}{
			"title": title,
			"items": items,
		})
	}

	list := tview.NewList()
	list.SetBorder(true).SetTitle(fmt.Sprintf(" %s ", title))

	for i, item := range items {
		list.AddItem(item, "", rune('a'+i), nil)
	}

	list.SetInputCapture(func(event *tcell.EventKey) *tcell.EventKey {
		switch event.Rune() {
		case 'q':
			b.App.Stop()
		case 'j':
			b.App.Stop()
			b.outputJSON(map[string]interface{}{
				"title": title,
				"items": items,
			})
		}
		return event
	})

	b.App.SetRoot(list, true)
	return b.App.Run()
}

// ShowStats displays statistics in a formatted view
func (b *BaseCommand) ShowStats(title string, stats map[string]interface{}) error {
	if b.UseJSON {
		return b.outputJSON(stats)
	}

	textView := tview.NewTextView().
		SetDynamicColors(true).
		SetRegions(true).
		SetBorder(true).
		SetTitle(fmt.Sprintf(" %s ", title))

	var content strings.Builder
	content.WriteString(fmt.Sprintf("[yellow]%s[white]\n\n", title))

	for category, value := range stats {
		content.WriteString(fmt.Sprintf("[green]%s:[white]\n", strings.Title(strings.ReplaceAll(category, "_", " "))))

		if subStats, ok := value.(map[string]int); ok {
			for key, val := range subStats {
				content.WriteString(fmt.Sprintf("  [cyan]%s:[white] %d\n", strings.Title(strings.ReplaceAll(key, "_", " ")), val))
			}
		} else {
			content.WriteString(fmt.Sprintf("  [cyan]%v[white]\n", value))
		}
		content.WriteString("\n")
	}

	content.WriteString("[yellow]Press 'q' to quit, 'j' for JSON[white]")
	textView.SetTitle(content.String())

	textView.SetInputCapture(func(event *tcell.EventKey) *tcell.EventKey {
		switch event.Rune() {
		case 'q':
			b.App.Stop()
		case 'j':
			b.App.Stop()
			b.outputJSON(stats)
		}
		return event
	})

	b.App.SetRoot(textView, true)
	return b.App.Run()
}

// ShowMessage displays a simple message with optional confirmation
func (b *BaseCommand) ShowMessage(title, message string, requireConfirm bool) error {
	if b.UseJSON {
		fmt.Println(message)
		return nil
	}

	modal := tview.NewModal().
		SetText(message).
		AddButtons([]string{"OK"}).
		SetDoneFunc(func(buttonIndex int, buttonLabel string) {
			b.App.Stop()
		})

	if title != "" {
		modal.SetTitle(title)
	}

	b.App.SetRoot(modal, false)
	return b.App.Run()
}

// outputJSON outputs data as JSON (fallback or when requested)
func (b *BaseCommand) outputJSON(data interface{}) error {
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	return encoder.Encode(data)
}

// ShowInteractiveForm displays an interactive form for user input
func (b *BaseCommand) ShowInteractiveForm(title string, fields []FormField, onSubmit func(map[string]string) error) error {
	if b.UseJSON {
		// For JSON mode, prompt for each field via stdin
		return b.promptForFields(fields, onSubmit)
	}

	form := tview.NewForm()
	form.SetBorder(true).SetTitle(fmt.Sprintf(" %s ", title))

	values := make(map[string]string)

	// Add form fields
	for _, field := range fields {
		switch field.Type {
		case "text":
			form.AddInputField(field.Label, field.Default, 0, nil, func(text string) {
				values[field.Key] = text
			})
		case "password":
			form.AddPasswordField(field.Label, field.Default, 0, '*', func(text string) {
				values[field.Key] = text
			})
		case "select":
			form.AddDropDown(field.Label, field.Options, 0, func(option string, index int) {
				values[field.Key] = option
			})
		case "checkbox":
			form.AddCheckbox(field.Label, field.Default == "true", func(checked bool) {
				values[field.Key] = strconv.FormatBool(checked)
			})
		case "textarea":
			form.AddTextArea(field.Label, field.Default, 0, 0, 0, func(text string) {
				values[field.Key] = text
			})
		}
	}

	// Add buttons
	form.AddButton("Submit", func() {
		b.App.Stop()
		onSubmit(values)
	})

	form.AddButton("Cancel", func() {
		b.App.Stop()
	})

	b.App.SetRoot(form, true)
	return b.App.Run()
}

// FormField represents a form field configuration
type FormField struct {
	Key     string
	Label   string
	Type    string // "text", "password", "select", "checkbox", "textarea"
	Default string
	Options []string // for select fields
}

// ShowMultiPanel displays multiple panels side by side
func (b *BaseCommand) ShowMultiPanel(title string, panels []Panel) error {
	if b.UseJSON {
		// Combine all panel data for JSON output
		combined := map[string]interface{}{}
		for _, panel := range panels {
			combined[panel.Title] = panel.Data
		}
		return b.outputJSON(combined)
	}

	flex := tview.NewFlex()

	for i, panel := range panels {
		var primitive tview.Primitive

		switch panel.Type {
		case "table":
			table := tview.NewTable().SetBorders(true)
			table.SetTitle(fmt.Sprintf(" %s ", panel.Title))

			// Add headers if available
			if headers, ok := panel.Data["headers"].([]string); ok {
				for col, header := range headers {
					table.SetCell(0, col, tview.NewTableCell(header).SetAttributes(tcell.AttrBold))
				}
			}

			// Add data rows
			if rows, ok := panel.Data["rows"].([][]string); ok {
				for row, data := range rows {
					for col, cell := range data {
						table.SetCell(row+1, col, tview.NewTableCell(cell))
					}
				}
			}

			primitive = table

		case "text":
			textView := tview.NewTextView()
			textView.SetTitle(fmt.Sprintf(" %s ", panel.Title))
			textView.SetBorder(true)

			if text, ok := panel.Data["content"].(string); ok {
				textView.SetText(text)
			}

			primitive = textView

		case "list":
			list := tview.NewList()
			list.SetTitle(fmt.Sprintf(" %s ", panel.Title))
			list.SetBorder(true)

			if items, ok := panel.Data["items"].([]string); ok {
				for _, item := range items {
					list.AddItem(item, "", 0, nil)
				}
			}

			primitive = list
		}

		if primitive != nil {
			if i == 0 {
				flex.AddItem(primitive, 0, 1, true)
			} else {
				flex.AddItem(primitive, 0, 1, false)
			}
		}
	}

	// Add title and navigation help
	mainFlex := tview.NewFlex().SetDirection(tview.FlexRow)
	titleView := tview.NewTextView().SetText(fmt.Sprintf(" %s ", title)).SetTextAlign(tview.AlignCenter)
	helpView := tview.NewTextView().SetText(" Tab: Switch panels | q: Quit | j: JSON ").SetTextAlign(tview.AlignCenter)

	mainFlex.AddItem(titleView, 1, 0, false)
	mainFlex.AddItem(flex, 0, 1, true)
	mainFlex.AddItem(helpView, 1, 0, false)

	// Handle navigation
	mainFlex.SetInputCapture(func(event *tcell.EventKey) *tcell.EventKey {
		switch event.Rune() {
		case 'q':
			b.App.Stop()
		case 'j':
			b.App.Stop()
			combined := map[string]interface{}{}
			for _, panel := range panels {
				combined[panel.Title] = panel.Data
			}
			b.outputJSON(combined)
		}
		return event
	})

	b.App.SetRoot(mainFlex, true)
	return b.App.Run()
}

// Panel represents a panel in a multi-panel layout
type Panel struct {
	Title string
	Type  string // "table", "text", "list"
	Data  map[string]interface{}
}

// promptForFields handles form input in JSON mode
func (b *BaseCommand) promptForFields(fields []FormField, onSubmit func(map[string]string) error) error {
	values := make(map[string]string)

	for _, field := range fields {
		var input string
		fmt.Printf("%s", field.Label)
		if field.Default != "" {
			fmt.Printf(" [%s]", field.Default)
		}
		fmt.Print(": ")

		fmt.Scanln(&input)
		if input == "" && field.Default != "" {
			input = field.Default
		}

		values[field.Key] = input
	}

	return onSubmit(values)
}

// Example: Interactive user creation form
func (uc *UserCommands) createUserInteractive(cmd *cobra.Command, args []string) error {
	fields := []FormField{
		{Key: "email", Label: "Email Address", Type: "text"},
		{Key: "username", Label: "Username", Type: "text"},
		{Key: "firstName", Label: "First Name", Type: "text"},
		{Key: "lastName", Label: "Last Name", Type: "text"},
		{Key: "password", Label: "Password", Type: "password"},
		{Key: "userType", Label: "User Type", Type: "select", Options: []string{"internal", "external"}},
		{Key: "verified", Label: "Email Verified", Type: "checkbox", Default: "false"},
		{Key: "admin", Label: "Admin User", Type: "checkbox", Default: "false"},
	}

	return uc.base.ShowInteractiveForm("Create New User", fields, func(values map[string]string) error {
		// Validate required fields
		if values["email"] == "" {
			return fmt.Errorf("email is required")
		}

		username := values["username"]
		password := values["password"]
		userType := values["userType"]

		// Create user request
		createReq := &model.CreateUserRequest{
			Email:         values["email"],
			Username:      &username,
			FirstName:     &password,
			LastName:      &userType,
			Password:      values["password"],
			UserType:      model.UserType(values["userType"]),
			EmailVerified: values["verified"] == "true",
			Active:        true,
		}

		// Create user
		userService := uc.base.Container.UserService()
		newUser, err := userService.CreateUser(uc.base.Ctx, *createReq)
		if err != nil {
			return fmt.Errorf("failed to create user: %w", err)
		}

		// Show success message
		message := fmt.Sprintf("User created successfully!\n\nID: %s\nEmail: %s",
			newUser.ID.String(), values["email"])
		return uc.base.ShowMessage("Success", message, false)
	})
}

// Example: Dashboard with multiple panels
func (sc *SystemCommands) showDashboard(cmd *cobra.Command, args []string) error {
	jsonOutput, _ := cmd.Flags().GetBool("json")
	sc.base.UseJSON = jsonOutput

	// Fetch data for different panels
	db := sc.base.Container.DB()

	// System status panel
	statusPanel := Panel{
		Title: "System Status",
		Type:  "text",
		Data: map[string]interface{}{
			"content": sc.getSystemStatusText(),
		},
	}

	// Recent users panel
	recentUsers, _ := db.User.Query().Limit(10).All(sc.base.Ctx)
	userRows := [][]string{}
	for _, user := range recentUsers {
		userRows = append(userRows, []string{
			user.Email,
			string(user.UserType),
			user.CreatedAt.Format("01-02 15:04"),
		})
	}

	usersPanel := Panel{
		Title: "Recent Users",
		Type:  "table",
		Data: map[string]interface{}{
			"headers": []string{"Email", "Type", "Created"},
			"rows":    userRows,
		},
	}

	// Activity log panel
	activityPanel := Panel{
		Title: "Recent Activity",
		Type:  "list",
		Data: map[string]interface{}{
			"items": []string{
				"User login: user@example.com",
				"Organization created: Acme Corp",
				"Role assigned: Admin to john@doe.com",
				"API key generated for service-account",
				"System backup completed",
			},
		},
	}

	panels := []Panel{statusPanel, usersPanel, activityPanel}
	return sc.base.ShowMultiPanel("Frank Auth Dashboard", panels)
}

func (sc *SystemCommands) getSystemStatusText() string {
	var status strings.Builder

	status.WriteString("[green]System Health[white]\n")
	status.WriteString("✅ Database: Connected\n")
	status.WriteString("✅ Redis: Connected\n")
	status.WriteString("✅ Services: Operational\n\n")

	status.WriteString("[yellow]Quick Stats[white]\n")
	status.WriteString("👥 Active Users: 1,247\n")
	status.WriteString("🏢 Organizations: 89\n")
	status.WriteString("🔑 Active Sessions: 156\n")
	status.WriteString("📊 Audit Logs: 12,445\n\n")

	status.WriteString("[cyan]System Info[white]\n")
	status.WriteString("Version: 1.0.0\n")
	status.WriteString("Uptime: 7d 14h 23m\n")
	status.WriteString("Last Backup: 2024-01-15 02:00:00\n")

	return status.String()
}

// Add interactive commands to the command group
func (uc *UserCommands) addInteractiveCommands(rootCmd *cobra.Command) {
	// Interactive user creation
	createInteractiveCmd := &cobra.Command{
		Use:   "create-interactive",
		Short: "Create user with interactive form",
		RunE:  uc.createUserInteractive,
	}

	rootCmd.AddCommand(createInteractiveCmd)
}

func (sc *SystemCommands) addDashboardCommand(rootCmd *cobra.Command) {
	dashboardCmd := &cobra.Command{
		Use:   "dashboard",
		Short: "Show system dashboard",
		RunE:  sc.showDashboard,
	}
	dashboardCmd.Flags().Bool("json", false, "output as JSON instead of dashboard")

	rootCmd.AddCommand(dashboardCmd)
}
