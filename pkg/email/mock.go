package email

import (
	"context"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"time"
)

// MockEmailSender implements the Sender interface but logs emails to files or console
type MockEmailSender struct {
	OutputDir string // Directory to save emails as files, if empty logs to console
}

// Send logs emails instead of sending them
func (m *MockEmailSender) Send(ctx context.Context, email Email) error {
	// Format email content for logging
	content := fmt.Sprintf("===== EMAIL =====\n"+
		"Time: %s\n"+
		"From: %s\n"+
		"To: %v\n"+
		"CC: %v\n"+
		"BCC: %v\n"+
		"Subject: %s\n"+
		"HTML Content: %s\n"+
		"Text Content: %s\n"+
		"================\n",
		time.Now().Format(time.RFC3339),
		email.From,
		email.To,
		email.CC,
		email.BCC,
		email.Subject,
		email.HTMLContent,
		email.TextContent)

	// Log to file if OutputDir is set
	if m.OutputDir != "" {
		timestamp := time.Now().Format("20060102_150405")
		filename := filepath.Join(m.OutputDir, fmt.Sprintf("email_%s.txt", timestamp))

		// Create directory if it doesn't exist
		if err := os.MkdirAll(m.OutputDir, 0755); err != nil {
			return err
		}

		// Write to file
		return os.WriteFile(filename, []byte(content), 0644)
	}

	// Otherwise log to console
	log.Println(content)
	return nil
}

// NewMockEmailSender creates a new mock email sender
func NewMockEmailSender(outputDir string) *MockEmailSender {
	return &MockEmailSender{
		OutputDir: outputDir,
	}
}
