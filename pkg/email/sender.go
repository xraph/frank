package email

import (
	"context"
)

// Email represents an email to be sent
type Email struct {
	To          []string
	From        string
	Subject     string
	HTMLContent string
	TextContent string
	CC          []string
	BCC         []string
	ReplyTo     string
	Attachments []Attachment
	Headers     map[string]string
}

// Sender interface for sending emails
type Sender interface {
	// Send sends an email
	Send(ctx context.Context, email Email) error
}
