package email

import (
	"context"
	"time"
)

// Email represents an email to be sent
type Email struct {
	MessageID   string                 `json:"message_id,omitempty"`
	From        string                 `json:"from"`
	FromName    string                 `json:"from_name,omitempty"`
	To          []string               `json:"to"`
	CC          []string               `json:"cc,omitempty"`
	BCC         []string               `json:"bcc,omitempty"`
	ReplyTo     string                 `json:"reply_to,omitempty"`
	Subject     string                 `json:"subject"`
	HTMLContent string                 `json:"html_content,omitempty"`
	TextContent string                 `json:"text_content,omitempty"`
	Attachments []Attachment           `json:"attachments,omitempty"`
	Headers     map[string]string      `json:"headers,omitempty"`
	Tags        []string               `json:"tags,omitempty"`
	Metadata    map[string]interface{} `json:"metadata,omitempty"`
	ScheduledAt *time.Time             `json:"scheduled_at,omitempty"`
	TrackOpens  bool                   `json:"track_opens"`
	TrackClicks bool                   `json:"track_clicks"`
	Priority    string                 `json:"priority,omitempty"` // high, normal, low
	Provider    string                 `json:"provider,omitempty"` // smtp, sendgrid, ses, etc.
}

type DeliveryInfo struct {
	MessageID    string                 `json:"message_id"`
	Status       string                 `json:"status"`
	SentAt       time.Time              `json:"sent_at"`
	DeliveredAt  *time.Time             `json:"delivered_at,omitempty"`
	OpenedAt     *time.Time             `json:"opened_at,omitempty"`
	ClickedAt    *time.Time             `json:"clicked_at,omitempty"`
	BouncedAt    *time.Time             `json:"bounced_at,omitempty"`
	BounceReason string                 `json:"bounce_reason,omitempty"`
	Opens        int                    `json:"opens"`
	Clicks       int                    `json:"clicks"`
	Provider     string                 `json:"provider"`
	Metadata     map[string]interface{} `json:"metadata,omitempty"`
}
type BulkEmailResult struct {
	Successful   []string      `json:"successful"`
	Failed       []FailedEmail `json:"failed"`
	SuccessCount int           `json:"success_count"`
	FailureCount int           `json:"failure_count"`
	ProcessedAt  time.Time     `json:"processed_at"`
}

type FailedEmail struct {
	Email  string `json:"email"`
	Reason string `json:"reason"`
	Error  string `json:"error"`
}

// Sender interface for sending emails
type Sender interface {
	// Send sends an email
	Send(ctx context.Context, email Email) error
	SendBulkEmails(ctx context.Context, emails []Email) (*BulkEmailResult, error)
	TestConnection(ctx context.Context) error
	GetDeliveryStatus(ctx context.Context, messageID string) (*DeliveryInfo, error)
	Name() string
}
