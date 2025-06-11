package email

import (
	"github.com/rs/xid"
)

// SendEmailInput represents input for sending an email
type SendEmailInput struct {
	To          []string               `json:"to" validate:"required,dive,email"`
	From        string                 `json:"from,omitempty"`
	Subject     string                 `json:"subject" validate:"required"`
	HTMLContent string                 `json:"html_content,omitempty"`
	TextContent string                 `json:"text_content,omitempty"`
	CC          []string               `json:"cc,omitempty"`
	BCC         []string               `json:"bcc,omitempty"`
	ReplyTo     string                 `json:"reply_to,omitempty"`
	Attachments []Attachment           `json:"attachments,omitempty"`
	Headers     map[string]string      `json:"headers,omitempty"`
	Metadata    map[string]interface{} `json:"metadata,omitempty"`
}

// SendTemplateInput represents input for sending an email using a template
type SendTemplateInput struct {
	To             []string               `json:"to" validate:"required,dive,email"`
	From           string                 `json:"from,omitempty"`
	Subject        *string                `json:"subject,omitempty"`
	TemplateType   string                 `json:"template_type" validate:"required"`
	TemplateData   map[string]interface{} `json:"template_data" validate:"required"`
	OrganizationID xid.ID                 `json:"organization_id,omitempty"`
	Locale         string                 `json:"locale,omitempty"`
	CC             []string               `json:"cc,omitempty"`
	BCC            []string               `json:"bcc,omitempty"`
	ReplyTo        string                 `json:"reply_to,omitempty"`
	Attachments    []Attachment           `json:"attachments,omitempty"`
	Headers        map[string]string      `json:"headers,omitempty"`
	Metadata       map[string]interface{} `json:"metadata,omitempty"`
}

// CreateTemplateInput represents input for creating an email template
type CreateTemplateInput struct {
	Name           string                 `json:"name" validate:"required"`
	Subject        string                 `json:"subject" validate:"required"`
	Type           string                 `json:"type" validate:"required"`
	HTMLContent    string                 `json:"html_content" validate:"required"`
	TextContent    string                 `json:"text_content,omitempty"`
	OrganizationID *xid.ID                `json:"organization_id,omitempty"`
	Active         bool                   `json:"active"`
	System         bool                   `json:"system,omitempty"`
	Locale         string                 `json:"locale,omitempty"`
	Metadata       map[string]interface{} `json:"metadata,omitempty"`
}

// UpdateTemplateInput represents input for updating an email template
type UpdateTemplateInput struct {
	Name        *string                `json:"name,omitempty"`
	Subject     *string                `json:"subject,omitempty"`
	HTMLContent *string                `json:"html_content,omitempty"`
	TextContent *string                `json:"text_content,omitempty"`
	Active      *bool                  `json:"active,omitempty"`
	Locale      *string                `json:"locale,omitempty"`
	Metadata    map[string]interface{} `json:"metadata,omitempty"`
}

// Attachment represents an email attachment
type Attachment struct {
	Content []byte `json:"content"`

	// Filename is the name of the attachment
	Filename string `json:"filename"`

	// ContentType is the MIME type of the attachment
	ContentType string `json:"content_type"`

	// Base64Content is the base64-encoded content of the attachment
	Base64Content string

	// Size is the size of the attachment in bytes (optional)
	Size int64

	Disposition string `json:"disposition,omitempty"` // attachment, inline
	ContentID   string `json:"content_id,omitempty"`
}

// NewAttachment creates a new email attachment
func NewAttachment(filename string, contentType string, base64Content string) Attachment {
	return Attachment{
		Filename:      filename,
		ContentType:   contentType,
		Base64Content: base64Content,
		Size:          int64(len(base64Content)),
	}
}
