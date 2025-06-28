package notification

import (
	"context"
	"time"

	"github.com/xraph/frank/ent"
	"go.uber.org/zap"
)

// // UpdatedSMSService methods to use system templates
// func (s *smsService) SendVerificationSMS(ctx context.Context, user *ent.User, code string) error {
// 	data := map[string]interface{}{
// 		"appName":   s.getConfig().App.Name,
// 		"userName":  getUserDisplayName(user),
// 		"code":      code,
// 		"expiresIn": "10 minutes",
// 	}
//
// 	return s.SendSystemSMS(ctx, "sms_verification", user.PhoneNumber, data)
// }
//
// func (s *smsService) SendWelcomeSMS(ctx context.Context, user *ent.User, organizationName string) error {
// 	data := map[string]interface{}{
// 		"appName":          s.getConfig().App.Name,
// 		"userName":         getUserDisplayName(user),
// 		"organizationName": organizationName,
// 		"loginUrl":         "https://app.frank.com/login",
// 	}
//
// 	return s.SendSystemSMS(ctx, "welcome_sms", user.PhoneNumber, data)
// }
//
// func (s *smsService) SendPasswordResetSMS(ctx context.Context, user *ent.User, code string) error {
// 	data := map[string]interface{}{
// 		"appName":   s.getConfig().App.Name,
// 		"userName":  getUserDisplayName(user),
// 		"code":      code,
// 		"expiresIn": "15 minutes",
// 	}
//
// 	return s.SendSystemSMS(ctx, "password_reset_sms", user.PhoneNumber, data)
// }
//
// func (s *smsService) SendMagicLinkSMS(ctx context.Context, user *ent.User, magicLinkUrl string) error {
// 	data := map[string]interface{}{
// 		"appName":      s.getConfig().App.Name,
// 		"userName":     getUserDisplayName(user),
// 		"magicLinkUrl": magicLinkUrl,
// 		"expiresIn":    "15 minutes",
// 	}
//
// 	return s.SendSystemSMS(ctx, "magic_link_sms", user.PhoneNumber, data)
// }
//
// func (s *smsService) SendMFACodeSMS(ctx context.Context, user *ent.User, code string) error {
// 	data := map[string]interface{}{
// 		"appName":   s.getConfig().App.Name,
// 		"userName":  getUserDisplayName(user),
// 		"code":      code,
// 		"expiresIn": "5 minutes",
// 	}
//
// 	return s.SendSystemSMS(ctx, "mfa_code_sms", user.PhoneNumber, data)
// }

func (s *smsService) SendLoginSuccessSMS(ctx context.Context, user *ent.User, login LoginNotification) error {
	templateType := "login_success_sms"
	if login.Suspicious {
		templateType = "suspicious_login_sms"
	}

	data := map[string]interface{}{
		"appName":     s.getConfig().App.Name,
		"userName":    getUserDisplayName(user),
		"location":    login.Location,
		"timestamp":   login.Timestamp.Format("Jan 2, 15:04"),
		"ipAddress":   login.IPAddress,
		"securityUrl": s.getConfig().GetFrontendAddressWithPath(s.getConfig().Frontend.SecurityPath),
	}

	return s.SendSystemSMS(ctx, templateType, user.PhoneNumber, data)
}

// func (s *smsService) SendPasswordChangedSMS(ctx context.Context, user *ent.User) error {
// 	data := map[string]interface{}{
// 		"appName":   s.getConfig().App.Name,
// 		"userName":  getUserDisplayName(user),
// 		"timestamp": time.Now().Format("Jan 2, 15:04"),
// 	}
//
// 	return s.SendSystemSMS(ctx, "password_changed_sms", user.PhoneNumber, data)
// }
//
// func (s *smsService) SendAccountLockedSMS(ctx context.Context, user *ent.User, reason string) error {
// 	data := map[string]interface{}{
// 		"appName":     s.getConfig().App.Name,
// 		"userName":    getUserDisplayName(user),
// 		"reason":      reason,
// 		"supportUrl":  "https://support.frank.com",
// 		"referenceId": xid.New().String()[:8], // Short reference ID
// 	}
//
// 	return s.SendSystemSMS(ctx, "account_locked_sms", user.PhoneNumber, data)
// }

func (s *smsService) SendOrganizationInvitationSMS(ctx context.Context, invitation SMSInvitation) error {
	data := map[string]interface{}{
		"appName":          s.getConfig().App.Name,
		"inviterName":      invitation.InviterName,
		"organizationName": invitation.OrganizationName,
		"role":             invitation.Role,
		"invitationUrl":    invitation.JoinURL,
		"expiresAt":        invitation.ExpiresAt.Format("Jan 2"),
	}

	return s.SendSystemSMS(ctx, "organization_invitation_sms", invitation.PhoneNumber, data)
}

func (s *smsService) SendUserJoinedNotificationSMS(ctx context.Context, adminPhoneNumbers []string, notification UserJoinedNotification) error {
	data := map[string]interface{}{
		"appName":          s.getConfig().App.Name,
		"newMemberName":    notification.NewMemberName,
		"organizationName": notification.OrganizationName,
		"role":             notification.Role,
		"joinedAt":         notification.JoinedAt.Format("Jan 2"),
		"teamUrl":          notification.TeamURL,
	}

	for _, phoneNumber := range adminPhoneNumbers {
		err := s.SendSystemSMS(ctx, "user_joined_organization_sms", phoneNumber, data)
		if err != nil {
			s.logger.Error("failed to send user joined SMS notification",
				zap.String("phoneNumber", phoneNumber),
				zap.Error(err),
			)
		}
	}

	return nil
}

// func (s *smsService) SendInvitationReminderSMS(ctx context.Context, invitation SMSInvitation) error {
// 	timeLeft := time.Until(invitation.ExpiresAt)
// 	var timeLeftStr string
// 	if timeLeft.Hours() < 24 {
// 		timeLeftStr = fmt.Sprintf("%.0f hours", timeLeft.Hours())
// 	} else {
// 		timeLeftStr = fmt.Sprintf("%.0f days", timeLeft.Hours()/24)
// 	}
//
// 	data := map[string]interface{}{
// 		"appName":          s.getConfig().App.Name,
// 		"inviterName":      invitation.InviterName,
// 		"organizationName": invitation.OrganizationName,
// 		"timeLeft":         timeLeftStr,
// 		"invitationUrl":    invitation.JoinURL,
// 	}
//
// 	return s.SendSystemSMS(ctx, "invitation_reminder_sms", invitation.PhoneNumber, data)
// }

func (s *smsService) SendAPIKeyGeneratedSMS(ctx context.Context, user *ent.User, keyName string) error {
	data := map[string]interface{}{
		"appName": s.getConfig().App.Name,
		"keyName": keyName,
	}

	return s.SendSystemSMS(ctx, "api_key_generated_sms", user.PhoneNumber, data)
}

func (s *smsService) SendSessionTerminatedSMS(ctx context.Context, user *ent.User) error {
	data := map[string]interface{}{
		"appName":  s.getConfig().App.Name,
		"loginUrl": s.getConfig().GetFrontendAddressWithPath(s.getConfig().Frontend.LoginPath),
	}

	return s.SendSystemSMS(ctx, "session_terminated_sms", user.PhoneNumber, data)
}

func (s *smsService) SendBackupCodesGeneratedSMS(ctx context.Context, user *ent.User, codeCount int) error {
	data := map[string]interface{}{
		"appName":   s.getConfig().App.Name,
		"codeCount": codeCount,
		"timestamp": time.Now().Format("Jan 2, 15:04"),
	}

	return s.SendSystemSMS(ctx, "backup_codes_generated_sms", user.PhoneNumber, data)
}

func (s *smsService) SendRoleChangedSMS(ctx context.Context, user *ent.User, roleChange RoleChangeNotification) error {
	data := map[string]interface{}{
		"appName":          s.getConfig().App.Name,
		"organizationName": roleChange.OrganizationName,
		"oldRole":          roleChange.OldRole,
		"newRole":          roleChange.NewRole,
		"changedBy":        roleChange.ChangedBy,
		"timestamp":        roleChange.ChangedAt.Format("Jan 2"),
	}

	return s.SendSystemSMS(ctx, "role_changed_sms", user.PhoneNumber, data)
}

func (s *smsService) SendDeviceAddedSMS(ctx context.Context, user *ent.User, device DeviceInfo) error {
	data := map[string]interface{}{
		"appName":    s.getConfig().App.Name,
		"deviceName": device.DeviceName,
		"deviceType": device.DeviceType,
	}

	return s.SendSystemSMS(ctx, "device_added_sms", user.PhoneNumber, data)
}

// func (s *smsService) SendPaymentFailedSMS(ctx context.Context, phoneNumbers []string, payment PaymentFailedNotification) error {
// 	data := map[string]interface{}{
// 		"appName":          s.getConfig().App.Name,
// 		"organizationName": payment.OrganizationName,
// 		"amount":           payment.Amount,
// 		"currency":         payment.Currency,
// 		"billingUrl":       payment.BillingURL,
// 	}
//
// 	for _, phoneNumber := range phoneNumbers {
// 		err := s.SendSystemSMS(ctx, "payment_failed_sms", phoneNumber, data)
// 		if err != nil {
// 			s.logger.Error("failed to send payment failed SMS",
// 				zap.String("phoneNumber", phoneNumber),
// 				zap.Error(err),
// 			)
// 		}
// 	}
//
// 	return nil
// }
//
// func (s *smsService) SendUsageAlertSMS(ctx context.Context, phoneNumbers []string, usage UsageAlertNotification) error {
// 	data := map[string]interface{}{
// 		"appName":          s.getConfig().App.Name,
// 		"organizationName": usage.OrganizationName,
// 		"resourceType":     usage.ResourceType,
// 		"percentage":       int(usage.PercentageUsed),
// 		"upgradeUrl":       usage.UpgradeURL,
// 	}
//
// 	for _, phoneNumber := range phoneNumbers {
// 		err := s.SendSystemSMS(ctx, "usage_alert_sms", phoneNumber, data)
// 		if err != nil {
// 			s.logger.Error("failed to send usage alert SMS",
// 				zap.String("phoneNumber", phoneNumber),
// 				zap.Error(err),
// 			)
// 		}
// 	}
//
// 	return nil
// }
//
// // Enhanced SendSystemSMS to handle template rendering with character limit validation
// func (s *smsService) SendSystemSMS(ctx context.Context, templateType, phoneNumber string, data map[string]interface{}) error {
// 	// Get system template
// 	template, err := s.templateRepo.GetSystemTemplate(ctx, templateType, "en")
// 	if err != nil {
// 		return fmt.Errorf("failed to get system template %s: %w", templateType, err)
// 	}
//
// 	if !template.Active {
// 		return fmt.Errorf("template %s is not active", templateType)
// 	}
//
// 	// Render template with data
// 	rendered, err := s.RenderSMSTemplate(ctx, template.ID.String(), data)
// 	if err != nil {
// 		return fmt.Errorf("failed to render SMS template: %w", err)
// 	}
//
// 	// Validate message length
// 	if len(rendered.Content) > template.MaxLength && template.MaxLength > 0 {
// 		s.logger.Warn("SMS message exceeds template max length",
// 			zap.String("template", templateType),
// 			zap.Int("length", len(rendered.Content)),
// 			zap.Int("maxLength", template.MaxLength),
// 		)
// 	}
//
// 	// Send SMS
// 	smsRequest := sms.SMS{
// 		To:             phoneNumber,
// 		Message:        rendered.Content,
// 		MessageType:    template.MessageType,
// 		OrganizationID: template.OrganizationID,
// 	}
//
// 	return s.SendSMS(ctx, smsRequest)
// }

// Additional notification structures
type UserJoinedNotification struct {
	NewMemberName    string    `json:"newMemberName"`
	OrganizationName string    `json:"organizationName"`
	Role             string    `json:"role"`
	JoinedAt         time.Time `json:"joinedAt"`
	TeamURL          string    `json:"teamUrl"`
}

type RoleChangeNotification struct {
	OrganizationName string    `json:"organizationName"`
	OldRole          string    `json:"oldRole"`
	NewRole          string    `json:"newRole"`
	ChangedBy        string    `json:"changedBy"`
	ChangedAt        time.Time `json:"changedAt"`
}

type PaymentFailedNotification struct {
	OrganizationName string  `json:"organizationName"`
	Amount           float64 `json:"amount"`
	Currency         string  `json:"currency"`
	BillingURL       string  `json:"billingUrl"`
}

type UsageAlertNotification struct {
	OrganizationName string  `json:"organizationName"`
	ResourceType     string  `json:"resourceType"`
	PercentageUsed   float64 `json:"percentageUsed"`
	UpgradeURL       string  `json:"upgradeUrl"`
}

type DeviceInfo struct {
	DeviceName string `json:"deviceName"`
	DeviceType string `json:"deviceType"`
}
