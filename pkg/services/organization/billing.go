package organization

import (
	"context"
	"fmt"
	"time"

	"github.com/rs/xid"
	"github
	"github.com/xraph/frank/ent"
	"github.com/xraph/frank/ent/organization"
	"github.com/xraph/frank/internal/repository"
	"github.com/xraph/frank/pkg/errors"
	"github.com/xraph/frank/pkg/logging"
	"github.com/rs/xid"
)

// BillingService defines the interface for billing business logic
type BillingService interface {
	// Subscription management
	CreateSubscription(ctx context.Context, input CreateSubscriptionInput) (*model.OrganizationBilling, error)
	UpdateSubscription(ctx context.Context, organizationID xid.ID, input UpdateSubscriptionInput) (*model.OrganizationBilling, error)
	CancelSubscription(ctx context.Context, organizationID xid.ID, reason string) error
	ReactivateSubscription(ctx context.Context, organizationID xid.ID) (*model.OrganizationBilling, error)

	// Plan management
	ChangePlan(ctx context.Context, organizationID xid.ID, input ChangePlanInput) (*model.OrganizationBilling, error)
	GetAvailablePlans(ctx context.Context) ([]*model.BillingPlan, error)
	GetPlanDetails(ctx context.Context, planID string) (*model.BillingPlan, error)
	ValidatePlanChange(ctx context.Context, organizationID xid.ID, newPlan string) error

	// Trial management
	StartTrial(ctx context.Context, organizationID xid.ID, planID string, duration time.Duration) (*model.OrganizationBilling, error)
	ExtendTrial(ctx context.Context, organizationID xid.ID, extension time.Duration) (*model.OrganizationBilling, error)
	ConvertTrial(ctx context.Context, organizationID xid.ID, paymentMethodID string) (*model.OrganizationBilling, error)

	// Usage tracking
	TrackUsage(ctx context.Context, organizationID xid.ID, usage model.UsageData) error
	GetUsage(ctx context.Context, organizationID xid.ID, period string) (*model.OrganizationUsage, error)
	GetUsageAlerts(ctx context.Context, organizationID xid.ID) ([]*model.UsageAlert, error)
	CheckUsageLimits(ctx context.Context, organizationID xid.ID, resourceType string) (*model.UsageLimitCheck, error)

	// Payment methods
	AddPaymentMethod(ctx context.Context, organizationID xid.ID, input AddPaymentMethodInput) (*model.PaymentMethod, error)
	UpdatePaymentMethod(ctx context.Context, organizationID xid.ID, paymentMethodID string, input UpdatePaymentMethodInput) (*model.PaymentMethod, error)
	RemovePaymentMethod(ctx context.Context, organizationID xid.ID, paymentMethodID string) error
	SetDefaultPaymentMethod(ctx context.Context, organizationID xid.ID, paymentMethodID string) error
	ListPaymentMethods(ctx context.Context, organizationID xid.ID) ([]*model.PaymentMethod, error)

	// Billing contacts
	AddBillingContact(ctx context.Context, organizationID, userID xid.ID) error
	RemoveBillingContact(ctx context.Context, organizationID, userID xid.ID) error
	ListBillingContacts(ctx context.Context, organizationID xid.ID) ([]*model.BillingContact, error)
	UpdateBillingAddress(ctx context.Context, organizationID xid.ID, address model.Address) error

	// Invoices and billing
	GetBillingInfo(ctx context.Context, organizationID xid.ID) (*model.OrganizationBilling, error)
	GetInvoices(ctx context.Context, organizationID xid.ID, params model.ListInvoicesParams) (*model.InvoiceListResponse, error)
	GetInvoice(ctx context.Context, organizationID xid.ID, invoiceID string) (*model.Invoice, error)
	DownloadInvoice(ctx context.Context, organizationID xid.ID, invoiceID string) ([]byte, error)

	// Billing analytics
	GetBillingStats(ctx context.Context, organizationID xid.ID) (*model.BillingStats, error)
	GetRevenueMetrics(ctx context.Context, organizationID xid.ID, period string) (*model.RevenueMetrics, error)
	GetBillingHistory(ctx context.Context, organizationID xid.ID, params model.ListBillingHistoryParams) (*model.BillingHistoryResponse, error)

	// Webhooks and notifications
	HandleWebhook(ctx context.Context, webhookData []byte, signature string) error
	SendBillingNotification(ctx context.Context, organizationID xid.ID, notificationType string, data map[string]interface{}) error

	// Administrative operations
	ProcessBilling(ctx context.Context, organizationID xid.ID) error
	ReconcileBilling(ctx context.Context, organizationID xid.ID) error
	RefundPayment(ctx context.Context, organizationID xid.ID, paymentID string, amount int, reason string) (*model.Refund, error)
}

// CreateSubscriptionInput represents input for creating a subscription
type CreateSubscriptionInput struct {
	OrganizationID  xid.ID         `json:"organizationId"`
	PlanID          string         `json:"planId"`
	PaymentMethodID string         `json:"paymentMethodId"`
	TrialDays       int            `json:"trialDays,omitempty"`
	CouponCode      string         `json:"couponCode,omitempty"`
	BillingAddress  *model.Address `json:"billingAddress,omitempty"`
	BillingEmail    string         `json:"billingEmail,omitempty"`
	TaxID           string         `json:"taxId,omitempty"`
}

// UpdateSubscriptionInput represents input for updating a subscription
type UpdateSubscriptionInput struct {
	PaymentMethodID *string        `json:"paymentMethodId,omitempty"`
	BillingAddress  *model.Address `json:"billingAddress,omitempty"`
	BillingEmail    *string        `json:"billingEmail,omitempty"`
	TaxID           *string        `json:"taxId,omitempty"`
}

// ChangePlanInput represents input for changing plans
type ChangePlanInput struct {
	NewPlanID     string     `json:"newPlanId"`
	EffectiveDate *time.Time `json:"effectiveDate,omitempty"`
	Proration     bool       `json:"proration"`
	Reason        string     `json:"reason,omitempty"`
}

// AddPaymentMethodInput represents input for adding a payment method
type AddPaymentMethodInput struct {
	Type           string         `json:"type"`  // card, bank_account, etc.
	Token          string         `json:"token"` // Payment processor token
	IsDefault      bool           `json:"isDefault"`
	BillingAddress *model.Address `json:"billingAddress,omitempty"`
}

// UpdatePaymentMethodInput represents input for updating a payment method
type UpdatePaymentMethodInput struct {
	BillingAddress *model.Address `json:"billingAddress,omitempty"`
	IsDefault      *bool          `json:"isDefault,omitempty"`
}

// PaymentProvider defines the interface for payment processing
type PaymentProvider interface {
	CreateCustomer(ctx context.Context, input CreateCustomerInput) (*CustomerResult, error)
	CreateSubscription(ctx context.Context, input CreateSubscriptionProviderInput) (*SubscriptionResult, error)
	UpdateSubscription(ctx context.Context, subscriptionID string, input UpdateSubscriptionProviderInput) (*SubscriptionResult, error)
	CancelSubscription(ctx context.Context, subscriptionID string) error
	AddPaymentMethod(ctx context.Context, customerID string, input AddPaymentMethodProviderInput) (*PaymentMethodResult, error)
	GetInvoices(ctx context.Context, customerID string) ([]*InvoiceResult, error)
	ProcessRefund(ctx context.Context, paymentID string, amount int) (*RefundResult, error)
}

// billingService implements BillingService
type billingService struct {
	organizationRepo repository.OrganizationRepository
	membershipRepo   repository.MembershipRepository
	auditRepo        repository.AuditRepository
	paymentProvider  PaymentProvider
	logger           logging.Logger
	planConfig       map[string]*model.BillingPlan
}

// NewBillingService creates a new billing service
func NewBillingService(
	repo repository.Repository,
	paymentProvider PaymentProvider,
	logger logging.Logger,
) BillingService {
	return &billingService{
		organizationRepo: repo.Organization(),
		membershipRepo:   repo.Membership(),
		auditRepo:        repo.Audit(),
		paymentProvider:  paymentProvider,
		logger:           logger,
		planConfig:       initializePlanConfig(),
	}
}

// CreateSubscription creates a new subscription for an organization
func (s *billingService) CreateSubscription(ctx context.Context, input CreateSubscriptionInput) (*model.OrganizationBilling, error) {
	// Validate organization exists
	org, err := s.organizationRepo.GetByID(ctx, input.OrganizationID)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeNotFound, "Organization not found")
	}

	// Validate plan exists
	plan, exists := s.planConfig[input.PlanID]
	if !exists {
		return nil, errors.New(errors.CodeBadRequest, "Invalid plan ID")
	}

	// Check if organization already has a subscription
	if org.SubscriptionID != "" {
		return nil, errors.New(errors.CodeConflict, "Organization already has an active subscription")
	}

	// Create customer in payment provider if not exists
	var customerID string
	if org.CustomerID == "" {
		customerInput := CreateCustomerInput{
			OrganizationID: input.OrganizationID,
			Name:           org.Name,
			Email:          input.BillingEmail,
			Address:        input.BillingAddress,
			TaxID:          input.TaxID,
		}

		customerResult, err := s.paymentProvider.CreateCustomer(ctx, customerInput)
		if err != nil {
			return nil, errors.Wrap(err, errors.CodeInternalServer, "Failed to create customer")
		}
		customerID = customerResult.CustomerID

		// Update organization with customer ID
		_, err = s.organizationRepo.Update(ctx, input.OrganizationID, repository.UpdateOrganizationInput{
			CustomerID: &customerID,
		})
		if err != nil {
			return nil, errors.Wrap(err, errors.CodeInternalServer, "Failed to update organization with customer ID")
		}
	} else {
		customerID = org.CustomerID
	}

	// Create subscription in payment provider
	subscriptionInput := CreateSubscriptionProviderInput{
		CustomerID:      customerID,
		PlanID:          input.PlanID,
		PaymentMethodID: input.PaymentMethodID,
		TrialDays:       input.TrialDays,
		CouponCode:      input.CouponCode,
	}

	subscriptionResult, err := s.paymentProvider.CreateSubscription(ctx, subscriptionInput)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeInternalServer, "Failed to create subscription")
	}

	// Update organization with subscription details
	now := time.Now()
	trialEnd := now.Add(time.Duration(input.TrialDays) * 24 * time.Hour)

	updateInput := repository.UpdateOrganizationInput{
		Plan:               &input.PlanID,
		SubscriptionID:     &subscriptionResult.SubscriptionID,
		SubscriptionStatus: &subscriptionResult.Status,
		ExternalUserLimit:  &plan.ExternalUserLimit,
		EndUserLimit:       &plan.EndUserLimit,
		APIRequestLimit:    &plan.APIRequestLimit,
	}

	if input.TrialDays > 0 {
		updateInput.TrialEndsAt = &trialEnd
	}

	_, err = s.organizationRepo.Update(ctx, input.OrganizationID, updateInput)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeInternalServer, "Failed to update organization with subscription")
	}

	// Create audit log
	_, err = s.auditRepo.Create(ctx, repository.CreateAuditInput{
		OrganizationID: &input.OrganizationID,
		Action:         "billing.subscription_created",
		ResourceType:   "subscription",
		Status:         "success",
		Details: map[string]interface{}{
			"organization_id":   input.OrganizationID,
			"plan_id":           input.PlanID,
			"subscription_id":   subscriptionResult.SubscriptionID,
			"customer_id":       customerID,
			"trial_days":        input.TrialDays,
			"organization_name": org.Name,
		},
		Metadata: map[string]interface{}{
			"organization_id":   input.OrganizationID,
			"plan_id":           input.PlanID,
			"subscription_id":   subscriptionResult.SubscriptionID,
			"customer_id":       customerID,
			"trial_days":        input.TrialDays,
			"organization_name": org.Name,
		},
	})
	if err != nil {
		s.logger.Error("Failed to create audit log for subscription creation", logging.Error(err))
	}

	return s.buildBillingInfo(org, plan, subscriptionResult), nil
}

// UpdateSubscription updates an existing subscription
func (s *billingService) UpdateSubscription(ctx context.Context, organizationID xid.ID, input UpdateSubscriptionInput) (*model.OrganizationBilling, error) {
	org, err := s.organizationRepo.GetByID(ctx, organizationID)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeNotFound, "Organization not found")
	}

	if org.SubscriptionID == "" {
		return nil, errors.New(errors.CodeBadRequest, "Organization does not have an active subscription")
	}

	// Update subscription in payment provider
	providerInput := UpdateSubscriptionProviderInput{}
	if input.PaymentMethodID != nil {
		providerInput.PaymentMethodID = *input.PaymentMethodID
	}

	subscriptionResult, err := s.paymentProvider.UpdateSubscription(ctx, org.SubscriptionID, providerInput)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeInternalServer, "Failed to update subscription")
	}

	// Update organization record
	updateInput := repository.UpdateOrganizationInput{}
	if subscriptionResult != nil {
		updateInput.SubscriptionStatus = &subscriptionResult.Status
	}

	_, err = s.organizationRepo.Update(ctx, organizationID, updateInput)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeInternalServer, "Failed to update organization")
	}

	// Get plan details
	plan := s.planConfig[org.Plan]

	// Create audit log
	_, err = s.auditRepo.Create(ctx, repository.CreateAuditInput{
		OrganizationID: &organizationID,
		Action:         "billing.subscription_updated",
		ResourceType:   "subscription",
		Status:         "success",
		Details: map[string]interface{}{
			"organization_id": organizationID,
			"subscription_id": org.SubscriptionID,
		},
	})
	if err != nil {
		s.logger.Error("Failed to create audit log for subscription update", logging.Error(err))
	}

	return s.buildBillingInfo(org, plan, subscriptionResult), nil
}

// CancelSubscription cancels a subscription
func (s *billingService) CancelSubscription(ctx context.Context, organizationID xid.ID, reason string) error {
	org, err := s.organizationRepo.GetByID(ctx, organizationID)
	if err != nil {
		return errors.Wrap(err, errors.CodeNotFound, "Organization not found")
	}

	if org.SubscriptionID == "" {
		return errors.New(errors.CodeBadRequest, "Organization does not have an active subscription")
	}

	// Cancel subscription in payment provider
	err = s.paymentProvider.CancelSubscription(ctx, org.SubscriptionID)
	if err != nil {
		return errors.Wrap(err, errors.CodeInternalServer, "Failed to cancel subscription")
	}

	// Update organization status
	cancelledStatus := organization.SubscriptionStatusCanceled
	_, err = s.organizationRepo.Update(ctx, organizationID, repository.UpdateOrganizationInput{
		SubscriptionStatus: &cancelledStatus,
	})
	if err != nil {
		return errors.Wrap(err, errors.CodeInternalServer, "Failed to update organization status")
	}

	// Create audit log
	_, err = s.auditRepo.Create(ctx, repository.CreateAuditInput{
		OrganizationID: &organizationID,
		Action:         "billing.subscription_cancelled",
		ResourceType:   "subscription",
		Status:         "success",
		Details: map[string]interface{}{
			"organization_id":     organizationID,
			"subscription_id":     org.SubscriptionID,
			"cancellation_reason": reason,
		},
	})
	if err != nil {
		s.logger.Error("Failed to create audit log for subscription cancellation", logging.Error(err))
	}

	return nil
}

// ChangePlan changes the organization's billing plan
func (s *billingService) ChangePlan(ctx context.Context, organizationID xid.ID, input ChangePlanInput) (*model.OrganizationBilling, error) {
	org, err := s.organizationRepo.GetByID(ctx, organizationID)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeNotFound, "Organization not found")
	}

	// Validate new plan
	newPlan, exists := s.planConfig[input.NewPlanID]
	if !exists {
		return nil, errors.New(errors.CodeBadRequest, "Invalid new plan ID")
	}

	oldPlan := s.planConfig[org.Plan]

	// Validate plan change
	err = s.ValidatePlanChange(ctx, organizationID, input.NewPlanID)
	if err != nil {
		return nil, err
	}

	// Update subscription in payment provider
	providerInput := UpdateSubscriptionProviderInput{
		PlanID:    input.NewPlanID,
		Proration: input.Proration,
	}

	if input.EffectiveDate != nil {
		providerInput.EffectiveDate = *input.EffectiveDate
	}

	subscriptionResult, err := s.paymentProvider.UpdateSubscription(ctx, org.SubscriptionID, providerInput)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeInternalServer, "Failed to update subscription plan")
	}

	// Update organization with new plan limits
	updateInput := repository.UpdateOrganizationInput{
		Plan:              &input.NewPlanID,
		ExternalUserLimit: &newPlan.ExternalUserLimit,
		EndUserLimit:      &newPlan.EndUserLimit,
		APIRequestLimit:   &newPlan.APIRequestLimit,
	}

	if subscriptionResult != nil {
		updateInput.SubscriptionStatus = &subscriptionResult.Status
	}

	_, err = s.organizationRepo.Update(ctx, organizationID, updateInput)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeInternalServer, "Failed to update organization plan")
	}

	// Create audit log
	_, err = s.auditRepo.Create(ctx, repository.CreateAuditInput{
		OrganizationID: &organizationID,
		Action:         "billing.plan_changed",
		ResourceType:   "subscription",
		Status:         "success",
		Details: map[string]interface{}{
			"organization_id": organizationID,
			"old_plan_id":     org.Plan,
			"new_plan_id":     input.NewPlanID,
			"old_plan_name":   oldPlan.Name,
			"new_plan_name":   newPlan.Name,
			"change_reason":   input.Reason,
			"proration":       input.Proration,
		},
	})
	if err != nil {
		s.logger.Error("Failed to create audit log for plan change", logging.Error(err))
	}

	return s.buildBillingInfo(org, newPlan, subscriptionResult), nil
}

// GetAvailablePlans returns all available billing plans
func (s *billingService) GetAvailablePlans(ctx context.Context) ([]*model.BillingPlan, error) {
	plans := make([]*model.BillingPlan, 0, len(s.planConfig))
	for _, plan := range s.planConfig {
		plans = append(plans, plan)
	}
	return plans, nil
}

// GetPlanDetails returns details for a specific plan
func (s *billingService) GetPlanDetails(ctx context.Context, planID string) (*model.BillingPlan, error) {
	plan, exists := s.planConfig[planID]
	if !exists {
		return nil, errors.New(errors.CodeNotFound, "Plan not found")
	}
	return plan, nil
}

// ValidatePlanChange validates if a plan change is allowed
func (s *billingService) ValidatePlanChange(ctx context.Context, organizationID xid.ID, newPlan string) error {
	org, err := s.organizationRepo.GetByID(ctx, organizationID)
	if err != nil {
		return errors.Wrap(err, errors.CodeNotFound, "Organization not found")
	}

	// Get current usage
	currentCounts, err := s.organizationRepo.GetCurrentUserCounts(ctx, organizationID)
	if err != nil {
		return errors.Wrap(err, errors.CodeInternalServer, "Failed to get current usage")
	}

	// Get new plan limits
	plan, exists := s.planConfig[newPlan]
	if !exists {
		return errors.New(errors.CodeBadRequest, "Invalid new plan")
	}

	// Check if current usage exceeds new plan limits
	if currentCounts.CurrentExternalUsers > plan.ExternalUserLimit {
		return errors.New(errors.CodeBadRequest, fmt.Sprintf("Current external user count (%d) exceeds new plan limit (%d)", currentCounts.CurrentExternalUsers, plan.ExternalUserLimit))
	}

	if currentCounts.CurrentEndUsers > plan.EndUserLimit {
		return errors.New(errors.CodeBadRequest, fmt.Sprintf("Current end user count (%d) exceeds new plan limit (%d)", currentCounts.CurrentEndUsers, plan.EndUserLimit))
	}

	// Check if it's a valid transition
	currentPlan := s.planConfig[org.Plan]
	if currentPlan != nil && !s.isValidPlanTransition(currentPlan.ID, newPlan) {
		return errors.New(errors.CodeBadRequest, "Invalid plan transition")
	}

	return nil
}

// StartTrial starts a trial for an organization
func (s *billingService) StartTrial(ctx context.Context, organizationID xid.ID, planID string, duration time.Duration) (*model.OrganizationBilling, error) {
	org, err := s.organizationRepo.GetByID(ctx, organizationID)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeNotFound, "Organization not found")
	}

	if org.TrialUsed {
		return nil, errors.New(errors.CodeBadRequest, "Trial has already been used for this organization")
	}

	// Validate plan
	plan, exists := s.planConfig[planID]
	if !exists {
		return nil, errors.New(errors.CodeBadRequest, "Invalid plan ID")
	}

	// Start trial
	trialEnd := time.Now().Add(duration)
	err = s.organizationRepo.StartTrial(ctx, organizationID, &trialEnd)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeInternalServer, "Failed to start trial")
	}

	// Update plan limits
	_, err = s.organizationRepo.Update(ctx, organizationID, repository.UpdateOrganizationInput{
		Plan:              &planID,
		ExternalUserLimit: &plan.ExternalUserLimit,
		EndUserLimit:      &plan.EndUserLimit,
		APIRequestLimit:   &plan.APIRequestLimit,
	})
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeInternalServer, "Failed to update plan limits")
	}

	// Create audit log
	_, err = s.auditRepo.Create(ctx, repository.CreateAuditInput{
		OrganizationID: &organizationID,
		Action:         "billing.trial_started",
		ResourceType:   "organization",
		Status:         "success",
		Details: map[string]interface{}{
			"organization_id": organizationID,
			"plan_id":         planID,
			"trial_duration":  duration.String(),
			"trial_end":       trialEnd,
		},
	})
	if err != nil {
		s.logger.Error("Failed to create audit log for trial start", logging.Error(err))
	}

	return &model.OrganizationBilling{
		CustomerID:     org.CustomerID,
		SubscriptionID: org.SubscriptionID,
		Plan:           planID,
		Status:         string(org.SubscriptionStatus),
		TrialStart:     &org.CreatedAt,
		TrialEnd:       &trialEnd,
		Currency:       "usd",
	}, nil
}

// TrackUsage tracks usage for an organization
func (s *billingService) TrackUsage(ctx context.Context, organizationID xid.ID, usage model.UsageData) error {
	// Update organization with new usage data
	updateInput := repository.UpdateUsageInput{}

	switch usage.Type {
	case "api_requests":
		if usage.Count > 0 {
			updateInput.APIRequestsUsed = &usage.Count
		}
	case "external_users":
		if usage.Delta != 0 {
			counts := repository.UpdateUserCountsInput{
				ExternalUsersDelta: usage.Delta,
			}
			err := s.organizationRepo.UpdateUserCounts(ctx, organizationID, counts)
			if err != nil {
				return errors.Wrap(err, errors.CodeInternalServer, "Failed to update user counts")
			}
		}
	case "end_users":
		if usage.Delta != 0 {
			counts := repository.UpdateUserCountsInput{
				EndUsersDelta: usage.Delta,
			}
			err := s.organizationRepo.UpdateUserCounts(ctx, organizationID, counts)
			if err != nil {
				return errors.Wrap(err, errors.CodeInternalServer, "Failed to update user counts")
			}
		}
	}

	if updateInput.APIRequestsUsed != nil {
		err := s.organizationRepo.UpdateUsage(ctx, organizationID, updateInput)
		if err != nil {
			return errors.Wrap(err, errors.CodeInternalServer, "Failed to update usage")
		}
	}

	return nil
}

// GetUsage returns usage information for an organization
func (s *billingService) GetUsage(ctx context.Context, organizationID xid.ID, period string) (*model.OrganizationUsage, error) {
	org, err := s.organizationRepo.GetByID(ctx, organizationID)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeNotFound, "Organization not found")
	}

	return &model.OrganizationUsage{
		Period:            period,
		ExternalUsers:     org.CurrentExternalUsers,
		EndUsers:          org.CurrentEndUsers,
		APIRequests:       org.APIRequestsUsed,
		Storage:           0, // Would track actual storage usage
		Bandwidth:         0, // Would track actual bandwidth usage
		LoginEvents:       0, // Would track from audit logs
		EmailsSent:        0, // Would track from email service
		SMSSent:           0, // Would track from SMS service
		WebhookDeliveries: 0, // Would track from webhook service
		LastUpdated:       time.Now(),
	}, nil
}

// CheckUsageLimits checks if usage is within limits
func (s *billingService) CheckUsageLimits(ctx context.Context, organizationID xid.ID, resourceType string) (*model.UsageLimitCheck, error) {
	org, err := s.organizationRepo.GetByID(ctx, organizationID)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeNotFound, "Organization not found")
	}

	check := &model.UsageLimitCheck{
		ResourceType: resourceType,
		WithinLimit:  true,
		Warning:      false,
	}

	switch resourceType {
	case "external_users":
		check.CurrentUsage = org.CurrentExternalUsers
		check.Limit = org.ExternalUserLimit
		check.WithinLimit = org.CurrentExternalUsers < org.ExternalUserLimit
		check.Warning = float64(org.CurrentExternalUsers)/float64(org.ExternalUserLimit) > 0.8
		check.PercentageUsed = float64(org.CurrentExternalUsers) / float64(org.ExternalUserLimit) * 100
	case "end_users":
		check.CurrentUsage = org.CurrentEndUsers
		check.Limit = org.EndUserLimit
		check.WithinLimit = org.CurrentEndUsers < org.EndUserLimit
		check.Warning = float64(org.CurrentEndUsers)/float64(org.EndUserLimit) > 0.8
		check.PercentageUsed = float64(org.CurrentEndUsers) / float64(org.EndUserLimit) * 100
	case "api_requests":
		check.CurrentUsage = org.APIRequestsUsed
		check.Limit = org.APIRequestLimit
		check.WithinLimit = org.APIRequestsUsed < org.APIRequestLimit
		check.Warning = float64(org.APIRequestsUsed)/float64(org.APIRequestLimit) > 0.8
		check.PercentageUsed = float64(org.APIRequestsUsed) / float64(org.APIRequestLimit) * 100
	default:
		return nil, errors.New(errors.CodeBadRequest, "Invalid resource type")
	}

	return check, nil
}

// GetBillingInfo returns billing information for an organization
func (s *billingService) GetBillingInfo(ctx context.Context, organizationID xid.ID) (*model.OrganizationBilling, error) {
	org, err := s.organizationRepo.GetByID(ctx, organizationID)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeNotFound, "Organization not found")
	}

	plan := s.planConfig[org.Plan]
	if plan == nil {
		return nil, errors.New(errors.CodeNotFound, "Plan not found")
	}

	return &model.OrganizationBilling{
		CustomerID:         org.CustomerID,
		SubscriptionID:     org.SubscriptionID,
		Plan:               org.Plan,
		Status:             string(org.SubscriptionStatus),
		CurrentPeriodStart: org.CreatedAt,                          // Would be actual billing period start
		CurrentPeriodEnd:   org.CreatedAt.Add(30 * 24 * time.Hour), // Would be actual billing period end
		TrialStart:         org.TrialEndsAt,
		TrialEnd:           org.TrialEndsAt,
		Amount:             s.getPlanAmount(org.Plan),
		Currency:           "usd",
	}, nil
}

// GetBillingStats returns billing statistics
func (s *billingService) GetBillingStats(ctx context.Context, organizationID xid.ID) (*model.BillingStats, error) {
	org, err := s.organizationRepo.GetByID(ctx, organizationID)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeNotFound, "Organization not found")
	}

	return &model.BillingStats{
		MonthlyRevenue:     s.getPlanAmount(org.Plan),
		TotalRevenue:       s.getPlanAmount(org.Plan) * 12, // Simplified calculation
		ActiveSubscription: org.SubscriptionStatus == organization.SubscriptionStatusActive,
		DaysUntilRenewal:   30, // Would calculate actual days
		UsagePercentage:    s.calculateUsagePercentage(org),
		PaymentStatus:      "current",
	}, nil
}

func (s *billingService) ReactivateSubscription(ctx context.Context, organizationID xid.ID) (*model.OrganizationBilling, error) {
	// TODO implement me
	panic("implement me")
}

func (s *billingService) ExtendTrial(ctx context.Context, organizationID xid.ID, extension time.Duration) (*model.OrganizationBilling, error) {
	// TODO implement me
	panic("implement me")
}

func (s *billingService) ConvertTrial(ctx context.Context, organizationID xid.ID, paymentMethodID string) (*model.OrganizationBilling, error) {
	// TODO implement me
	panic("implement me")
}

func (s *billingService) GetUsageAlerts(ctx context.Context, organizationID xid.ID) ([]*model.UsageAlert, error) {
	// TODO implement me
	panic("implement me")
}

func (s *billingService) AddPaymentMethod(ctx context.Context, organizationID xid.ID, input AddPaymentMethodInput) (*model.PaymentMethod, error) {
	// TODO implement me
	panic("implement me")
}

func (s *billingService) UpdatePaymentMethod(ctx context.Context, organizationID xid.ID, paymentMethodID string, input UpdatePaymentMethodInput) (*model.PaymentMethod, error) {
	// TODO implement me
	panic("implement me")
}

func (s *billingService) RemovePaymentMethod(ctx context.Context, organizationID xid.ID, paymentMethodID string) error {
	// TODO implement me
	panic("implement me")
}

func (s *billingService) SetDefaultPaymentMethod(ctx context.Context, organizationID xid.ID, paymentMethodID string) error {
	// TODO implement me
	panic("implement me")
}

func (s *billingService) ListPaymentMethods(ctx context.Context, organizationID xid.ID) ([]*model.PaymentMethod, error) {
	// TODO implement me
	panic("implement me")
}

func (s *billingService) AddBillingContact(ctx context.Context, organizationID, userID xid.ID) error {
	// TODO implement me
	panic("implement me")
}

func (s *billingService) RemoveBillingContact(ctx context.Context, organizationID, userID xid.ID) error {
	// TODO implement me
	panic("implement me")
}

func (s *billingService) ListBillingContacts(ctx context.Context, organizationID xid.ID) ([]*model.BillingContact, error) {
	// TODO implement me
	panic("implement me")
}

func (s *billingService) UpdateBillingAddress(ctx context.Context, organizationID xid.ID, address model.Address) error {
	// TODO implement me
	panic("implement me")
}

func (s *billingService) GetInvoices(ctx context.Context, organizationID xid.ID, params model.ListInvoicesParams) (*model.InvoiceListResponse, error) {
	// TODO implement me
	panic("implement me")
}

func (s *billingService) GetInvoice(ctx context.Context, organizationID xid.ID, invoiceID string) (*model.Invoice, error) {
	// TODO implement me
	panic("implement me")
}

func (s *billingService) DownloadInvoice(ctx context.Context, organizationID xid.ID, invoiceID string) ([]byte, error) {
	// TODO implement me
	panic("implement me")
}

func (s *billingService) GetRevenueMetrics(ctx context.Context, organizationID xid.ID, period string) (*model.RevenueMetrics, error) {
	// TODO implement me
	panic("implement me")
}

func (s *billingService) GetBillingHistory(ctx context.Context, organizationID xid.ID, params model.ListBillingHistoryParams) (*model.BillingHistoryResponse, error) {
	// TODO implement me
	panic("implement me")
}

func (s *billingService) HandleWebhook(ctx context.Context, webhookData []byte, signature string) error {
	// TODO implement me
	panic("implement me")
}

func (s *billingService) SendBillingNotification(ctx context.Context, organizationID xid.ID, notificationType string, data map[string]interface{}) error {
	// TODO implement me
	panic("implement me")
}

func (s *billingService) ProcessBilling(ctx context.Context, organizationID xid.ID) error {
	// TODO implement me
	panic("implement me")
}

func (s *billingService) ReconcileBilling(ctx context.Context, organizationID xid.ID) error {
	// TODO implement me
	panic("implement me")
}

func (s *billingService) RefundPayment(ctx context.Context, organizationID xid.ID, paymentID string, amount int, reason string) (*model.Refund, error) {
	// TODO implement me
	panic("implement me")
}

// Helper methods

// buildBillingInfo builds billing information from organization and subscription data
func (s *billingService) buildBillingInfo(org *ent.Organization, plan *model.BillingPlan, subscription *SubscriptionResult) *model.OrganizationBilling {
	billing := &model.OrganizationBilling{
		CustomerID:     org.CustomerID,
		SubscriptionID: org.SubscriptionID,
		Plan:           org.Plan,
		Status:         string(org.SubscriptionStatus),
		Currency:       "usd",
	}

	if plan != nil {
		billing.Amount = plan.Price
	}

	if subscription != nil {
		billing.Status = string(subscription.Status)
		billing.CurrentPeriodStart = subscription.CurrentPeriodStart
		billing.CurrentPeriodEnd = subscription.CurrentPeriodEnd
	}

	if org.TrialEndsAt != nil {
		billing.TrialStart = &org.CreatedAt
		billing.TrialEnd = org.TrialEndsAt
	}

	return billing
}

// isValidPlanTransition checks if a plan transition is valid
func (s *billingService) isValidPlanTransition(currentPlan, newPlan string) bool {
	// Define valid transitions
	validTransitions := map[string][]string{
		"free":       {"basic", "pro", "enterprise"},
		"basic":      {"pro", "enterprise"},
		"pro":        {"enterprise", "basic"},
		"enterprise": {"pro"},
	}

	allowed, exists := validTransitions[currentPlan]
	if !exists {
		return false
	}

	for _, allowedPlan := range allowed {
		if allowedPlan == newPlan {
			return true
		}
	}
	return false
}

// getPlanAmount returns the amount for a plan
func (s *billingService) getPlanAmount(planID string) int {
	plan, exists := s.planConfig[planID]
	if !exists {
		return 0
	}
	return plan.Price
}

// calculateUsagePercentage calculates overall usage percentage
func (s *billingService) calculateUsagePercentage(org *ent.Organization) float64 {
	externalUsage := float64(org.CurrentExternalUsers) / float64(org.ExternalUserLimit)
	endUsage := float64(org.CurrentEndUsers) / float64(org.EndUserLimit)
	apiUsage := float64(org.APIRequestsUsed) / float64(org.APIRequestLimit)

	return (externalUsage + endUsage + apiUsage) / 3 * 100
}

// initializePlanConfig initializes the plan configuration
func initializePlanConfig() map[string]*model.BillingPlan {
	return map[string]*model.BillingPlan{
		"free": {
			ID:                "free",
			Name:              "Free",
			Description:       "Perfect for getting started",
			Price:             0,
			BillingInterval:   "month",
			ExternalUserLimit: 5,
			EndUserLimit:      100,
			APIRequestLimit:   1000,
			Features: []string{
				"Basic authentication",
				"Email support",
				"Standard security",
			},
		},
		"basic": {
			ID:                "basic",
			Name:              "Basic",
			Description:       "Great for small teams",
			Price:             2900, // $29.00
			BillingInterval:   "month",
			ExternalUserLimit: 25,
			EndUserLimit:      1000,
			APIRequestLimit:   10000,
			Features: []string{
				"All Free features",
				"SSO integration",
				"Priority support",
				"Advanced security",
			},
		},
		"pro": {
			ID:                "pro",
			Name:              "Pro",
			Description:       "Best for growing businesses",
			Price:             9900, // $99.00
			BillingInterval:   "month",
			ExternalUserLimit: 100,
			EndUserLimit:      10000,
			APIRequestLimit:   100000,
			Features: []string{
				"All Basic features",
				"Advanced MFA",
				"Audit logs",
				"Custom branding",
				"API access",
			},
		},
		"enterprise": {
			ID:                "enterprise",
			Name:              "Enterprise",
			Description:       "For large organizations",
			Price:             29900, // $299.00
			BillingInterval:   "month",
			ExternalUserLimit: 1000,
			EndUserLimit:      100000,
			APIRequestLimit:   1000000,
			Features: []string{
				"All Pro features",
				"SAML SSO",
				"Advanced compliance",
				"Custom integrations",
				"Dedicated support",
			},
		},
	}
}
