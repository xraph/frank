package rbac

import (
	"context"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/juicycleff/frank/internal/repository"
	"github.com/juicycleff/frank/pkg/errors"
	"github.com/juicycleff/frank/pkg/logging"
	"github.com/rs/xid"
)

// ConditionalPermissionEngine provides Attribute-Based Access Control (ABAC) capabilities
type ConditionalPermissionEngine struct {
	logger     logging.Logger
	repo       repository.RoleRepository
	evaluators map[string]ConditionEvaluator
}

// ConditionEvaluator interface for custom condition evaluators
type ConditionEvaluator interface {
	Evaluate(condition *Condition, context *PermissionContext) (bool, error)
	SupportedOperators() []string
}

// Condition represents a single condition in a permission rule
type Condition struct {
	Field    string      `json:"field"`          // e.g., "user.department", "resource.owner_id"
	Operator string      `json:"operator"`       // e.g., "equals", "in", "matches_pattern"
	Value    interface{} `json:"value"`          // Expected value or pattern
	Type     string      `json:"type,omitempty"` // string, number, boolean, array, date
}

// ConditionRule represents a complex condition with logical operators
type ConditionRule struct {
	Operator   string           `json:"operator"` // "and", "or", "not"
	Conditions []*Condition     `json:"conditions,omitempty"`
	Rules      []*ConditionRule `json:"rules,omitempty"`
}

// PermissionContext contains all contextual information for permission evaluation
type PermissionContext struct {
	UserID       xid.ID                 `json:"user_id"`
	User         map[string]interface{} `json:"user"`         // User attributes
	Resource     map[string]interface{} `json:"resource"`     // Resource attributes
	Request      map[string]interface{} `json:"request"`      // Request context (IP, time, etc.)
	Organization map[string]interface{} `json:"organization"` // Organization attributes
	Session      map[string]interface{} `json:"session"`      // Session context
	Environment  map[string]interface{} `json:"environment"`  // Environment context
	CustomAttrs  map[string]interface{} `json:"custom_attrs"` // Custom attributes
}

// PolicyRule represents a complete ABAC policy rule
type PolicyRule struct {
	ID          xid.ID         `json:"id"`
	Name        string         `json:"name"`
	Description string         `json:"description"`
	Effect      PolicyEffect   `json:"effect"`      // "permit" or "deny"
	Priority    int            `json:"priority"`    // Higher number = higher priority
	Target      *PolicyTarget  `json:"target"`      // When this rule applies
	Condition   *ConditionRule `json:"condition"`   // Conditions to evaluate
	Obligations []string       `json:"obligations"` // Actions to take when rule matches
	Active      bool           `json:"active"`
	CreatedAt   time.Time      `json:"created_at"`
	CreatedBy   string         `json:"created_by"`
	OrgID       *xid.ID        `json:"org_id,omitempty"`
}

type PolicyEffect string

const (
	PolicyEffectPermit PolicyEffect = "permit"
	PolicyEffectDeny   PolicyEffect = "deny"
)

// PolicyTarget defines when a policy rule should be evaluated
type PolicyTarget struct {
	Resources    []string `json:"resources,omitempty"`    // Which resources this applies to
	Actions      []string `json:"actions,omitempty"`      // Which actions this applies to
	UserTypes    []string `json:"user_types,omitempty"`   // Which user types this applies to
	Environments []string `json:"environments,omitempty"` // Which environments (dev, prod, etc.)
}

// PolicyDecision represents the result of policy evaluation
type PolicyDecision struct {
	Decision    PolicyEffect       `json:"decision"` // "permit" or "deny"
	MatchedRule *PolicyRule        `json:"matched_rule,omitempty"`
	Obligations []string           `json:"obligations,omitempty"`
	Reasons     []string           `json:"reasons"` // Why this decision was made
	Context     *PermissionContext `json:"context,omitempty"`
}

// NewConditionalPermissionEngine creates a new conditional permission engine
func NewConditionalPermissionEngine(repo repository.RoleRepository, logger logging.Logger) *ConditionalPermissionEngine {
	engine := &ConditionalPermissionEngine{
		logger:     logger,
		repo:       repo,
		evaluators: make(map[string]ConditionEvaluator),
	}

	// Register default evaluators
	engine.RegisterEvaluator("string", &StringEvaluator{})
	engine.RegisterEvaluator("number", &NumberEvaluator{})
	engine.RegisterEvaluator("boolean", &BooleanEvaluator{})
	engine.RegisterEvaluator("array", &ArrayEvaluator{})
	engine.RegisterEvaluator("date", &DateEvaluator{})
	engine.RegisterEvaluator("pattern", &PatternEvaluator{})

	return engine
}

// RegisterEvaluator registers a custom condition evaluator
func (cpe *ConditionalPermissionEngine) RegisterEvaluator(conditionType string, evaluator ConditionEvaluator) {
	cpe.evaluators[conditionType] = evaluator
}

// EvaluatePermission evaluates a permission request with full ABAC context
func (cpe *ConditionalPermissionEngine) EvaluatePermission(ctx context.Context, userID xid.ID, resource, action string, context *PermissionContext) (*PolicyDecision, error) {
	// Set default context if not provided
	if context == nil {
		context = &PermissionContext{
			UserID: userID,
		}
	}

	// Enrich context with user, organization, and system data
	err := cpe.enrichContext(ctx, context)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "failed to enrich permission context")
	}

	// Get applicable policy rules
	rules, err := cpe.getApplicablePolicyRules(ctx, resource, action, context)
	if err != nil {
		return nil, err
	}

	// If no specific rules found, fall back to standard RBAC
	if len(rules) == 0 {
		hasPermission, err := cpe.repo.GetUserPermissions(ctx, userID)
		if err != nil {
			return nil, err
		}

		// Check if user has the required permission through roles
		for _, perm := range hasPermission {
			if (perm.Resource == resource && perm.Action == action) ||
				(perm.Resource == resource && perm.Action == "*") ||
				(perm.Resource == "*" && perm.Action == "*") {
				return &PolicyDecision{
					Decision: PolicyEffectPermit,
					Reasons:  []string{"granted through role-based permission"},
					Context:  context,
				}, nil
			}
		}

		return &PolicyDecision{
			Decision: PolicyEffectDeny,
			Reasons:  []string{"no applicable rules found and no role-based permission"},
			Context:  context,
		}, nil
	}

	// Evaluate rules in priority order (highest first)
	for _, rule := range rules {
		if !rule.Active {
			continue
		}

		matches, err := cpe.evaluateRule(rule, context)
		if err != nil {
			cpe.logger.Warn("Failed to evaluate policy rule",
				logging.String("rule_id", rule.ID.String()),
				logging.Error(err))
			continue
		}

		if matches {
			decision := &PolicyDecision{
				Decision:    rule.Effect,
				MatchedRule: rule,
				Obligations: rule.Obligations,
				Reasons:     []string{fmt.Sprintf("matched rule: %s", rule.Name)},
				Context:     context,
			}

			// Log the decision
			cpe.logger.Info("Policy decision made",
				logging.String("user_id", userID.String()),
				logging.String("resource", resource),
				logging.String("action", action),
				logging.String("decision", string(rule.Effect)),
				logging.String("rule", rule.Name))

			return decision, nil
		}
	}

	// No rules matched, default to deny
	return &PolicyDecision{
		Decision: PolicyEffectDeny,
		Reasons:  []string{"no rules matched"},
		Context:  context,
	}, nil
}

// CreatePolicyRule creates a new policy rule
func (cpe *ConditionalPermissionEngine) CreatePolicyRule(ctx context.Context, rule *PolicyRule) (*PolicyRule, error) {
	// Validate the rule
	err := cpe.validatePolicyRule(rule)
	if err != nil {
		return nil, err
	}

	// Set defaults
	if rule.ID.IsNil() {
		rule.ID = xid.New()
	}
	rule.CreatedAt = time.Now()

	// Store the rule (you'll need to implement storage)
	err = cpe.storePolicyRule(ctx, rule)
	if err != nil {
		return nil, err
	}

	cpe.logger.Info("Policy rule created",
		logging.String("rule_id", rule.ID.String()),
		logging.String("name", rule.Name))

	return rule, nil
}

// Helper methods

func (cpe *ConditionalPermissionEngine) enrichContext(ctx context.Context, permCtx *PermissionContext) error {
	// Get user attributes
	if permCtx.User == nil {
		user, err := cpe.getUserAttributes(ctx, permCtx.UserID)
		if err != nil {
			return err
		}
		permCtx.User = user
	}

	// Add request context
	if permCtx.Request == nil {
		permCtx.Request = make(map[string]interface{})
	}

	// Extract from Go context (this would depend on your middleware)
	if clientIP := ctx.Value("client_ip"); clientIP != nil {
		permCtx.Request["client_ip"] = clientIP
	}

	if userAgent := ctx.Value("user_agent"); userAgent != nil {
		permCtx.Request["user_agent"] = userAgent
	}

	permCtx.Request["timestamp"] = time.Now()
	permCtx.Request["day_of_week"] = time.Now().Weekday().String()
	permCtx.Request["hour"] = time.Now().Hour()

	// Add environment context
	if permCtx.Environment == nil {
		permCtx.Environment = map[string]interface{}{
			"deployment": "production", // This would come from config
			"region":     "us-east-1",  // This would come from config
		}
	}

	return nil
}

func (cpe *ConditionalPermissionEngine) getUserAttributes(ctx context.Context, userID xid.ID) (map[string]interface{}, error) {
	// This would fetch user attributes from your user service
	// For now, return basic attributes
	return map[string]interface{}{
		"id":          userID.String(),
		"department":  "engineering", // This would come from user data
		"role":        "developer",   // This would come from user data
		"location":    "US",          // This would come from user data
		"tenure_days": 365,           // This would be calculated
	}, nil
}

func (cpe *ConditionalPermissionEngine) getApplicablePolicyRules(ctx context.Context, resource, action string, permCtx *PermissionContext) ([]*PolicyRule, error) {
	// This would query your policy rule storage
	// For now, return empty slice
	return []*PolicyRule{}, nil
}

func (cpe *ConditionalPermissionEngine) evaluateRule(rule *PolicyRule, context *PermissionContext) (bool, error) {
	// Check if rule target matches
	if !cpe.targetMatches(rule.Target, context) {
		return false, nil
	}

	// Evaluate the condition
	if rule.Condition == nil {
		return true, nil // No condition means it always matches if target matches
	}

	return cpe.evaluateConditionRule(rule.Condition, context)
}

func (cpe *ConditionalPermissionEngine) targetMatches(target *PolicyTarget, context *PermissionContext) bool {
	if target == nil {
		return true // No target restrictions
	}

	// Check user type
	if len(target.UserTypes) > 0 {
		userType, ok := context.User["type"].(string)
		if !ok || !contains(target.UserTypes, userType) {
			return false
		}
	}

	// Check environment
	if len(target.Environments) > 0 {
		env, ok := context.Environment["deployment"].(string)
		if !ok || !contains(target.Environments, env) {
			return false
		}
	}

	return true
}

func (cpe *ConditionalPermissionEngine) evaluateConditionRule(rule *ConditionRule, context *PermissionContext) (bool, error) {
	switch rule.Operator {
	case "and":
		return cpe.evaluateAndRule(rule, context)
	case "or":
		return cpe.evaluateOrRule(rule, context)
	case "not":
		return cpe.evaluateNotRule(rule, context)
	default:
		return false, errors.New(errors.CodeValidationError, fmt.Sprintf("unsupported rule operator: %s", rule.Operator))
	}
}

func (cpe *ConditionalPermissionEngine) evaluateAndRule(rule *ConditionRule, context *PermissionContext) (bool, error) {
	// All conditions must be true
	for _, condition := range rule.Conditions {
		result, err := cpe.evaluateCondition(condition, context)
		if err != nil {
			return false, err
		}
		if !result {
			return false, nil
		}
	}

	// All nested rules must be true
	for _, nestedRule := range rule.Rules {
		result, err := cpe.evaluateConditionRule(nestedRule, context)
		if err != nil {
			return false, err
		}
		if !result {
			return false, nil
		}
	}

	return true, nil
}

func (cpe *ConditionalPermissionEngine) evaluateOrRule(rule *ConditionRule, context *PermissionContext) (bool, error) {
	// At least one condition must be true
	for _, condition := range rule.Conditions {
		result, err := cpe.evaluateCondition(condition, context)
		if err != nil {
			return false, err
		}
		if result {
			return true, nil
		}
	}

	// At least one nested rule must be true
	for _, nestedRule := range rule.Rules {
		result, err := cpe.evaluateConditionRule(nestedRule, context)
		if err != nil {
			return false, err
		}
		if result {
			return true, nil
		}
	}

	return false, nil
}

func (cpe *ConditionalPermissionEngine) evaluateNotRule(rule *ConditionRule, context *PermissionContext) (bool, error) {
	// Negate the result of the nested evaluation
	if len(rule.Conditions) > 0 || len(rule.Rules) > 0 {
		// Create a temporary AND rule to evaluate
		tempRule := &ConditionRule{
			Operator:   "and",
			Conditions: rule.Conditions,
			Rules:      rule.Rules,
		}
		result, err := cpe.evaluateAndRule(tempRule, context)
		return !result, err
	}
	return false, nil
}

func (cpe *ConditionalPermissionEngine) evaluateCondition(condition *Condition, context *PermissionContext) (bool, error) {
	// Get the evaluator for this condition type
	evaluator, exists := cpe.evaluators[condition.Type]
	if !exists {
		// Default to string evaluator
		evaluator = cpe.evaluators["string"]
	}

	return evaluator.Evaluate(condition, context)
}

func (cpe *ConditionalPermissionEngine) validatePolicyRule(rule *PolicyRule) error {
	if rule.Name == "" {
		return errors.New(errors.CodeValidationError, "rule name is required")
	}

	if rule.Effect != PolicyEffectPermit && rule.Effect != PolicyEffectDeny {
		return errors.New(errors.CodeValidationError, "rule effect must be 'permit' or 'deny'")
	}

	// Validate condition rule if present
	if rule.Condition != nil {
		return cpe.validateConditionRule(rule.Condition)
	}

	return nil
}

func (cpe *ConditionalPermissionEngine) validateConditionRule(rule *ConditionRule) error {
	validOperators := map[string]bool{
		"and": true, "or": true, "not": true,
	}

	if !validOperators[rule.Operator] {
		return errors.New(errors.CodeValidationError, fmt.Sprintf("invalid rule operator: %s", rule.Operator))
	}

	// Validate nested conditions
	for _, condition := range rule.Conditions {
		err := cpe.validateCondition(condition)
		if err != nil {
			return err
		}
	}

	// Validate nested rules
	for _, nestedRule := range rule.Rules {
		err := cpe.validateConditionRule(nestedRule)
		if err != nil {
			return err
		}
	}

	return nil
}

func (cpe *ConditionalPermissionEngine) validateCondition(condition *Condition) error {
	if condition.Field == "" {
		return errors.New(errors.CodeValidationError, "condition field is required")
	}

	if condition.Operator == "" {
		return errors.New(errors.CodeValidationError, "condition operator is required")
	}

	// Check if evaluator exists for this type
	if condition.Type != "" {
		if _, exists := cpe.evaluators[condition.Type]; !exists {
			return errors.New(errors.CodeValidationError, fmt.Sprintf("unsupported condition type: %s", condition.Type))
		}
	}

	return nil
}

func (cpe *ConditionalPermissionEngine) storePolicyRule(ctx context.Context, rule *PolicyRule) error {
	// Implementation would store the rule in your database
	// You might want to add a PolicyRule entity to your schema
	return nil
}

// Built-in evaluators

// StringEvaluator handles string comparisons
type StringEvaluator struct{}

func (se *StringEvaluator) Evaluate(condition *Condition, context *PermissionContext) (bool, error) {
	value := getFieldValue(condition.Field, context)
	valueStr := toString(value)
	expectedStr := toString(condition.Value)

	switch condition.Operator {
	case "equals":
		return valueStr == expectedStr, nil
	case "not_equals":
		return valueStr != expectedStr, nil
	case "contains":
		return strings.Contains(valueStr, expectedStr), nil
	case "starts_with":
		return strings.HasPrefix(valueStr, expectedStr), nil
	case "ends_with":
		return strings.HasSuffix(valueStr, expectedStr), nil
	case "in":
		if list, ok := condition.Value.([]interface{}); ok {
			for _, item := range list {
				if valueStr == toString(item) {
					return true, nil
				}
			}
		}
		return false, nil
	default:
		return false, errors.New(errors.CodeValidationError, fmt.Sprintf("unsupported string operator: %s", condition.Operator))
	}
}

func (se *StringEvaluator) SupportedOperators() []string {
	return []string{"equals", "not_equals", "contains", "starts_with", "ends_with", "in"}
}

// NumberEvaluator handles numeric comparisons
type NumberEvaluator struct{}

func (ne *NumberEvaluator) Evaluate(condition *Condition, context *PermissionContext) (bool, error) {
	value := getFieldValue(condition.Field, context)
	valueNum := toFloat64(value)
	expectedNum := toFloat64(condition.Value)

	switch condition.Operator {
	case "equals":
		return valueNum == expectedNum, nil
	case "not_equals":
		return valueNum != expectedNum, nil
	case "greater_than":
		return valueNum > expectedNum, nil
	case "greater_than_or_equal":
		return valueNum >= expectedNum, nil
	case "less_than":
		return valueNum < expectedNum, nil
	case "less_than_or_equal":
		return valueNum <= expectedNum, nil
	default:
		return false, errors.New(errors.CodeValidationError, fmt.Sprintf("unsupported number operator: %s", condition.Operator))
	}
}

func (ne *NumberEvaluator) SupportedOperators() []string {
	return []string{"equals", "not_equals", "greater_than", "greater_than_or_equal", "less_than", "less_than_or_equal"}
}

// BooleanEvaluator handles boolean comparisons
type BooleanEvaluator struct{}

func (be *BooleanEvaluator) Evaluate(condition *Condition, context *PermissionContext) (bool, error) {
	value := getFieldValue(condition.Field, context)
	valueBool := toBool(value)
	expectedBool := toBool(condition.Value)

	switch condition.Operator {
	case "equals":
		return valueBool == expectedBool, nil
	case "not_equals":
		return valueBool != expectedBool, nil
	default:
		return false, errors.New(errors.CodeValidationError, fmt.Sprintf("unsupported boolean operator: %s", condition.Operator))
	}
}

func (be *BooleanEvaluator) SupportedOperators() []string {
	return []string{"equals", "not_equals"}
}

// ArrayEvaluator handles array operations
type ArrayEvaluator struct{}

func (ae *ArrayEvaluator) Evaluate(condition *Condition, context *PermissionContext) (bool, error) {
	value := getFieldValue(condition.Field, context)

	switch condition.Operator {
	case "contains":
		if arr, ok := value.([]interface{}); ok {
			for _, item := range arr {
				if toString(item) == toString(condition.Value) {
					return true, nil
				}
			}
		}
		return false, nil
	case "size_equals":
		if arr, ok := value.([]interface{}); ok {
			expectedSize := int(toFloat64(condition.Value))
			return len(arr) == expectedSize, nil
		}
		return false, nil
	case "empty":
		if arr, ok := value.([]interface{}); ok {
			return len(arr) == 0, nil
		}
		return true, nil // Non-array values are considered "empty"
	default:
		return false, errors.New(errors.CodeValidationError, fmt.Sprintf("unsupported array operator: %s", condition.Operator))
	}
}

func (ae *ArrayEvaluator) SupportedOperators() []string {
	return []string{"contains", "size_equals", "empty"}
}

// DateEvaluator handles date/time comparisons
type DateEvaluator struct{}

func (de *DateEvaluator) Evaluate(condition *Condition, context *PermissionContext) (bool, error) {
	value := getFieldValue(condition.Field, context)
	valueTime := toTime(value)
	expectedTime := toTime(condition.Value)

	switch condition.Operator {
	case "equals":
		return valueTime.Equal(expectedTime), nil
	case "before":
		return valueTime.Before(expectedTime), nil
	case "after":
		return valueTime.After(expectedTime), nil
	case "between":
		// Expect condition.Value to be an array with two dates
		if dates, ok := condition.Value.([]interface{}); ok && len(dates) == 2 {
			start := toTime(dates[0])
			end := toTime(dates[1])
			return valueTime.After(start) && valueTime.Before(end), nil
		}
		return false, errors.New(errors.CodeValidationError, "between operator requires array with two dates")
	default:
		return false, errors.New(errors.CodeValidationError, fmt.Sprintf("unsupported date operator: %s", condition.Operator))
	}
}

func (de *DateEvaluator) SupportedOperators() []string {
	return []string{"equals", "before", "after", "between"}
}

// PatternEvaluator handles regex pattern matching
type PatternEvaluator struct{}

func (pe *PatternEvaluator) Evaluate(condition *Condition, context *PermissionContext) (bool, error) {
	value := getFieldValue(condition.Field, context)
	valueStr := toString(value)
	pattern := toString(condition.Value)

	switch condition.Operator {
	case "matches":
		matched, err := regexp.MatchString(pattern, valueStr)
		return matched, err
	default:
		return false, errors.New(errors.CodeValidationError, fmt.Sprintf("unsupported pattern operator: %s", condition.Operator))
	}
}

func (pe *PatternEvaluator) SupportedOperators() []string {
	return []string{"matches"}
}

// Utility functions

func getFieldValue(field string, context *PermissionContext) interface{} {
	parts := strings.Split(field, ".")
	if len(parts) < 2 {
		return nil
	}

	var data map[string]interface{}
	switch parts[0] {
	case "user":
		data = context.User
	case "resource":
		data = context.Resource
	case "request":
		data = context.Request
	case "organization":
		data = context.Organization
	case "session":
		data = context.Session
	case "environment":
		data = context.Environment
	case "custom":
		data = context.CustomAttrs
	default:
		return nil
	}

	// Navigate nested fields
	current := data
	for i := 1; i < len(parts); i++ {
		if current == nil {
			return nil
		}
		if val, ok := current[parts[i]]; ok {
			if i == len(parts)-1 {
				return val
			}
			if nested, ok := val.(map[string]interface{}); ok {
				current = nested
			} else {
				return nil
			}
		} else {
			return nil
		}
	}

	return nil
}

func toString(value interface{}) string {
	if value == nil {
		return ""
	}
	return fmt.Sprintf("%v", value)
}

func toFloat64(value interface{}) float64 {
	switch v := value.(type) {
	case float64:
		return v
	case float32:
		return float64(v)
	case int:
		return float64(v)
	case int64:
		return float64(v)
	case string:
		if f, err := strconv.ParseFloat(v, 64); err == nil {
			return f
		}
	}
	return 0
}

func toBool(value interface{}) bool {
	switch v := value.(type) {
	case bool:
		return v
	case string:
		return v == "true" || v == "1" || v == "yes"
	case int:
		return v != 0
	case float64:
		return v != 0
	}
	return false
}

func toTime(value interface{}) time.Time {
	switch v := value.(type) {
	case time.Time:
		return v
	case string:
		if t, err := time.Parse(time.RFC3339, v); err == nil {
			return t
		}
		if t, err := time.Parse("2006-01-02", v); err == nil {
			return t
		}
	case int64:
		return time.Unix(v, 0)
	}
	return time.Time{}
}

func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}
