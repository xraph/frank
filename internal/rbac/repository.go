package rbac

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/juicycleff/frank/pkg/errors"
	"github.com/juicycleff/frank/pkg/logging"
)

// Enforcer provides access control enforcement
type Enforcer interface {
	// Enforce checks if a user has permission to perform an action on a resource
	Enforce(ctx context.Context, userID, resource, action string) (bool, error)

	// EnforceWithContext checks permission with additional context data
	EnforceWithContext(ctx context.Context, userID, resource, action string, contextData map[string]interface{}) (bool, error)

	// GetAllowedActions returns all actions a user can perform on a resource
	GetAllowedActions(ctx context.Context, userID, resource string) ([]string, error)
}

type enforcer struct {
	repo   Repository
	logger logging.Logger
}

// NewEnforcer creates a new RBAC enforcer
func NewEnforcer(repo Repository, logger logging.Logger) Enforcer {
	return &enforcer{
		repo:   repo,
		logger: logger,
	}
}

// Enforce checks if a user has permission to perform an action on a resource
func (e *enforcer) Enforce(ctx context.Context, userID, resource, action string) (bool, error) {
	return e.EnforceWithContext(ctx, userID, resource, action, nil)
}

// EnforceWithContext checks permission with additional context data
func (e *enforcer) EnforceWithContext(ctx context.Context, userID, resource, action string, contextData map[string]interface{}) (bool, error) {
	// Get all user's permissions
	permissions, err := e.repo.GetUserPermissions(ctx, userID)
	if err != nil {
		if errors.IsNotFound(err) {
			// User not found, no permissions
			return false, nil
		}
		return false, err
	}

	// Get permission string in format "resource:action"
	permString := fmt.Sprintf("%s:%s", resource, action)
	fmt.Println(permString)

	// Check for exact match or wildcard permissions
	for _, perm := range permissions {
		// Check for exact permission match
		if (perm.Resource == resource && perm.Action == action) ||
			(perm.Resource == resource && perm.Action == "*") ||
			(perm.Resource == "*" && perm.Action == "*") {

			// If permission has conditions, evaluate them
			if perm.Conditions != "" && contextData != nil {
				allowed, err := e.evaluateConditions(perm.Conditions, contextData)
				if err != nil {
					e.logger.Warn("Failed to evaluate permission conditions",
						logging.Error(err),
						logging.String("permission_id", perm.ID),
						logging.String("user_id", userID),
					)
					continue
				}

				if allowed {
					return true, nil
				}

				// Conditions not met, continue checking other permissions
				continue
			}

			// No conditions or no context data, permission granted
			return true, nil
		}
	}

	// No matching permission found
	return false, nil
}

// GetAllowedActions returns all actions a user can perform on a resource
func (e *enforcer) GetAllowedActions(ctx context.Context, userID, resource string) ([]string, error) {
	// Get all user's permissions
	permissions, err := e.repo.GetUserPermissions(ctx, userID)
	if err != nil {
		if errors.IsNotFound(err) {
			// User not found, no permissions
			return []string{}, nil
		}
		return nil, err
	}

	// Collect allowed actions
	allowedActions := make(map[string]struct{})

	for _, perm := range permissions {
		// Check if permission applies to this resource
		if perm.Resource == resource || perm.Resource == "*" {
			// Add the action to allowed actions
			allowedActions[perm.Action] = struct{}{}
		}
	}

	// Convert map to slice
	result := make([]string, 0, len(allowedActions))
	for action := range allowedActions {
		result = append(result, action)
	}

	return result, nil
}

// evaluateConditions evaluates permission conditions against context data
func (e *enforcer) evaluateConditions(conditionsJSON string, contextData map[string]interface{}) (bool, error) {
	// Parse conditions from JSON
	var conditions map[string]interface{}
	if err := json.Unmarshal([]byte(conditionsJSON), &conditions); err != nil {
		return false, fmt.Errorf("failed to parse conditions: %w", err)
	}

	// Implement condition evaluation logic
	// This is a simplified implementation that could be expanded with a full expression evaluator

	// Example conditions format:
	// {
	//   "operator": "and",
	//   "conditions": [
	//     {"field": "resource.owner_id", "operator": "equals", "value": "{{user.id}}"},
	//     {"field": "request.method", "operator": "in", "value": ["GET", "HEAD"]}
	//   ]
	// }

	// For this implementation, we'll just check if all fields exist and have matching values
	operator, ok := conditions["operator"].(string)
	if !ok {
		return false, fmt.Errorf("invalid conditions format, missing operator")
	}

	conditionsList, ok := conditions["conditions"].([]interface{})
	if !ok {
		return false, fmt.Errorf("invalid conditions format, missing conditions list")
	}

	// Process conditions based on operator
	switch operator {
	case "and":
		// All conditions must be true
		for _, conditionItem := range conditionsList {
			condition, ok := conditionItem.(map[string]interface{})
			if !ok {
				return false, fmt.Errorf("invalid condition format")
			}

			match, err := e.evaluateCondition(condition, contextData)
			if err != nil {
				return false, err
			}

			if !match {
				// One condition is false, entire AND expression is false
				return false, nil
			}
		}
		// All conditions were true
		return true, nil

	case "or":
		// At least one condition must be true
		for _, conditionItem := range conditionsList {
			condition, ok := conditionItem.(map[string]interface{})
			if !ok {
				return false, fmt.Errorf("invalid condition format")
			}

			match, err := e.evaluateCondition(condition, contextData)
			if err != nil {
				return false, err
			}

			if match {
				// One condition is true, entire OR expression is true
				return true, nil
			}
		}
		// No conditions were true
		return false, nil

	default:
		return false, fmt.Errorf("unsupported operator: %s", operator)
	}
}

// evaluateCondition evaluates a single condition against context data
func (e *enforcer) evaluateCondition(condition map[string]interface{}, contextData map[string]interface{}) (bool, error) {
	field, ok := condition["field"].(string)
	if !ok {
		return false, fmt.Errorf("missing field in condition")
	}

	operator, ok := condition["operator"].(string)
	if !ok {
		return false, fmt.Errorf("missing operator in condition")
	}

	conditionValue := condition["value"]
	if conditionValue == nil {
		return false, fmt.Errorf("missing value in condition")
	}

	// Extract context value
	contextValue, ok := getNestedValue(contextData, field)
	if !ok {
		// Field not found in context data
		return false, nil
	}

	// Evaluate condition based on operator
	switch operator {
	case "equals":
		return valueEquals(contextValue, conditionValue)

	case "not_equals":
		equals, err := valueEquals(contextValue, conditionValue)
		return !equals, err

	case "in":
		return valueIn(contextValue, conditionValue)

	case "not_in":
		in, err := valueIn(contextValue, conditionValue)
		return !in, err

	case "greater_than":
		return valueGreaterThan(contextValue, conditionValue)

	case "less_than":
		return valueLessThan(contextValue, conditionValue)

	default:
		return false, fmt.Errorf("unsupported condition operator: %s", operator)
	}
}

// getNestedValue retrieves a nested value from a map using a dot notation path
func getNestedValue(data map[string]interface{}, path string) (interface{}, bool) {
	// TODO: Implement nested value lookup with dot notation
	// For now, just return the top-level value
	value, ok := data[path]
	return value, ok
}

// valueEquals checks if two values are equal
func valueEquals(a, b interface{}) (bool, error) {
	// Try to compare directly
	if a == b {
		return true, nil
	}

	// Try to convert to comparable types
	// This is a simplified implementation
	return false, nil
}

// valueIn checks if a value is in a list
func valueIn(value, list interface{}) (bool, error) {
	// Convert list to slice if needed
	listSlice, ok := list.([]interface{})
	if !ok {
		return false, fmt.Errorf("expected list value to be a slice")
	}

	// Check if value is in the list
	for _, item := range listSlice {
		if value == item {
			return true, nil
		}
	}

	return false, nil
}

// valueGreaterThan checks if a value is greater than another
func valueGreaterThan(a, b interface{}) (bool, error) {
	// Try to convert to comparable numeric types
	// This is a simplified implementation that would need to be expanded
	return false, nil
}

// valueLessThan checks if a value is less than another
func valueLessThan(a, b interface{}) (bool, error) {
	// Try to convert to comparable numeric types
	// This is a simplified implementation that would need to be expanded
	return false, nil
}
