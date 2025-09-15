package sso

import (
	"fmt"
)

// ConfigMerger provides functionality to merge configurations
type ConfigMerger struct{}

// NewConfigMerger creates a new config merger
func NewConfigMerger() *ConfigMerger {
	return &ConfigMerger{}
}

// MergeConfigs merges template config with user config, prioritizing user config
func (m *ConfigMerger) MergeConfigs(templateConfig, userConfig map[string]any) map[string]any {
	// OnStart with a copy of template config
	merged := make(map[string]any)

	// Copy template config
	for key, value := range templateConfig {
		merged[key] = value
	}

	// Override with user config values
	for key, value := range userConfig {
		// Skip nil values
		if value == nil {
			continue
		}

		// Skip empty strings
		if strVal, ok := value.(string); ok && strVal == "" {
			continue
		}

		// Skip empty slices
		if sliceVal, ok := value.([]string); ok && len(sliceVal) == 0 {
			continue
		}
		if sliceVal, ok := value.([]any); ok && len(sliceVal) == 0 {
			continue
		}

		merged[key] = value
	}

	return merged
}

// Common configuration field extractors

// GetStringConfig safely extracts a string value from config
func GetStringConfig(config map[string]any, key string) string {
	if value, exists := config[key]; exists {
		if str, ok := value.(string); ok {
			return str
		}
	}
	return ""
}

// GetStringSliceConfig safely extracts a string slice from config
func GetStringSliceConfig(config map[string]any, key string) []string {
	if value, exists := config[key]; exists {
		if slice, ok := value.([]string); ok {
			return slice
		}
		if slice, ok := value.([]any); ok {
			result := make([]string, 0, len(slice))
			for _, item := range slice {
				if str, ok := item.(string); ok {
					result = append(result, str)
				}
			}
			return result
		}
	}
	return nil
}

// GetBoolConfig safely extracts a boolean value from config
func GetBoolConfig(config map[string]any, key string) bool {
	if value, exists := config[key]; exists {
		if b, ok := value.(bool); ok {
			return b
		}
	}
	return false
}

// GetIntConfig safely extracts an integer value from config
func GetIntConfig(config map[string]any, key string) int {
	if value, exists := config[key]; exists {
		if i, ok := value.(int); ok {
			return i
		}
		if f, ok := value.(float64); ok {
			return int(f)
		}
	}
	return 0
}

// GetFloat64Config safely extracts a float64 value from config
func GetFloat64Config(config map[string]any, key string) float64 {
	if value, exists := config[key]; exists {
		if f, ok := value.(float64); ok {
			return f
		}
		if i, ok := value.(int); ok {
			return float64(i)
		}
	}
	return 0.0
}

// SetConfigValue safely sets a value in config map if it's not empty
func SetConfigValue(config map[string]any, key string, value any) {
	if value == nil {
		return
	}

	switch v := value.(type) {
	case string:
		if v != "" {
			config[key] = v
		}
	case []string:
		if len(v) > 0 {
			config[key] = v
		}
	case []any:
		if len(v) > 0 {
			config[key] = v
		}
	case bool:
		config[key] = v
	case int:
		if v != 0 {
			config[key] = v
		}
	case float64:
		if v != 0.0 {
			config[key] = v
		}
	default:
		config[key] = v
	}
}

// CloneConfig creates a deep copy of a configuration map
func CloneConfig(config map[string]any) map[string]any {
	clone := make(map[string]any)
	for key, value := range config {
		switch v := value.(type) {
		case []string:
			// Deep copy string slices
			clonedSlice := make([]string, len(v))
			copy(clonedSlice, v)
			clone[key] = clonedSlice
		case []any:
			// Deep copy any slices
			clonedSlice := make([]any, len(v))
			copy(clonedSlice, v)
			clone[key] = clonedSlice
		case map[string]any:
			// Recursively clone nested maps
			clone[key] = CloneConfig(v)
		default:
			// Copy primitive values directly
			clone[key] = v
		}
	}
	return clone
}

// ValidateConfigKeys checks if all keys in config are supported
func ValidateConfigKeys(config map[string]any, supportedKeys []string) error {
	supportedSet := make(map[string]bool)
	for _, key := range supportedKeys {
		supportedSet[key] = true
	}

	for key := range config {
		if !supportedSet[key] {
			return fmt.Errorf("unsupported configuration key: %s", key)
		}
	}

	return nil
}
