package config

// Represents a form field configuration
type FormField struct {
	// Field identifier name
	Name string `json:"name" mapstructure:"name" yaml:"name"`
	// Display label for the field
	Label string `json:"label" mapstructure:"label" yaml:"label"`
	// Type of form field
	Type string `json:"type" mapstructure:"type" yaml:"type"`
	// Placeholder text
	Placeholder *string `json:"placeholder" mapstructure:"placeholder" yaml:"placeholder"`
	// Whether the field is required
	Required bool `json:"required" mapstructure:"required" yaml:"required"`
	// Indicates if field represents a first name
	IsFirstName bool `json:"isFirstName" mapstructure:"isFirstName" yaml:"isFirstName"`
	// Indicates if field represents a last name
	IsLastName bool `json:"isLastName" mapstructure:"isLastName" yaml:"isLastName"`
	// Indicates if field represents an email
	IsEmail bool `json:"isEmail" mapstructure:"isEmail" yaml:"isEmail"`
	// Options for select fields
	Options []*FormFieldSelectOption `json:"options" mapstructure:"options" yaml:"options"`
	// Validation rules for the field
	Validation *FormFieldValidationRules `json:"validation" mapstructure:"validation" yaml:"validation"`
	// Row position identifier (string or number)
	Row any `json:"row" mapstructure:"row" yaml:"row"`
	// Width of the field
	Width string `json:"width" mapstructure:"width" yaml:"width"`
}

// Option for select fields
type FormFieldSelectOption struct {
	// Option value
	Value string `json:"value" mapstructure:"value" yaml:"value"`
	// Option display label
	Label string `json:"label" mapstructure:"label" yaml:"label"`
}

// Validation rules for form fields
type FormFieldValidationRules struct {
	// Regex pattern for validation
	Pattern *string `json:"pattern" mapstructure:"pattern" yaml:"pattern"`
	// Minimum length
	MinLength *int `json:"minLength" mapstructure:"minLength" yaml:"minLength"`
	// Maximum length
	MaxLength *int `json:"maxLength" mapstructure:"maxLength" yaml:"maxLength"`
	// Minimum value
	Min *float32 `json:"min" mapstructure:"min" yaml:"min"`
	// Maximum value
	Max *float32 `json:"max" mapstructure:"max" yaml:"max"`
}
