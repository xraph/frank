package design

import (
	. "goa.design/goa/v3/dsl"
)

// FieldType represents the type of form field
type FieldType string

const (
	FieldTypeText     FieldType = "text"
	FieldTypeSelect   FieldType = "select"
	FieldTypeEmail    FieldType = "email"
	FieldTypePassword FieldType = "password"
	FieldTypeCheckbox FieldType = "checkbox"
	FieldTypeNumber   FieldType = "number"
)

// FieldWidth represents the width options for form fields
type FieldWidth string

const (
	FieldWidthFull  FieldWidth = "full"
	FieldWidthHalf  FieldWidth = "half"
	FieldWidthThird FieldWidth = "third"
)

var FormField = Type("FormField", func() {
	Meta("struct:pkg:path", "designtypes")

	Description("Represents a form field configuration")

	Field(1, "name", String, func() {
		Description("Field identifier name")
		Example("firstName")
		Meta("struct:tag:json", "name")
		Meta("struct:tag:yaml", "name")
		Meta("struct:tag:mapstructure", "name")
	})

	Field(2, "label", String, func() {
		Description("Display label for the field")
		Example("First Name")
		Meta("struct:tag:json", "label")
		Meta("struct:tag:yaml", "label")
		Meta("struct:tag:mapstructure", "label")
	})

	Field(3, "type", String, func() {
		Description("Type of form field")
		Enum("text", "select", "checkbox", "number")
		Example("text")
		Meta("struct:tag:json", "type")
		Meta("struct:tag:yaml", "type")
		Meta("struct:tag:mapstructure", "type")
	})

	Field(4, "placeholder", String, func() {
		Description("Placeholder text")
		Example("Enter your first name")
		Meta("struct:tag:json", "placeholder")
		Meta("struct:tag:yaml", "placeholder")
		Meta("struct:tag:mapstructure", "placeholder")
	})

	Field(5, "required", Boolean, func() {
		Description("Whether the field is required")
		Default(false)
		Meta("struct:tag:json", "required")
		Meta("struct:tag:yaml", "required")
		Meta("struct:tag:mapstructure", "required")
	})

	Field(6, "isFirstName", Boolean, func() {
		Description("Indicates if field represents a first name")
		Default(false)
		Meta("struct:tag:json", "isFirstName")
		Meta("struct:tag:yaml", "isFirstName")
		Meta("struct:tag:mapstructure", "isFirstName")
	})

	Field(7, "isLastName", Boolean, func() {
		Description("Indicates if field represents a last name")
		Default(false)
		Meta("struct:tag:json", "isLastName")
		Meta("struct:tag:yaml", "isLastName")
		Meta("struct:tag:mapstructure", "isLastName")
	})

	Field(8, "isEmail", Boolean, func() {
		Description("Indicates if field represents an email")
		Default(false)
		Meta("struct:tag:json", "isEmail")
		Meta("struct:tag:yaml", "isEmail")
		Meta("struct:tag:mapstructure", "isEmail")
	})

	Field(9, "options", ArrayOf(FormFieldSelectOption), func() {
		Description("Options for select fields")
		Meta("struct:tag:json", "options")
		Meta("struct:tag:yaml", "options")
		Meta("struct:tag:mapstructure", "options")
	})

	Field(10, "validation", FormFieldValidationRules, func() {
		Description("Validation rules for the field")
		Meta("struct:tag:json", "validation")
		Meta("struct:tag:yaml", "validation")
		Meta("struct:tag:mapstructure", "validation")
	})

	Field(11, "row", Any, func() {
		Description("Row position identifier (string or number)")
		Meta("struct:tag:json", "row")
		Meta("struct:tag:yaml", "row")
		Meta("struct:tag:mapstructure", "row")
		Example("1")
	})

	Field(12, "width", String, func() {
		Meta("struct:tag:json", "width")
		Meta("struct:tag:yaml", "width")
		Meta("struct:tag:mapstructure", "width")
		Description("Width of the field")
		Enum("full", "half", "third")
		Default("full")
	})

	Required("name", "label", "type")
})

var FormFieldSelectOption = Type("FormFieldSelectOption", func() {
	Meta("struct:pkg:path", "designtypes")
	Description("Option for select fields")

	Field(1, "value", String, func() {
		Description("Option value")
		Meta("struct:tag:json", "value")
		Meta("struct:tag:yaml", "value")
		Meta("struct:tag:mapstructure", "value")
	})

	Field(2, "label", String, func() {
		Description("Option display label")
		Meta("struct:tag:json", "label")
		Meta("struct:tag:yaml", "label")
		Meta("struct:tag:mapstructure", "label")
	})

	Required("label", "value")
})

var FormFieldValidationRules = Type("FormFieldValidationRules", func() {
	Meta("struct:pkg:path", "designtypes")

	Description("Validation rules for form fields")

	Field(1, "pattern", String, func() {
		Description("Regex pattern for validation")
		Meta("struct:tag:json", "pattern")
		Meta("struct:tag:yaml", "pattern")
		Meta("struct:tag:mapstructure", "pattern")
	})

	Field(2, "minLength", Int, func() {
		Description("Minimum length")
		Minimum(0)
		Meta("struct:tag:json", "minLength")
		Meta("struct:tag:yaml", "minLength")
		Meta("struct:tag:mapstructure", "minLength")
	})

	Field(3, "maxLength", Int, func() {
		Description("Maximum length")
		Minimum(1)
		Meta("struct:tag:json", "maxLength")
		Meta("struct:tag:yaml", "maxLength")
		Meta("struct:tag:mapstructure", "maxLength")
	})

	Field(4, "min", Float32, func() {
		Description("Minimum value")
		Meta("struct:tag:json", "min")
		Meta("struct:tag:yaml", "min")
		Meta("struct:tag:mapstructure", "min")
	})

	Field(5, "max", Float32, func() {
		Description("Maximum value")
		Meta("struct:tag:json", "max")
		Meta("struct:tag:yaml", "max")
		Meta("struct:tag:mapstructure", "max")
	})
})
