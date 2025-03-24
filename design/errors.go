package design

import (
	. "goa.design/goa/v3/dsl"
)

var FrankError = Type("FrankError", func() {
	// Generate in shared types package
	// Meta("struct:pkg:path", "designtypes")
	Description("Standard error response format")
	Field(1, "code", String, "Error code")
	Field(2, "message", String, "Error message")
	Field(3, "details", Any, "Additional error details")
	Field(4, "id", String, "Unique error ID")
	Required("code", "message")
})

var BadRequestError = Type("BadRequestError", func() {
	// Generate in shared types package
	// Meta("struct:pkg:path", "designtypes")
	Description("Bad request response")
	Extend(FrankError)
	Example(map[string]interface{}{
		"code":    "BAD_REQUEST",
		"message": "Invalid request parameters",
		"details": map[string]interface{}{
			"fields": []interface{}{
				map[string]interface{}{
					"path":    "email",
					"message": "must be a valid email address",
				},
			},
		},
	})
})

var UnauthorizedError = Type("UnauthorizedError", func() {
	// Generate in shared types package
	// Meta("struct:pkg:path", "designtypes")
	Description("Unauthorized response")
	Extend(FrankError)
	Example(map[string]interface{}{
		"code":    "UNAUTHORIZED",
		"message": "Authentication required",
	})
})

var ForbiddenError = Type("ForbiddenError", func() {
	// Generate in shared types package
	// Meta("struct:pkg:path", "designtypes")
	Description("Forbidden response")
	Extend(FrankError)
	Example(map[string]interface{}{
		"code":    "FORBIDDEN",
		"message": "Permission denied",
	})
})

var NotFoundError = Type("NotFoundError", func() {
	// Generate in shared types package
	// Meta("struct:pkg:path", "designtypes")
	Description("Not found response")
	Extend(FrankError)
	Example(map[string]interface{}{
		"code":    "NOT_FOUND",
		"message": "Resource not found",
	})
})

var ConflictError = Type("ConflictError", func() {
	// Generate in shared types package
	// Meta("struct:pkg:path", "designtypes")
	Description("Conflict response")
	Extend(FrankError)
})

var InternalServerError = Type("InternalServerError", func() {
	// Generate in shared types package
	// Meta("struct:pkg:path", "designtypes")
	Description("Internal server error response")
	Extend(FrankError)
	Example(map[string]interface{}{
		"code":    "INTERNAL_ERROR",
		"message": "An unexpected error occurred",
	})
})
