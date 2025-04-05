package design

import (
	. "goa.design/goa/v3/dsl"
)

var EmailType = Type("Email", func() {
	// Generate in shared types package
	Meta("struct:pkg:path", "designtypes")
	Description("User email address")
	Attribute("email", String, "Email address", func() {
		Format(FormatEmail)
		Example("user@example.com")
		Meta("struct:tag:json", "email")
	})
})

var UserID = Type("UserID", func() {
	// Generate in shared types package
	Meta("struct:pkg:path", "designtypes")
	Description("User ID")

	Attribute("id", String, "User ID", func() {
		Example("usr_123456789")
		Meta("struct:tag:json", "id")
	})

	Required("id")
})

var OrgID = Type("OrgID", func() {
	// Generate in shared types package
	Meta("struct:pkg:path", "designtypes")
	Description("Organization ID")
	Attribute("id", String, "Organization ID", func() {
		Example("org_123456789")
		Meta("struct:tag:json", "id")
	})
	Required("id")
})

var Timestamp = Type("Timestamp", func() {
	// Generate in shared types package
	Meta("struct:pkg:path", "designtypes")
	Description("RFC3339 formatted timestamp")
	Attribute("time", String, "Timestamp", func() {
		Format("date-time")
		Example("2023-01-01T12:00:00Z")
		Meta("struct:tag:json", "time")
	})
	Required("time")
})

var BaseType = Type("Base", func() {
	// Generate in shared types package
	Meta("struct:pkg:path", "designtypes")
	Description("Base type")
	Field(1, "id", String, "ID of the entity", func() {
		Example("2023-01-01T12:00:00Z")
		Meta("struct:tag:json", "id")
	})
	Field(2, "created_at", String, "Created At", func() {
		Format(FormatDateTime)
		Example("2023-01-01T12:00:00Z")
		Meta("struct:tag:json", "created_at", "createdAt")
	})
	Field(3, "updated_at", String, "Updated At", func() {
		Format(FormatDateTime)
		Example("2023-01-01T12:00:00Z")
		Meta("struct:tag:json", "updated_at", "updatedAt")
	})
	Required("id", "created_at", "updated_at")
})

var BaseUserType = Type("BaseUser", func() {
	Meta("struct:pkg:path", "designtypes")

	Description("Base user type")

	Extend(EmailType)
	Field(5, "first_name", String, "User first name", func() {
		Meta("struct:tag:json", "first_name", "firstName")
	})
	Field(6, "last_name", String, "User last name", func() {
		Meta("struct:tag:json", "last_name", "lastName")
	})
	Field(7, "id", String, "ID of the entity", func() {
		Example("2023-01-01T12:00:00Z")
		Meta("struct:tag:json", "id")
	})
	Field(8, "phone_number", String, "User phone number", func() {
		Meta("struct:tag:json", "phone_number", "phoneNumber")
	})
	Field(10, "profile_image_url", String, "URL to user's profile image", func() {
		Meta("struct:tag:json", "profile_image_url", "profileImageUrl")
	})
	Field(11, "metadata", MetadataType, "User metadata", func() {
		Meta("struct:tag:json", "metadata")
	})

	Attribute("locale", String, "User locale", func() {
		Default("en")
		Meta("struct:tag:json", "locale")
	})
})

var BaseAuthUserType = Type("BaseAuthUser", func() {
	Meta("struct:pkg:path", "designtypes")

	Description("Base auth user type")

	Extend(BaseUserType)

	Field(7, "email_verified", Boolean, "Whether email is verified", func() {
		Meta("struct:tag:json", "email_verified", "emailVerified")
	})
	Field(9, "phone_verified", Boolean, "Whether phone is verified", func() {
		Meta("struct:tag:json", "phone_verified", "phoneVerified")
	})
	Field(10, "profile_image_url", String, "URL to user's profile image", func() {
		Meta("struct:tag:json", "profile_image_url", "profileImageUrl")
	})

	Required("email", "email_verified", "id")
})

var Pagination = Type("Pagination", func() {
	Meta("struct:pkg:path", "designtypes")
	Description("Pagination parameters")

	Field(1, "offset", Int, "Offset", func() {
		Minimum(0)
		Default(0)
		Example(0)
		Meta("struct:tag:json", "offset")
	})
	Field(2, "limit", Int, "Limit", func() {
		Minimum(1)
		Maximum(100)
		Default(10)
		Example(10)
		Meta("struct:tag:json", "limit")
	})
	Field(3, "total", Int, "Total number of items", func() {
		Meta("struct:tag:json", "total")
	})
	Field(4, "total_pages", Int, "Total number of pages", func() {
		Meta("struct:tag:json", "total_pages", "totalPages")
	})
	Field(5, "current_page", Int, "Current page number", func() {
		Meta("struct:tag:json", "current_page", "currentPage")
	})
	Field(6, "has_next", Boolean, "Has next page", func() {
		Meta("struct:tag:json", "has_next", "hasNext")
	})
	Field(7, "has_previous", Boolean, "Has previous page", func() {
		Meta("struct:tag:json", "has_previous", "hasPrevious")
	})

	Required("total", "offset", "limit", "total_pages", "current_page", "has_next", "has_previous")

})

var MetadataType = MapOf(String, Any, func() {
	Description("Arbitrary metadata as key-value pairs")
	Meta("struct:tag:json", "metadata")
})

var Session = Type("Session", func() {
	Meta("struct:pkg:path", "designtypes")

	Description("User session information")

	Extend(BaseType)

	Attribute("user_id", String, "User ID", func() {
		Meta("struct:tag:json", "user_id", "userId")
	})
	Attribute("device_id", String, "Device ID", func() {
		Meta("struct:tag:json", "device_id", "deviceId")
	})
	Attribute("ip_address", String, "IP address", func() {
		Meta("struct:tag:json", "ip_address", "ipAddress")
	})
	Attribute("user_agent", String, "User agent string", func() {
		Meta("struct:tag:json", "user_agent", "userAgent")
	})
	Attribute("location", String, "Location", func() {
		Meta("struct:tag:json", "location")
	})
	Attribute("token", String, "Session token", func() {
		Meta("struct:tag:json", "token")
	})
	Attribute("organization_id", String, "Organization ID", func() {
		Meta("struct:tag:json", "organization_id", "organizationId")
	})
	Attribute("is_active", Boolean, "Session is active", func() {
		Meta("struct:tag:json", "is_active", "isActive")
	})
	Attribute("metadata", MetadataType, "Session metadata", func() {
		Meta("struct:tag:json", "metadata")
		Example(map[string]interface{}{
			"ip_address": "127.0.0.1",
		})
	})

	Field(5, "last_active_at", String, "Last activity timestamp", func() {
		Format(FormatDateTime)
		Meta("struct:tag:json", "last_active_at", "lastActiveAt")
		Example("2023-01-01T12:00:00Z")
	})
	Field(6, "expires_at", String, "Expiry timestamp", func() {
		Format(FormatDateTime)
		Meta("struct:tag:json", "expires_at", "expiresAt")
		Example("2023-01-01T12:00:00Z")
	})

	Required("id", "created_at", "expires_at")
})

var PaginationResponse = Type("PaginationResponse", func() {
	Meta("struct:pkg:path", "designtypes")
	Description("Pagination response")

	Field(2, "pagination", Pagination, "Pagination params", func() {
		Meta("struct:tag:json", "pagination")
	})

	Required("pagination")

})
