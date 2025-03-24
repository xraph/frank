package design

import (
	. "goa.design/goa/v3/dsl"
)

var PermissionResponse = Type("PermissionResponse", func() {
	Meta("struct:pkg:path", "designtypes")
	Description("Permission information")
	Attribute("id", String, "Permission ID")
	Attribute("name", String, "Permission name")
	Attribute("description", String, "Permission description")
	Attribute("resource", String, "Resource this permission applies to")
	Attribute("action", String, "Action this permission allows")
	Attribute("conditions", String, "JSON expression for conditional access")
	Attribute("system", Boolean, "Whether this is a system permission")
	Attribute("created_at", String, "Creation timestamp")
	Attribute("updated_at", String, "Last update timestamp")
	Required("id", "name", "description", "resource", "action", "system", "created_at")
})

var CreatePermissionRequest = Type("CreatePermissionRequest", func() {
	Description("Create permission request")
	Attribute("name", String, "Permission name", func() {
		Example("users:read")
	})
	Attribute("description", String, "Permission description", func() {
		Example("Allows reading user information")
	})
	Attribute("resource", String, "Resource this permission applies to", func() {
		Example("users")
	})
	Attribute("action", String, "Action this permission allows", func() {
		Example("read")
	})
	Attribute("conditions", String, "JSON expression for conditional access")
	Required("name", "description", "resource", "action")
})

var UpdatePermissionRequest = Type("UpdatePermissionRequest", func() {
	Description("Update permission request")
	Attribute("name", String, "Permission name")
	Attribute("description", String, "Permission description")
	Attribute("conditions", String, "JSON expression for conditional access")
})

var RoleResponse = Type("RoleResponse", func() {
	Meta("struct:pkg:path", "designtypes")

	Description("Role information")
	Attribute("id", String, "Role ID")
	Attribute("name", String, "Role name")
	Attribute("description", String, "Role description")
	Attribute("organization_id", String, "Organization ID")
	Attribute("system", Boolean, "Whether this is a system role")
	Attribute("is_default", Boolean, "Whether this is a default role for new users")
	Attribute("permissions", ArrayOf(PermissionResponse), "Permissions assigned to this role")
	Attribute("created_at", String, "Creation timestamp")
	Attribute("updated_at", String, "Last update timestamp")
	Required("id", "name", "system", "is_default", "created_at")
})

var CreateRoleRequest = Type("CreateRoleRequest", func() {
	Description("Create role request")
	Attribute("name", String, "Role name", func() {
		Example("Admin")
	})
	Attribute("description", String, "Role description", func() {
		Example("Administrator role with full access")
	})
	Attribute("organization_id", String, "Organization ID")
	Attribute("is_default", Boolean, "Whether this is a default role for new users", func() {
		Default(false)
	})
	Required("name")
})

var UpdateRoleRequest = Type("UpdateRoleRequest", func() {
	Description("Update role request")
	Attribute("name", String, "Role name")
	Attribute("description", String, "Role description")
	Attribute("is_default", Boolean, "Whether this is a default role for new users")
})

var AddRolePermissionRequest = Type("AddRolePermissionRequest", func() {
	Description("Add permission to role request")
	Attribute("permission_id", String, "Permission ID")
	Required("permission_id")
})

var ListPermissionsResponse = Type("ListPermissionsResponse", func() {
	Description("Add permission to role request")
	Attribute("data", ArrayOf(PermissionResponse))
	Attribute("pagination", Pagination)
	Required("data", "pagination")
})

var _ = Service("rbac", func() {
	Description("Role-Based Access Control service")

	Error("bad_request", BadRequestError)
	Error("unauthorized", UnauthorizedError)
	Error("forbidden", ForbiddenError)
	Error("not_found", NotFoundError)
	Error("conflict", ConflictError)
	Error("internal_error", InternalServerError)

	HTTP(func() {
		Response("bad_request", StatusBadRequest)
		Response("unauthorized", StatusUnauthorized)
		Response("forbidden", StatusForbidden)
		Response("not_found", StatusNotFound)
		Response("conflict", StatusConflict)
		Response("internal_error", StatusInternalServerError)
	})

	// Permissions management
	Method("list_permissions", func() {
		Description("List permissions")
		Security(JWTAuth)
		Payload(func() {
			Token("jwt")
			Attribute("offset", Int, "Pagination offset", func() {
				Default(0)
				Minimum(0)
			})
			Attribute("limit", Int, "Number of items to return", func() {
				Default(20)
				Minimum(1)
				Maximum(100)
			})
			Attribute("resource", String, "Filter by resource")
			Attribute("action", String, "Filter by action")
			Attribute("search", String, "Search term")
		})
		Result(ListPermissionsResponse)
		Error("unauthorized", UnauthorizedError)
		HTTP(func() {
			GET("/v1/permissions")
			Response(StatusOK)
			Params(func() {
				Param("offset")
				Param("limit")
				Param("resource")
				Param("action")
				Param("search")
			})
		})
	})

	Method("create_permission", func() {
		Description("Create a new permission")
		Security(JWTAuth)
		Payload(func() {
			Token("jwt")
			Attribute("permission", CreatePermissionRequest)
			Required("permission")
		})
		Result(PermissionResponse)
		Error("forbidden", ForbiddenError)
		Error("bad_request", BadRequestError)
		Error("unauthorized", UnauthorizedError)
		Error("conflict", ConflictError, "Permission with this resource and action already exists")
		HTTP(func() {
			POST("/v1/permissions")
			Response(StatusCreated)
		})
	})

	Method("get_permission", func() {
		Description("Get permission by ID")
		Security(JWTAuth)
		Payload(func() {
			Token("jwt")
			Attribute("id", String, "Permission ID")
			Required("id")
		})
		Result(PermissionResponse)
		Error("not_found", NotFoundError)
		Error("unauthorized", UnauthorizedError)
		HTTP(func() {
			GET("/v1/permissions/{id}")
			Response(StatusOK)
		})
	})

	Method("update_permission", func() {
		Description("Update permission")
		Security(JWTAuth)
		Payload(func() {
			Token("jwt")
			Attribute("id", String, "Permission ID")
			Attribute("permission", UpdatePermissionRequest)
			Required("id", "permission")
		})
		Result(PermissionResponse)
		Error("not_found", NotFoundError)
		Error("bad_request", BadRequestError)
		Error("unauthorized", UnauthorizedError)
		Error("forbidden", ForbiddenError, "Cannot update system permissions")
		HTTP(func() {
			PUT("/v1/permissions/{id}")
			Response(StatusOK)
		})
	})

	Method("delete_permission", func() {
		Description("Delete permission")
		Security(JWTAuth)
		Payload(func() {
			Token("jwt")
			Attribute("id", String, "Permission ID")
			Required("id")
		})
		Error("not_found", NotFoundError)
		Error("unauthorized", UnauthorizedError)
		Error("forbidden", ForbiddenError, "Cannot delete system permissions")
		HTTP(func() {
			DELETE("/v1/permissions/{id}")
			Response(StatusNoContent)
		})
	})

	// Role management
	Method("list_roles", func() {
		Description("List roles")
		Security(JWTAuth)
		Payload(func() {
			Token("jwt")
			Attribute("offset", Int, "Pagination offset", func() {
				Default(0)
				Minimum(0)
			})
			Attribute("limit", Int, "Number of items to return", func() {
				Default(20)
				Minimum(1)
				Maximum(100)
			})
			Attribute("organization_id", String, "Filter by organization ID")
			Attribute("search", String, "Search term")
		})
		Result(func() {
			Attribute("data", ArrayOf(RoleResponse))
			Attribute("pagination", Pagination)
			Required("data", "pagination")
		})
		Error("unauthorized", UnauthorizedError)
		HTTP(func() {
			GET("/v1/roles")
			Response(StatusOK)
			Params(func() {
				Param("offset")
				Param("limit")
				Param("organization_id")
				Param("search")
			})
		})
	})

	Method("create_role", func() {
		Description("Create a new role")
		Security(JWTAuth)
		Payload(func() {
			Token("jwt")
			Attribute("role", CreateRoleRequest)
			Required("role")
		})
		Result(RoleResponse)
		Error("forbidden", ForbiddenError)
		Error("bad_request", BadRequestError)
		Error("unauthorized", UnauthorizedError)
		Error("conflict", ConflictError, "Role with this name already exists in the organization")
		HTTP(func() {
			POST("/v1/roles")
			Response(StatusCreated)
		})
	})

	Method("get_role", func() {
		Description("Get role by ID")
		Security(JWTAuth)
		Payload(func() {
			Token("jwt")
			Attribute("id", String, "Role ID")
			Required("id")
		})
		Result(RoleResponse)
		Error("not_found", NotFoundError)
		Error("unauthorized", UnauthorizedError)
		HTTP(func() {
			GET("/v1/roles/{id}")
			Response(StatusOK)
		})
	})

	Method("update_role", func() {
		Description("Update role")
		Security(JWTAuth)
		Payload(func() {
			Token("jwt")
			Attribute("id", String, "Role ID")
			Attribute("role", UpdateRoleRequest)
			Required("id", "role")
		})
		Result(RoleResponse)
		Error("forbidden", ForbiddenError, "Cannot update system roles")
		Error("bad_request", BadRequestError)
		Error("not_found", NotFoundError)
		Error("unauthorized", UnauthorizedError)
		HTTP(func() {
			PUT("/v1/roles/{id}")
			Response(StatusOK)
		})
	})

	Method("delete_role", func() {
		Description("Delete role")
		Security(JWTAuth)
		Payload(func() {
			Token("jwt")
			Attribute("id", String, "Role ID")
			Required("id")
		})
		Error("forbidden", ForbiddenError, "Cannot delete system roles")
		Error("not_found", NotFoundError)
		Error("unauthorized", UnauthorizedError)
		HTTP(func() {
			DELETE("/v1/roles/{id}")
			Response(StatusNoContent)
		})
	})

	Method("list_role_permissions", func() {
		Description("List role permissions")
		Security(JWTAuth)
		Payload(func() {
			Token("jwt")
			Attribute("id", String, "Role ID")
			Required("id")
		})
		Result(func() {
			Attribute("permissions", ArrayOf(PermissionResponse))
			Required("permissions")
		})
		Error("not_found", NotFoundError)
		Error("unauthorized", UnauthorizedError)
		HTTP(func() {
			GET("/v1/roles/{id}/permissions")
			Response(StatusOK)
		})
	})

	Method("add_role_permission", func() {
		Description("Add permission to role")
		Security(JWTAuth)
		Payload(func() {
			Token("jwt")
			Attribute("id", String, "Role ID")
			Attribute("permission", AddRolePermissionRequest)
			Required("id", "permission")
		})
		Result(func() {
			Attribute("message", String, "Success message")
			Required("message")
		})
		Error("forbidden", ForbiddenError)
		Error("bad_request", BadRequestError)
		Error("not_found", NotFoundError)
		Error("unauthorized", UnauthorizedError)
		HTTP(func() {
			POST("/v1/roles/{id}/permissions")
			Response(StatusOK)
		})
	})

	Method("remove_role_permission", func() {
		Description("Remove permission from role")
		Security(JWTAuth)
		Payload(func() {
			Token("jwt")
			Attribute("id", String, "Role ID")
			Attribute("permission_id", String, "Permission ID")
			Required("id", "permission_id")
		})
		Error("not_found", NotFoundError)
		Error("unauthorized", UnauthorizedError)
		Error("forbidden", ForbiddenError)
		HTTP(func() {
			DELETE("/v1/roles/{id}/permissions/{permission_id}")
			Response(StatusNoContent)
		})
	})

	// Access control helper methods
	Method("check_permission", func() {
		Description("Check if user has a permission")
		Security(JWTAuth)
		Payload(func() {
			Token("jwt")
			Attribute("resource", String, "Resource to check")
			Attribute("action", String, "Action to check")
			Required("resource", "action")
		})
		Result(func() {
			Attribute("has_permission", Boolean, "Whether user has the permission")
			Required("has_permission")
		})
		Error("unauthorized", UnauthorizedError)
		HTTP(func() {
			GET("/v1/access/check")
			Param("resource")
			Param("action")
			Response(StatusOK)
		})
	})

	Method("check_role", func() {
		Description("Check if user has a role")
		Security(JWTAuth)
		Payload(func() {
			Token("jwt")
			Attribute("role", String, "Role name to check")
			Attribute("organization_id", String, "Organization ID")
			Required("role")
		})
		Result(func() {
			Attribute("has_role", Boolean, "Whether user has the role")
			Required("has_role")
		})
		Error("unauthorized", UnauthorizedError)
		HTTP(func() {
			GET("/v1/access/check-role")
			Param("role")
			Param("organization_id")
			Response(StatusOK)
		})
	})
})
