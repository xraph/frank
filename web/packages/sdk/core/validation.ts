// ================================
// Validation Types & Interfaces
// ================================

export type UserType = "internal" | "external" | "end_user";

export interface ConfigValidationError {
	field: string;
	message: string;
	value?: any;
	severity: "error" | "warning";
}

export interface ValidationResult {
	isValid: boolean;
	errors: ConfigValidationError[];
	warnings: ConfigValidationError[];
}

// ================================
// Validation Helper Functions
// ================================

/**
 * Creates a validation error
 */
export function createError(
	field: string,
	message: string,
	value?: any,
): ConfigValidationError {
	return {
		field,
		message,
		value,
		severity: "error",
	};
}

/**
 * Creates a validation warning
 */
export function createWarning(
	field: string,
	message: string,
	value?: any,
): ConfigValidationError {
	return {
		field,
		message,
		value,
		severity: "warning",
	};
}

/**
 * Validates if a string is a valid URL
 */
function isValidUrl(url: string): boolean {
	try {
		new URL(url);
		return true;
	} catch {
		return false;
	}
}

/**
 * Validates if a value is in a list of valid options
 */
function isValidOption<T>(value: T, validOptions: T[]): boolean {
	return validOptions.includes(value);
}

/**
 * Validates publishable key format
 */
export function validatePublishableKey(key: string): ConfigValidationError[] {
	const errors: ConfigValidationError[] = [];
	if (!key) {
		errors.push(createError("publishableKey", "Publishable key is required"));
		return errors;
	}
	if (typeof key !== "string") {
		errors.push(
			createError("publishableKey", "Publishable key must be a string", key),
		);
		return errors;
	}
	// Check format: pk_test_... or pk_live_...
	if (!/^pk_(test|live|standalone)_[a-zA-Z0-9_]+$/.test(key)) {
		errors.push(
			createError(
				"publishableKey",
				"Invalid publishable key format. Expected: pk_test_... or pk_live_... or pk_standalone_...",
				key,
			),
		);
	}
	if (key.length < 20) {
		errors.push(
			createError(
				"publishableKey",
				"Publishable key appears to be too short",
				key,
			),
		);
	}
	return errors;
}

/**
 * Validates API URL
 */
export function validateApiUrl(url?: string): ConfigValidationError[] {
	const errors: ConfigValidationError[] = [];
	if (!url) {
		return errors; // API URL is optional
	}
	if (typeof url !== "string") {
		errors.push(createError("apiUrl", "API URL must be a string", url));
		return errors;
	}
	if (!isValidUrl(url)) {
		errors.push(createError("apiUrl", "Invalid API URL format", url));
	}
	// Check for HTTPS in production
	if (
		url.startsWith("http://") &&
		!url.includes("localhost") &&
		!url.includes("127.0.0.1")
	) {
		errors.push(
			createWarning(
				"apiUrl",
				"Consider using HTTPS for production API URL",
				url,
			),
		);
	}
	return errors;
}

/**
 * Validates user type
 */
export function validateUserType(userType: string): ConfigValidationError[] {
	const errors: ConfigValidationError[] = [];
	const validUserTypes: UserType[] = ["internal", "external", "end_user"];
	if (!isValidOption(userType, validUserTypes)) {
		errors.push(
			createError(
				"userType",
				`Invalid user type. Must be one of: ${validUserTypes.join(", ")}`,
				userType,
			),
		);
	}
	return errors;
}

/**
 * Validates secret key format
 */
export function validateSecretKey(key?: string): ConfigValidationError[] {
	const errors: ConfigValidationError[] = [];
	if (!key) {
		return errors; // Secret key is optional
	}
	if (typeof key !== "string") {
		errors.push(createError("secretKey", "Secret key must be a string", key));
		return errors;
	}
	// Check format: sk_test_... or sk_live_...
	if (!/^sk_(test|live|standalone)_[a-zA-Z0-9_]+$/.test(key)) {
		errors.push(
			createError(
				"secretKey",
				"Invalid secret key format. Expected: sk_test_... or sk_live_... or sk_standalone_...",
				key,
			),
		);
	}
	if (key.length < 20) {
		errors.push(
			createError("secretKey", "Secret key appears to be too short", key),
		);
	}
	return errors;
}

/**
 * Validates project ID format
 */
export function validateProjectId(id?: string): ConfigValidationError[] {
	const errors: ConfigValidationError[] = [];
	if (!id) {
		return errors; // Project ID is optional
	}
	if (typeof id !== "string") {
		errors.push(createError("projectId", "Project ID must be a string", id));
		return errors;
	}
	// Basic format validation - adjust based on your actual format
	if (!/^[a-zA-Z0-9_-]+$/.test(id)) {
		errors.push(
			createError("projectId", "Project ID contains invalid characters", id),
		);
	}
	if (id.length < 3) {
		errors.push(
			createError("projectId", "Project ID appears to be too short", id),
		);
	}
	return errors;
}

/**
 * Validates storage key prefix
 */
export function validateStorageKeyPrefix(
	prefix?: string,
): ConfigValidationError[] {
	const errors: ConfigValidationError[] = [];
	if (!prefix) {
		return errors; // Storage key prefix is optional
	}
	if (typeof prefix !== "string") {
		errors.push(
			createError(
				"storageKeyPrefix",
				"Storage key prefix must be a string",
				prefix,
			),
		);
		return errors;
	}
	if (prefix.includes(" ")) {
		errors.push(
			createWarning(
				"storageKeyPrefix",
				"Storage key prefix contains spaces which may cause issues",
				prefix,
			),
		);
	}
	return errors;
}

/**
 * Validates session cookie name
 */
export function validateSessionCookieName(
	name?: string,
): ConfigValidationError[] {
	const errors: ConfigValidationError[] = [];
	if (!name) {
		return errors; // Session cookie name is optional
	}
	if (typeof name !== "string") {
		errors.push(
			createError(
				"sessionCookieName",
				"Session cookie name must be a string",
				name,
			),
		);
		return errors;
	}
	// Cookie name validation
	if (!/^[a-zA-Z0-9_-]+$/.test(name)) {
		errors.push(
			createError(
				"sessionCookieName",
				"Session cookie name contains invalid characters",
				name,
			),
		);
	}
	return errors;
}
