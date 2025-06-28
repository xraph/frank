import {
    Configuration, InitOverrideFunction,
} from '@frank-auth/client';

import {FrankAuthConfig, FrankAuthError} from './index';
import {convertError} from './errors';
import {
    ConfigValidationError, validateSecretKey, validateApiUrl, validateProjectId, validatePublishableKey,
    ValidationResult, validateSessionCookieName, validateStorageKeyPrefix, validateUserType,
    createError, createWarning,
} from './validation';

/**
 * FrankOrganization - Organization Management SDK
 *
 * Provides comprehensive organization management capabilities including:
 * - Organization CRUD operations
 * - Member management and invitations
 * - Domain verification and management
 * - Billing and subscription management
 * - Feature management and statistics
 * - Settings and configuration
 *
 * Supports multi-tenant architecture with organization-scoped operations
 */
export class BaseFrankAPI {
    private readonly _options: FrankAuthConfig
    private readonly _config: Configuration
    private readonly _validationResult: ValidationResult

    private _accessToken: string | null = null;
    private _refreshToken: string | null = null;
    private _activeSessionId: string | null = null;

    constructor(config: FrankAuthConfig, accessToken?: string) {
        this._options = config;
        this._accessToken = accessToken || null;

        // Validate configuration
        this._validationResult = this.validateConfig(config);

        const headers = {
            'X-Publishable-Key': this._options.publishableKey,
            'X-User-Type': this._options.userType,
            'Content-Type': 'application/json',
        } as Record<string, string>

        if (this._options.secretKey) {
            headers['X-API-Key'] = this._options.secretKey
        }

        if (this._options.secretKey) {
            headers['X-API-Key'] = this._options.secretKey
        }

        if (this._accessToken) {
            headers['Authorization'] = `Bearer ${this._accessToken}`
        }

        this._config = new Configuration({
            basePath: config.apiUrl,
            accessToken: () => this.accessToken || '',
            credentials: 'include',
            headers,
        });
    }

    // ================================
    // Getters & Configuration Access
    // ================================

    get config() {
        return this._config
    }

    get options() {
        return this._options
    }

    get accessToken(): string | null {
        return this._accessToken;
    }

    get refreshToken(): string | null {
        return this._refreshToken;
    }


    // ================================
    // Token Management
    // ================================

    /**
     * Update access token (called by FrankAuth when token changes)
     */
    set accessToken(token: string | null) {
        this._accessToken = token;
    }

    /**
     * Update refresh token (called by FrankAuth when token changes)
     */
    set refreshToken(token: string | null) {
        this._refreshToken = token;
    }

    /**
     * Reset all tokens
     */
    resetTokens() {
        this._accessToken = null;
        this._refreshToken = null;
    }

    /**
     * Update active session (called by FrankAuth when session changes)
     */
    set activeSession(session: string | null) {
        this._activeSessionId = session;
    }

    /**
     * Check if user is currently signed in
     */
    isSignedIn(): boolean {
        return !!this.accessToken;
    }

    // Update access token (called by FrankAuth when token changes)
    setProjectId(id: string): void {
        this._options.projectId = id;
    }


    protected get dynamicHeaders() {
        const h = {
            'X-Publishable-Key': this.options.publishableKey,
            'X-User-Type': this._options.userType,
            'Content-Type': 'application/json',
        } as Record<string, string>

        if (this.options.projectId) {
            h['X-Org-ID'] = this.options.projectId
        }

        if (this.options.secretKey) {
            h['X-API-Key'] = this.options.secretKey
        }

        if (this._accessToken) {
            h['Authorization'] = `Bearer ${this._accessToken}`
        }

        return h
    }

    /**
     * Helper method to merge dynamic headers with existing initOverrides
     */
    protected mergeHeaders(initOverrides?: RequestInit | InitOverrideFunction): RequestInit | InitOverrideFunction {
        const dynamicHeaders = this.dynamicHeaders;

        if (!initOverrides) {
            return {headers: dynamicHeaders};
        }

        if (typeof initOverrides === 'function') {
            const originalFn = initOverrides;
            return async (context) => {
                const result = await originalFn(context);
                return {
                    ...result,
                    headers: {
                        ...dynamicHeaders,
                        ...result?.headers,
                    }
                };
            };
        }

        return {
            ...initOverrides,
            headers: {
                ...dynamicHeaders,
                ...initOverrides.headers,
            }
        };
    }

    // ================================
    // Configuration Validation
    // ================================

    /**
     * Validates the complete Frank Auth configuration
     */
    public validateConfig(config: FrankAuthConfig): ValidationResult {
        const allErrors: ConfigValidationError[] = [];

        // Validate each configuration field
        allErrors.push(...validatePublishableKey(config.publishableKey));
        allErrors.push(...validateApiUrl(config.apiUrl));
        allErrors.push(...validateUserType(config.userType));
        allErrors.push(...validateSecretKey(config.secretKey));
        allErrors.push(...validateProjectId(config.projectId));
        allErrors.push(...validateStorageKeyPrefix(config.storageKeyPrefix));
        allErrors.push(...validateSessionCookieName(config.sessionCookieName));

        // Validate key consistency (test vs live)
        allErrors.push(...this.validateKeyConsistency(config));

        // Separate errors and warnings
        const errors = allErrors.filter(e => e.severity === 'error');
        const warnings = allErrors.filter(e => e.severity === 'warning');

        return {
            isValid: errors.length === 0,
            errors,
            warnings
        };
    }

    /**
     * Validates that publishable and secret keys are consistent (both test or both live)
     */
    private validateKeyConsistency(config: FrankAuthConfig): ConfigValidationError[] {
        const errors: ConfigValidationError[] = [];

        if (!config.secretKey) {
            return errors; // Skip if no secret key provided
        }

        const pubKeyEnv = config.publishableKey.startsWith('pk_test_') ? 'test' :
            config.publishableKey.startsWith('pk_live_') ? 'live' : 'unknown';
        const secretKeyEnv = config.secretKey.startsWith('sk_test_') ? 'test' :
            config.secretKey.startsWith('sk_live_') ? 'live' : 'unknown';

        if (pubKeyEnv !== secretKeyEnv && pubKeyEnv !== 'unknown' && secretKeyEnv !== 'unknown') {
            errors.push(createError(
                'keyConsistency',
                `Publishable key (${pubKeyEnv}) and secret key (${secretKeyEnv}) environments don't match`,
                {publishableKey: pubKeyEnv, secretKey: secretKeyEnv}
            ));
        }

        return errors;
    }

    /**
     * Handles validation results - throws on errors, logs warnings
     */
    private handleValidationResult(result: ValidationResult): void {
        // Log warnings
        if (result.warnings.length > 0) {
            console.warn('Frank Auth Configuration Warnings:', result.warnings);
        }

        // Throw on errors
        if (!result.isValid) {
            const errorMessages = result.errors.map(e => `${e.field}: ${e.message}`).join('\n');
            throw new FrankAuthError(
                `Invalid Frank Auth configuration:\n${errorMessages}`,
                'INVALID_CONFIG',
                {
                    originalError: result.errors,
                }
            );
        }
    }

    /**
     * Re-validates current configuration
     */
    public revalidateConfig(): ValidationResult {
        return this.validateConfig(this._options);
    }

    /**
     * Gets the current validation result
     */
    public getValidationResult(): ValidationResult {
        return this._validationResult;
    }

    /**
     * Checks if configuration is valid
     */
    public isConfigValid(): boolean {
        return this._validationResult.isValid;
    }

    /**
     * Gets configuration warnings
     */
    public getConfigWarnings(): ConfigValidationError[] {
        return this._validationResult.warnings;
    }

    /**
     * Gets configuration errors
     */
    public getConfigErrors(): ConfigValidationError[] {
        return this._validationResult.errors;
    }

    /**
     * Validates a specific configuration field
     */
    public validateField(field: keyof FrankAuthConfig, value: any): ConfigValidationError[] {
        switch (field) {
            case 'publishableKey':
                return validatePublishableKey(value);
            case 'apiUrl':
                return validateApiUrl(value);
            case 'userType':
                return validateUserType(value);
            case 'secretKey':
                return validateSecretKey(value);
            case 'projectId':
                return validateProjectId(value);
            case 'storageKeyPrefix':
                return validateStorageKeyPrefix(value);
            case 'sessionCookieName':
                return validateSessionCookieName(value);
            default:
                return [createError(field, `Unknown configuration field: ${field}`, value)];
        }
    }

    // ================================
    // Environment & Configuration Utilities
    // ================================

    /**
     * Check if SDK is running in test mode
     */
    public isTestMode(): boolean {
        return this.options.publishableKey.startsWith('pk_test_');
    }

    /**
     * Check if SDK is running in live mode
     */
    public isLiveMode(): boolean {
        return this.options.publishableKey.startsWith('pk_live_');
    }

    /**
     * Get the current environment (test/live)
     */
    public getEnvironment(): 'test' | 'live' | 'unknown' {
        if (this.isTestMode()) return 'test';
        if (this.isLiveMode()) return 'live';
        return 'unknown';
    }

    /**
     * Check if secret key is available (server-side operations)
     */
    public hasSecretKey(): boolean {
        return !!this.options.secretKey;
    }

    /**
     * Check if project/organization ID is set
     */
    public hasProjectId(): boolean {
        return !!this.options.projectId;
    }

    /**
     * Get sanitized configuration for logging (removes sensitive data)
     */
    public getSanitizedConfig(): Partial<FrankAuthConfig> {
        return {
            apiUrl: this.options.apiUrl,
            userType: this.options.userType,
            publishableKey: this.options.publishableKey ?
                `${this.options.publishableKey.substring(0, 12)}...` : undefined,
            secretKey: this.options.secretKey ? '[REDACTED]' : undefined,
            projectId: this.options.projectId,
            storageKeyPrefix: this.options.storageKeyPrefix,
            sessionCookieName: this.options.sessionCookieName,
        };
    }


    // ================================
    // Error Handling
    // ================================

    public handleError(error: any): Promise<FrankAuthError> {
        return convertError(error)
    }


    // ================================
    // Debugging & Diagnostics
    // ================================

    /**
     * Get diagnostic information about the SDK configuration
     */
    public getDiagnostics(): {
        isConfigValid: boolean;
        environment: string;
        hasSecretKey: boolean;
        hasProjectId: boolean;
        isSignedIn: boolean;
        validationErrors: ConfigValidationError[];
        validationWarnings: ConfigValidationError[];
        sanitizedConfig: Partial<FrankAuthConfig>;
    } {
        return {
            isConfigValid: this.isConfigValid(),
            environment: this.getEnvironment(),
            hasSecretKey: this.hasSecretKey(),
            hasProjectId: this.hasProjectId(),
            isSignedIn: this.isSignedIn(),
            validationErrors: this.getConfigErrors(),
            validationWarnings: this.getConfigWarnings(),
            sanitizedConfig: this.getSanitizedConfig(),
        };
    }

    /**
     * Log diagnostic information (useful for debugging)
     */
    public logDiagnostics(): void {
        const diagnostics = this.getDiagnostics();
        console.log('Frank Auth SDK Diagnostics:', diagnostics);
    }
}