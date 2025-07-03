import type {FrankAuthError, JSONObject} from '../types';

// Base error classes
export class FrankAuthBaseError extends Error {
    public readonly code: string;
    public readonly statusCode?: number;
    public readonly details?: JSONObject;
    public readonly timestamp: string;
    public readonly context?: string;

    constructor(
        message: string,
        code = 'FRANK_AUTH_ERROR',
        statusCode?: number,
        details?: JSONObject,
        context?: string
    ) {
        super(message);
        this.name = 'FrankAuthError';
        this.code = code;
        this.statusCode = statusCode;
        this.details = details;
        this.timestamp = new Date().toISOString();
        this.context = context;

        // Ensure the error stack is captured correctly
        if (Error.captureStackTrace) {
            Error.captureStackTrace(this, this.constructor);
        }
    }

    toJSON(): FrankAuthError {
        return {
            code: this.code,
            message: this.message,
            details: this.details,
            statusCode: this.statusCode,
        };
    }
}

// Specific error classes
export class AuthenticationError extends FrankAuthBaseError {
    constructor(message = 'Authentication failed', details?: JSONObject) {
        super(message, 'AUTHENTICATION_ERROR', 401, details, 'authentication');
    }
}

export class AuthorizationError extends FrankAuthBaseError {
    constructor(message = 'Access denied', details?: JSONObject) {
        super(message, 'AUTHORIZATION_ERROR', 403, details, 'authorization');
    }
}

export class ValidationError extends FrankAuthBaseError {
    public readonly fieldErrors: Record<string, string[]>;

    constructor(
        message = 'Validation failed',
        fieldErrors: Record<string, string[]> = {},
        details?: JSONObject
    ) {
        super(message, 'VALIDATION_ERROR', 400, details, 'validation');
        this.fieldErrors = fieldErrors;
    }

    getFieldError(field: string): string | undefined {
        const errors = this.fieldErrors[field];
        return errors && errors.length > 0 ? errors[0] : undefined;
    }

    hasFieldError(field: string): boolean {
        return Boolean(this.fieldErrors[field]?.length);
    }

    getAllFieldErrors(): string[] {
        return Object.values(this.fieldErrors).flat();
    }
}

export class NetworkError extends FrankAuthBaseError {
    public readonly isRetryable: boolean;

    constructor(
        message = 'Network request failed',
        isRetryable = true,
        details?: JSONObject
    ) {
        super(message, 'NETWORK_ERROR', undefined, details, 'network');
        this.isRetryable = isRetryable;
    }
}

export class TimeoutError extends FrankAuthBaseError {
    constructor(message = 'Request timed out', details?: JSONObject) {
        super(message, 'TIMEOUT_ERROR', 408, details, 'timeout');
    }
}

export class RateLimitError extends FrankAuthBaseError {
    public readonly retryAfter?: number;

    constructor(
        message = 'Rate limit exceeded',
        retryAfter?: number,
        details?: JSONObject
    ) {
        super(message, 'RATE_LIMIT_ERROR', 429, details, 'rate_limit');
        this.retryAfter = retryAfter;
    }
}

export class ServerError extends FrankAuthBaseError {
    constructor(message = 'Internal server error', details?: JSONObject) {
        super(message, 'SERVER_ERROR', 500, details, 'server');
    }
}

export class ConfigurationError extends FrankAuthBaseError {
    constructor(message = 'Configuration error', details?: JSONObject) {
        super(message, 'CONFIGURATION_ERROR', undefined, details, 'configuration');
    }
}

export class SessionError extends FrankAuthBaseError {
    constructor(message = 'Session error', details?: JSONObject) {
        super(message, 'SESSION_ERROR', 401, details, 'session');
    }
}

export class MFAError extends FrankAuthBaseError {
    public readonly challenge?: any;

    constructor(
        message = 'Multi-factor authentication required',
        challenge?: any,
        details?: JSONObject
    ) {
        super(message, 'MFA_ERROR', 428, details, 'mfa');
        this.challenge = challenge;
    }
}

export class PasskeyError extends FrankAuthBaseError {
    constructor(message = 'Passkey operation failed', details?: JSONObject) {
        super(message, 'PASSKEY_ERROR', undefined, details, 'passkey');
    }
}

export class OAuthError extends FrankAuthBaseError {
    public readonly provider?: string;
    public readonly errorCode?: string;

    constructor(
        message = 'OAuth authentication failed',
        provider?: string,
        errorCode?: string,
        details?: JSONObject
    ) {
        super(message, 'OAUTH_ERROR', 400, details, 'oauth');
        this.provider = provider;
        this.errorCode = errorCode;
    }
}

export class OrganizationError extends FrankAuthBaseError {
    constructor(message = 'Organization error', details?: JSONObject) {
        super(message, 'ORGANIZATION_ERROR', 400, details, 'organization');
    }
}

export class InvitationError extends FrankAuthBaseError {
    constructor(message = 'Invitation error', details?: JSONObject) {
        super(message, 'INVITATION_ERROR', 400, details, 'invitation');
    }
}

// Error factory functions
export const createError = (
    type: string,
    message: string,
    details?: JSONObject
): FrankAuthBaseError => {
    switch (type) {
        case 'AUTHENTICATION_ERROR':
            return new AuthenticationError(message, details);
        case 'AUTHORIZATION_ERROR':
            return new AuthorizationError(message, details);
        case 'VALIDATION_ERROR':
            return new ValidationError(message, {}, details);
        case 'NETWORK_ERROR':
            return new NetworkError(message, true, details);
        case 'TIMEOUT_ERROR':
            return new TimeoutError(message, details);
        case 'RATE_LIMIT_ERROR':
            return new RateLimitError(message, undefined, details);
        case 'SERVER_ERROR':
            return new ServerError(message, details);
        case 'CONFIGURATION_ERROR':
            return new ConfigurationError(message, details);
        case 'SESSION_ERROR':
            return new SessionError(message, details);
        case 'MFA_ERROR':
            return new MFAError(message, undefined, details);
        case 'PASSKEY_ERROR':
            return new PasskeyError(message, details);
        case 'OAUTH_ERROR':
            return new OAuthError(message, undefined, undefined, details);
        case 'ORGANIZATION_ERROR':
            return new OrganizationError(message, details);
        case 'INVITATION_ERROR':
            return new InvitationError(message, details);
        default:
            return new FrankAuthBaseError(message, type, undefined, details);
    }
};

export const createAuthenticationError = (message?: string, details?: JSONObject) =>
    new AuthenticationError(message, details);

export const createAuthorizationError = (message?: string, details?: JSONObject) =>
    new AuthorizationError(message, details);

export const createValidationError = (
    message?: string,
    fieldErrors?: Record<string, string[]>,
    details?: JSONObject
) => new ValidationError(message, fieldErrors, details);

export const createNetworkError = (
    message?: string,
    isRetryable?: boolean,
    details?: JSONObject
) => new NetworkError(message, isRetryable, details);

export const createSessionError = (message?: string, details?: JSONObject) =>
    new SessionError(message, details);

export const createMFAError = (
    message?: string,
    challenge?: any,
    details?: JSONObject
) => new MFAError(message, challenge, details);

// Error type guards
export const isFrankAuthError = (error: any): error is FrankAuthBaseError => {
    return error instanceof FrankAuthBaseError ||
        (error && typeof error === 'object' && error.code && error.message);
};

export const isAuthenticationError = (error: any): error is AuthenticationError => {
    return error instanceof AuthenticationError ||
        (isFrankAuthError(error) && error.code === 'AUTHENTICATION_ERROR');
};

export const isAuthorizationError = (error: any): error is AuthorizationError => {
    return error instanceof AuthorizationError ||
        (isFrankAuthError(error) && error.code === 'AUTHORIZATION_ERROR');
};

export const isValidationError = (error: any): error is ValidationError => {
    return error instanceof ValidationError ||
        (isFrankAuthError(error) && error.code === 'VALIDATION_ERROR');
};

export const isNetworkError = (error: any): error is NetworkError => {
    return error instanceof NetworkError ||
        (isFrankAuthError(error) && error.code === 'NETWORK_ERROR');
};

export const isTimeoutError = (error: any): error is TimeoutError => {
    return error instanceof TimeoutError ||
        (isFrankAuthError(error) && error.code === 'TIMEOUT_ERROR');
};

export const isRateLimitError = (error: any): error is RateLimitError => {
    return error instanceof RateLimitError ||
        (isFrankAuthError(error) && error.code === 'RATE_LIMIT_ERROR');
};

export const isServerError = (error: any): error is ServerError => {
    return error instanceof ServerError ||
        (isFrankAuthError(error) && error.code === 'SERVER_ERROR');
};

export const isSessionError = (error: any): error is SessionError => {
    return error instanceof SessionError ||
        (isFrankAuthError(error) && error.code === 'SESSION_ERROR');
};

export const isMFAError = (error: any): error is MFAError => {
    return error instanceof MFAError ||
        (isFrankAuthError(error) && error.code === 'MFA_ERROR');
};

export const isPasskeyError = (error: any): error is PasskeyError => {
    return error instanceof PasskeyError ||
        (isFrankAuthError(error) && error.code === 'PASSKEY_ERROR');
};

export const isOAuthError = (error: any): error is OAuthError => {
    return error instanceof OAuthError ||
        (isFrankAuthError(error) && error.code === 'OAUTH_ERROR');
};

export const isRetryableError = (error: any): boolean => {
    if (isNetworkError(error)) {
        return error.isRetryable;
    }

    if (isTimeoutError(error) || isRateLimitError(error) || isServerError(error)) {
        return true;
    }

    return false;
};

// Error handling utilities
export const handleError = (
    error: any,
    context?: string,
    defaultMessage?: string
): FrankAuthBaseError => {
    if (isFrankAuthError(error)) {
        return error;
    }

    if (error instanceof Error) {
        return new FrankAuthBaseError(
            error.message || defaultMessage || 'An error occurred',
            'UNKNOWN_ERROR',
            undefined,
            { originalError: error.name },
            context
        );
    }

    if (typeof error === 'string') {
        return new FrankAuthBaseError(
            error || defaultMessage || 'An error occurred',
            'UNKNOWN_ERROR',
            undefined,
            undefined,
            context
        );
    }

    return new FrankAuthBaseError(
        defaultMessage || 'An unknown error occurred',
        'UNKNOWN_ERROR',
        undefined,
        { originalError: error },
        context
    );
};

export const parseAPIError = (response: any): FrankAuthBaseError => {
    if (!response) {
        return new ServerError('No response received');
    }

    const { status, data } = response;

    // Handle different status codes
    switch (status) {
        case 400:
            if (data?.errors) {
                return new ValidationError(
                    data.message || 'Validation failed',
                    data.errors,
                    data
                );
            }
            return new FrankAuthBaseError(
                data?.message || 'Bad request',
                'BAD_REQUEST',
                400,
                data
            );

        case 401:
            return new AuthenticationError(
                data?.message || 'Authentication required',
                data
            );

        case 403:
            return new AuthorizationError(
                data?.message || 'Access denied',
                data
            );

        case 404:
            return new FrankAuthBaseError(
                data?.message || 'Resource not found',
                'NOT_FOUND',
                404,
                data
            );

        case 408:
            return new TimeoutError(
                data?.message || 'Request timeout',
                data
            );

        case 429:
            return new RateLimitError(
                data?.message || 'Rate limit exceeded',
                data?.retryAfter,
                data
            );

        case 500:
        case 502:
        case 503:
        case 504:
            return new ServerError(
                data?.message || 'Server error',
                data
            );

        default:
            return new FrankAuthBaseError(
                data?.message || `HTTP ${status} error`,
                `HTTP_${status}`,
                status,
                data
            );
    }
};

export const formatErrorMessage = (error: any): string => {
    if (isFrankAuthError(error)) {
        return error.message;
    }

    if (error instanceof Error) {
        return error.message;
    }

    if (typeof error === 'string') {
        return error;
    }

    return 'An unknown error occurred';
};

export const getErrorCode = (error: any): string => {
    if (isFrankAuthError(error)) {
        return error.code;
    }

    if (error instanceof Error) {
        return error.name;
    }

    return 'UNKNOWN_ERROR';
};

export const getErrorDetails = (error: any): JSONObject | undefined => {
    if (isFrankAuthError(error)) {
        return error.details;
    }

    return undefined;
};

// Error logging utilities
export interface ErrorLogger {
    error(message: string, error?: any, context?: JSONObject): void;
    warn(message: string, context?: JSONObject): void;
    info(message: string, context?: JSONObject): void;
    debug(message: string, context?: JSONObject): void;
}

export const createConsoleLogger = (): ErrorLogger => ({
    error: (message, error, context) => {
        console.error(message, error, context);
    },
    warn: (message, context) => {
        console.warn(message, context);
    },
    info: (message, context) => {
        console.info(message, context);
    },
    debug: (message, context) => {
        console.debug(message, context);
    },
});

export const logError = (
    error: any,
    logger: ErrorLogger = createConsoleLogger(),
    context?: JSONObject
): void => {
    const frankError = handleError(error);

    logger.error(
        `[${frankError.code}] ${frankError.message}`,
        {
            error: frankError,
            stack: frankError.stack,
            timestamp: frankError.timestamp,
            context: frankError.context,
            ...context,
        }
    );
};

// Error retry utilities
export interface RetryOptions {
    maxAttempts: number;
    delay: number;
    backoff: 'fixed' | 'exponential' | 'linear';
    shouldRetry?: (error: any, attempt: number) => boolean;
    onRetry?: (error: any, attempt: number) => void;
}

export const withRetry = async <T>(
    operation: () => Promise<T>,
    options: Partial<RetryOptions> = {}
): Promise<T> => {
    const {
        maxAttempts = 3,
        delay = 1000,
        backoff = 'exponential',
        shouldRetry = isRetryableError,
        onRetry,
    } = options;

    let lastError: any;

    for (let attempt = 1; attempt <= maxAttempts; attempt++) {
        try {
            return await operation();
        } catch (error) {
            lastError = error;

            if (attempt === maxAttempts || !shouldRetry(error, attempt)) {
                throw handleError(error);
            }

            if (onRetry) {
                onRetry(error, attempt);
            }

            // Calculate delay based on backoff strategy
            let actualDelay = delay;
            switch (backoff) {
                case 'exponential':
                    actualDelay = delay * Math.pow(2, attempt - 1);
                    break;
                case 'linear':
                    actualDelay = delay * attempt;
                    break;
                case 'fixed':
                default:
                    actualDelay = delay;
                    break;
            }

            // Add some jitter to prevent thundering herd
            actualDelay += Math.random() * 1000;

            await new Promise(resolve => setTimeout(resolve, actualDelay));
        }
    }

    throw handleError(lastError);
};

// Error boundary helpers for React
export interface ErrorBoundaryState {
    hasError: boolean;
    error?: FrankAuthBaseError;
}

export const createErrorBoundaryState = (): ErrorBoundaryState => ({
    hasError: false,
    error: undefined,
});

export const handleErrorBoundaryError = (
    error: any,
    errorInfo?: any
): ErrorBoundaryState => ({
    hasError: true,
    error: handleError(error, 'error_boundary', 'Component error occurred'),
});

// Export utilities object
export const ErrorUtils = {
    // Error classes
    FrankAuthBaseError,
    AuthenticationError,
    AuthorizationError,
    ValidationError,
    NetworkError,
    TimeoutError,
    RateLimitError,
    ServerError,
    ConfigurationError,
    SessionError,
    MFAError,
    PasskeyError,
    OAuthError,
    OrganizationError,
    InvitationError,

    // Factory functions
    createError,
    createAuthenticationError,
    createAuthorizationError,
    createValidationError,
    createNetworkError,
    createSessionError,
    createMFAError,

    // Type guards
    isFrankAuthError,
    isAuthenticationError,
    isAuthorizationError,
    isValidationError,
    isNetworkError,
    isTimeoutError,
    isRateLimitError,
    isServerError,
    isSessionError,
    isMFAError,
    isPasskeyError,
    isOAuthError,
    isRetryableError,

    // Utilities
    handleError,
    parseAPIError,
    formatErrorMessage,
    getErrorCode,
    getErrorDetails,
    logError,
    withRetry,

    // Error boundary
    createErrorBoundaryState,
    handleErrorBoundaryError,
};