// types.ts - Update your error types
export interface ErrorDetails {
    statusCode?: number;
    field?: string;
    originalError?: any;
    headers?: Record<string, string>;
    response?: Record<string, any>;
}


// Helper method to map HTTP status codes to error codes
export function getErrorCodeFromStatus(status: number): string {
    switch (status) {
        case 400:
            return 'BAD_REQUEST';
        case 401:
            return 'UNAUTHORIZED';
        case 403:
            return 'FORBIDDEN';
        case 404:
            return 'NOT_FOUND';
        case 409:
            return 'CONFLICT';
        case 422:
            return 'UNPROCESSABLE_ENTITY';
        case 429:
            return 'TOO_MANY_REQUESTS';
        case 500:
            return 'INTERNAL_SERVER_ERROR';
        case 502:
            return 'BAD_GATEWAY';
        case 503:
            return 'SERVICE_UNAVAILABLE';
        case 504:
            return 'GATEWAY_TIMEOUT';
        default:
            return 'API_ERROR';
    }
}

export class FrankAuthError extends Error {
    public readonly code: string;
    public readonly details?: ErrorDetails;

    constructor(message: string, code: string = 'UNKNOWN_ERROR', details?: ErrorDetails) {
        super(message);
        this.name = 'FrankAuthError';
        this.code = code;
        this.details = details;
    }
}

export class FrankAuthNetworkError extends FrankAuthError {
    constructor(message: string, originalError?: any) {
        super(message, 'NETWORK_ERROR', { originalError });
        this.name = 'FrankAuthNetworkError';
    }
}



export class FrankAuthValidationError extends FrankAuthError {
    constructor(message: string, public fields?: Record<string, string[]>) {
        super(message, 'VALIDATION_ERROR', {
            statusCode: 400,
            originalError: new Error(message),
            response: {
                errors: fields,
            }
        });
        this.name = 'FrankAuthValidationError';
    }
}

// errors.ts - Enhanced error handling utilities
import {FetchError, RequiredError, ResponseError} from '@frank-auth/client';

export function isResponseError(error: any): error is ResponseError {
    return error && error.name === 'ResponseError' && error.response instanceof Response;
}

export function isFetchError(error: any): error is FetchError {
    return error && error.name === 'FetchError';
}

export function isRequiredError(error: any): error is RequiredError {
    return error && error.name === 'RequiredError';
}

export async function extractErrorBody(response: Response): Promise<any> {
    try {
        const contentType = response.headers.get('content-type') || '';

        if (contentType.includes('application/json')) {
            return await response.json();
        } else if (contentType.includes('text/')) {
            const text = await response.text();
            try {
                return JSON.parse(text);
            } catch {
                return { message: text };
            }
        } else {
            // Try to parse as JSON first, fall back to text
            const text = await response.text();
            if (text) {
                try {
                    return JSON.parse(text);
                } catch {
                    return { message: text };
                }
            }
            return { message: `HTTP ${response.status} error` };
        }
    } catch (parseError) {
        console.warn("Failed to parse error response:", parseError);
        return { message: `HTTP ${response.status} error` };
    }
}

export async function convertError(error: any): Promise<FrankAuthError> {
    // Handle ResponseError from OpenAPI Generator CLI
    if (isResponseError(error)) {
        const response = error.response;
        const status = response.status;

        // Clone response to avoid "body already read" error
        const responseClone = response.clone();
        const errorData = await extractErrorBody(responseClone);

        // Extract headers for debugging
        const headers: Record<string, string> = {};
        response.headers.forEach((value, key) => {
            headers[key] = value;
        });

        // Handle specific error cases
        if (status === 400 && errorData?.errors) {
            return new FrankAuthError(
                errorData.message || 'Validation error',
                'VALIDATION_ERROR',
                {
                    statusCode: status,
                    originalError: errorData,
                    headers
                }
            );
        }

        if (status === 401) {
            return new FrankAuthError(
                errorData?.message || 'Authentication required',
                'UNAUTHORIZED',
                {
                    statusCode: status,
                    originalError: errorData,
                    headers
                }
            );
        }

        if (status === 403) {
            return new FrankAuthError(
                errorData?.message || 'Access forbidden',
                'FORBIDDEN',
                {
                    statusCode: status,
                    originalError: errorData,
                    headers
                }
            );
        }

        return new FrankAuthError(
            errorData?.message || `HTTP ${status} error`,
            errorData?.code || getErrorCodeFromStatus(status),
            {
                statusCode: status,
                originalError: errorData,
                headers
            }
        );
    }

    // Handle FetchError from OpenAPI Generator CLI
    if (isFetchError(error)) {
        return new FrankAuthNetworkError(
            error.cause?.message || 'Network error occurred',
            error
        );
    }

    // Handle RequiredError from OpenAPI Generator CLI
    if (isRequiredError(error)) {
        return new FrankAuthError(
            `Required field missing: ${error.field}`,
            'REQUIRED_FIELD_ERROR',
            {
                field: error.field,
                originalError: error
            }
        );
    }

    // Handle standard network errors
    if (error.name === 'TypeError' || error.message?.includes('fetch')) {
        return new FrankAuthNetworkError('Network error occurred', error);
    }

    // Handle other errors
    return new FrankAuthError(
        error.message || 'Unknown error occurred',
        'UNKNOWN_ERROR',
        { originalError: error }
    );
}

export async function handleError(error: any): Promise<FrankAuthError> {
    return convertError(error);
}

// Utility function to check if an error is retryable
export function isRetryableError(error: FrankAuthError): boolean {
    if (error instanceof FrankAuthNetworkError) {
        return true;
    }

    if (error.details?.statusCode) {
        const status = error.details.statusCode;
        // Retry on 5xx errors, 429 (rate limit), and 408 (timeout)
        return status >= 500 || status === 429 || status === 408;
    }

    return false;
}

// Utility to get user-friendly error messages
export function getUserFriendlyErrorMessage(error: FrankAuthError): string {
    switch (error.code) {
        case 'UNAUTHORIZED':
            return 'Please sign in to continue';
        case 'FORBIDDEN':
            return 'You do not have permission to perform this action';
        case 'VALIDATION_ERROR':
            return 'Please check your input and try again';
        case 'NETWORK_ERROR':
            return 'Network error. Please check your connection and try again';
        case 'REQUIRED_FIELD_ERROR':
            return `Required field: ${error.details?.field || 'unknown'}`;
        case 'TOO_MANY_REQUESTS':
            return 'Too many requests. Please wait a moment before trying again';
        default:
            return error.message || 'An unexpected error occurred';
    }
}