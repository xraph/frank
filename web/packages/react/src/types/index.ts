export * from './auth';
export * from './user';
export * from './organization';
export * from './session';
export * from './config';
export * from './theme';
export * from './component';
export * from './api';
export * from './events';

// Common utility types
export type XID = string; // Frank Auth uses XID format for all IDs
export type Timestamp = string; // ISO 8601 timestamp
export type JSONValue = string | number | boolean | null | JSONObject | JSONArray;
export type JSONObject = { [key: string]: JSONValue };
export type JSONArray = JSONValue[];

// Generic API response wrapper
export interface APIResponse<T = any> {
    data: T;
    success: boolean;
    message?: string;
    errors?: Record<string, string[]>;
}

// Pagination types
export interface PaginationParams {
    page?: number;
    limit?: number;
    offset?: number;
    cursor?: string;
}

export interface PaginatedResponse<T> {
    data: T[];
    pagination: {
        page: number;
        limit: number;
        total: number;
        totalPages: number;
        hasNext: boolean;
        hasPrev: boolean;
        nextCursor?: string;
        prevCursor?: string;
    };
}

// Common status types
export type Status = 'active' | 'inactive' | 'pending' | 'suspended' | 'blocked';
export type LoadingState = 'idle' | 'loading' | 'success' | 'error';

// Error types
export interface FrankAuthError {
    code: string;
    message: string;
    details?: Record<string, any>;
    statusCode?: number;
}

// Resource identifiers
export interface ResourceIdentifier {
    id: XID;
    type: string;
}

// Audit trail
export interface AuditTrail {
    action: string;
    userId: XID;
    timestamp: Timestamp;
    metadata?: JSONObject;
    ipAddress?: string;
    userAgent?: string;
}