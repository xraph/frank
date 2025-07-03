/**
 * @frank-auth/react - Verification & Invitation Utilities
 *
 * Utility functions for identity verification and organization invitations.
 * Includes formatters, validators, helpers, and common operations.
 */

// import {
//     VerificationMethod,
//     VerificationStatus,
//     InvitationStatus,
//     InvitationData,
//     VerificationResult
// } from '../types';

// ============================================================================
// Phone Number Utilities
// ============================================================================

import type {VerificationMethod, VerificationStatus} from "@/types";
import type {InvitationData} from "@/components/auth/invitations";

/**
 * Format phone number for display
 */
export function formatPhoneNumber(phoneNumber: string, format: 'national' | 'international' | 'masked' = 'national'): string {
    // Remove all non-numeric characters
    const cleaned = phoneNumber.replace(/\D/g, '');

    if (format === 'masked') {
        // Mask middle digits: +1 (555) 123-4567 → +1 (555) ***-4567
        if (cleaned.length === 10) {
            return `(${cleaned.slice(0, 3)}) ***-${cleaned.slice(6)}`;
        }
        if (cleaned.length === 11 && cleaned[0] === '1') {
            return `+1 (${cleaned.slice(1, 4)}) ***-${cleaned.slice(7)}`;
        }
        return phoneNumber.replace(/\d(?=\d{4})/g, '*');
    }

    if (format === 'international') {
        if (cleaned.length === 10) {
            return `+1 (${cleaned.slice(0, 3)}) ${cleaned.slice(3, 6)}-${cleaned.slice(6)}`;
        }
        if (cleaned.length === 11 && cleaned[0] === '1') {
            return `+1 (${cleaned.slice(1, 4)}) ${cleaned.slice(4, 7)}-${cleaned.slice(7)}`;
        }
        return phoneNumber;
    }

    // National format
    if (cleaned.length === 10) {
        return `(${cleaned.slice(0, 3)}) ${cleaned.slice(3, 6)}-${cleaned.slice(6)}`;
    }

    return phoneNumber;
}

/**
 * Validate phone number
 */
export function validatePhoneNumber(phoneNumber: string): { isValid: boolean; error?: string } {
    const cleaned = phoneNumber.replace(/\D/g, '');

    if (!cleaned) {
        return { isValid: false, error: 'Phone number is required' };
    }

    if (cleaned.length < 10) {
        return { isValid: false, error: 'Phone number must be at least 10 digits' };
    }

    if (cleaned.length > 15) {
        return { isValid: false, error: 'Phone number must be less than 15 digits' };
    }

    // US phone number validation
    if (cleaned.length === 10 || (cleaned.length === 11 && cleaned[0] === '1')) {
        const areaCode = cleaned.length === 10 ? cleaned.slice(0, 3) : cleaned.slice(1, 4);

        // Check for invalid area codes
        if (areaCode[0] === '0' || areaCode[0] === '1') {
            return { isValid: false, error: 'Invalid area code' };
        }

        return { isValid: true };
    }

    return { isValid: true }; // Allow international numbers
}

/**
 * Parse phone number to extract components
 */
export function parsePhoneNumber(phoneNumber: string): {
    countryCode?: string;
    areaCode?: string;
    exchange?: string;
    number?: string;
    extension?: string;
} {
    const cleaned = phoneNumber.replace(/\D/g, '');

    if (cleaned.length === 10) {
        return {
            countryCode: '1',
            areaCode: cleaned.slice(0, 3),
            exchange: cleaned.slice(3, 6),
            number: cleaned.slice(6)
        };
    }

    if (cleaned.length === 11 && cleaned[0] === '1') {
        return {
            countryCode: '1',
            areaCode: cleaned.slice(1, 4),
            exchange: cleaned.slice(4, 7),
            number: cleaned.slice(7)
        };
    }

    // For other formats, return the full number
    return { number: cleaned };
}

// ============================================================================
// Email Utilities
// ============================================================================

/**
 * Mask email address for display
 */
export function maskEmail(email: string): string {
    const [localPart, domain] = email.split('@');
    if (!domain) return email;

    if (localPart.length <= 2) {
        return `${localPart[0]}*@${domain}`;
    }

    const maskedLocal = localPart[0] + '*'.repeat(localPart.length - 2) + localPart[localPart.length - 1];
    return `${maskedLocal}@${domain}`;
}

/**
 * Validate email address
 */
export function validateEmail(email: string): { isValid: boolean; error?: string } {
    if (!email) {
        return { isValid: false, error: 'Email is required' };
    }

    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(email)) {
        return { isValid: false, error: 'Please enter a valid email address' };
    }

    if (email.length > 254) {
        return { isValid: false, error: 'Email address is too long' };
    }

    return { isValid: true };
}

/**
 * Extract domain from email
 */
export function getEmailDomain(email: string): string | null {
    const match = email.match(/@(.+)$/);
    return match ? match[1].toLowerCase() : null;
}

/**
 * Check if email is from a disposable email provider
 */
export function isDisposableEmail(email: string): boolean {
    const domain = getEmailDomain(email);
    if (!domain) return false;

    // Common disposable email domains
    const disposableDomains = [
        '10minutemail.com',
        'guerrillamail.com',
        'tempmail.org',
        'yopmail.com',
        'mailinator.com',
        'temp-mail.org'
    ];

    return disposableDomains.includes(domain);
}

// ============================================================================
// Verification Code Utilities
// ============================================================================

/**
 * Generate verification code
 */
export function generateVerificationCode(length = 6): string {
    const digits = '0123456789';
    let code = '';

    for (let i = 0; i < length; i++) {
        code += digits[Math.floor(Math.random() * digits.length)];
    }

    return code;
}

/**
 * Validate verification code format
 */
export function validateVerificationCode(code: string, expectedLength = 6): { isValid: boolean; error?: string } {
    if (!code) {
        return { isValid: false, error: 'Verification code is required' };
    }

    if (code.length !== expectedLength) {
        return { isValid: false, error: `Verification code must be ${expectedLength} digits` };
    }

    if (!/^\d+$/.test(code)) {
        return { isValid: false, error: 'Verification code must contain only numbers' };
    }

    return { isValid: true };
}

/**
 * Format verification code for display
 */
export function formatVerificationCode(code: string, separator = ' '): string {
    return code.split('').join(separator);
}

// ============================================================================
// Time and Duration Utilities
// ============================================================================

/**
 * Format time remaining in human-readable format
 */
export function formatTimeRemaining(seconds: number): string {
    if (seconds <= 0) return '0s';

    const minutes = Math.floor(seconds / 60);
    const remainingSeconds = seconds % 60;

    if (minutes > 0) {
        return `${minutes}m ${remainingSeconds}s`;
    }

    return `${remainingSeconds}s`;
}

/**
 * Format duration in various formats
 */
export function formatDuration(seconds: number, format: 'short' | 'long' | 'digital' = 'short'): string {
    const hours = Math.floor(seconds / 3600);
    const minutes = Math.floor((seconds % 3600) / 60);
    const remainingSeconds = seconds % 60;

    switch (format) {
        case 'digital':
            if (hours > 0) {
                return `${hours.toString().padStart(2, '0')}:${minutes.toString().padStart(2, '0')}:${remainingSeconds.toString().padStart(2, '0')}`;
            }
            return `${minutes.toString().padStart(2, '0')}:${remainingSeconds.toString().padStart(2, '0')}`;

        case 'long':
            const parts = [];
            if (hours > 0) parts.push(`${hours} hour${hours !== 1 ? 's' : ''}`);
            if (minutes > 0) parts.push(`${minutes} minute${minutes !== 1 ? 's' : ''}`);
            if (remainingSeconds > 0) parts.push(`${remainingSeconds} second${remainingSeconds !== 1 ? 's' : ''}`);
            return parts.join(', ');

        default: // 'short'
            if (hours > 0) return `${hours}h ${minutes}m`;
            if (minutes > 0) return `${minutes}m ${remainingSeconds}s`;
            return `${remainingSeconds}s`;
    }
}

/**
 * Check if timestamp is expired
 */
export function isExpired(expiresAt: string | Date): boolean {
    const expiration = typeof expiresAt === 'string' ? new Date(expiresAt) : expiresAt;
    return expiration.getTime() < Date.now();
}

/**
 * Get time until expiration
 */
export function getTimeUntilExpiration(expiresAt: string | Date): number {
    const expiration = typeof expiresAt === 'string' ? new Date(expiresAt) : expiresAt;
    const now = Date.now();
    const timeRemaining = Math.max(0, Math.floor((expiration.getTime() - now) / 1000));
    return timeRemaining;
}

// ============================================================================
// Verification Status Utilities
// ============================================================================

/**
 * Get verification status display properties
 */
export function getVerificationStatusProps(status: VerificationStatus, method: VerificationMethod) {
    const methodLabel = method === 'email' ? 'Email' : method === 'phone' ? 'Phone' : 'Identity';

    switch (status) {
        case 'idle':
            return {
                color: 'default' as const,
                label: `${methodLabel} Verification`,
                description: 'Not started',
                icon: 'clock',
                canRetry: false
            };

        case 'sending':
            return {
                color: 'primary' as const,
                label: 'Sending Code',
                description: `Sending verification code to your ${method}`,
                icon: 'loading',
                canRetry: false
            };

        case 'sent':
            return {
                color: 'primary' as const,
                label: 'Code Sent',
                description: `Verification code sent to your ${method}`,
                icon: 'sent',
                canRetry: false
            };

        case 'verifying':
            return {
                color: 'primary' as const,
                label: 'Verifying',
                description: 'Verifying your code...',
                icon: 'loading',
                canRetry: false
            };

        case 'verified':
            return {
                color: 'success' as const,
                label: 'Verified',
                description: `${methodLabel} verified successfully`,
                icon: 'check',
                canRetry: false
            };

        case 'error':
            return {
                color: 'danger' as const,
                label: 'Verification Failed',
                description: 'There was an error verifying your code',
                icon: 'error',
                canRetry: true
            };

        case 'expired':
            return {
                color: 'warning' as const,
                label: 'Code Expired',
                description: 'The verification code has expired',
                icon: 'warning',
                canRetry: true
            };

        default:
            return {
                color: 'default' as const,
                label: 'Unknown',
                description: 'Unknown verification status',
                icon: 'question',
                canRetry: false
            };
    }
}

// ============================================================================
// Invitation Utilities
// ============================================================================

/**
 * Parse invitation token from URL
 */
export function parseInvitationToken(): string | null {
    if (typeof window === 'undefined') return null;

    const params = new URLSearchParams(window.location.search);
    const hash = new URLSearchParams(window.location.hash.slice(1));

    return params.get('invitation_token') ||
        params.get('invite') ||
        hash.get('invitation_token') ||
        hash.get('invite') ||
        null;
}

/**
 * Format invitation expiration
 */
export function formatInvitationExpiration(expiresAt: string | Date): {
    text: string;
    status: 'active' | 'expiring' | 'expired';
    timeRemaining: number;
} {
    const expiration = typeof expiresAt === 'string' ? new Date(expiresAt) : expiresAt;
    const now = new Date();
    const timeDiff = expiration.getTime() - now.getTime();
    const hoursRemaining = Math.ceil(timeDiff / (1000 * 60 * 60));
    const daysRemaining = Math.ceil(timeDiff / (1000 * 60 * 60 * 24));

    if (timeDiff <= 0) {
        return {
            text: 'Expired',
            status: 'expired',
            timeRemaining: 0
        };
    }

    if (hoursRemaining <= 24) {
        return {
            text: `Expires in ${hoursRemaining} hour${hoursRemaining !== 1 ? 's' : ''}`,
            status: 'expiring',
            timeRemaining: Math.floor(timeDiff / 1000)
        };
    }

    return {
        text: `Expires in ${daysRemaining} day${daysRemaining !== 1 ? 's' : ''}`,
        status: 'active',
        timeRemaining: Math.floor(timeDiff / 1000)
    };
}

/**
 * Get invitation status display properties
 */
export function getInvitationStatusProps(status: InvitationStatus) {
    switch (status) {
        case 'idle':
            return {
                color: 'default' as const,
                label: 'Invitation',
                description: 'Processing invitation...',
                icon: 'clock',
                canRetry: false
            };

        case 'validating':
            return {
                color: 'primary' as const,
                label: 'Validating',
                description: 'Validating invitation...',
                icon: 'loading',
                canRetry: false
            };

        case 'valid':
            return {
                color: 'success' as const,
                label: 'Valid Invitation',
                description: 'Invitation is valid and ready to accept',
                icon: 'check',
                canRetry: false
            };

        case 'accepting':
            return {
                color: 'primary' as const,
                label: 'Accepting',
                description: 'Accepting invitation...',
                icon: 'loading',
                canRetry: false
            };

        case 'declining':
            return {
                color: 'primary' as const,
                label: 'Declining',
                description: 'Declining invitation...',
                icon: 'loading',
                canRetry: false
            };

        case 'accepted':
            return {
                color: 'success' as const,
                label: 'Accepted',
                description: 'Invitation accepted successfully',
                icon: 'check',
                canRetry: false
            };

        case 'declined':
            return {
                color: 'default' as const,
                label: 'Declined',
                description: 'Invitation has been declined',
                icon: 'x',
                canRetry: false
            };

        case 'expired':
            return {
                color: 'warning' as const,
                label: 'Expired',
                description: 'This invitation has expired',
                icon: 'warning',
                canRetry: false
            };

        case 'invalid':
            return {
                color: 'danger' as const,
                label: 'Invalid',
                description: 'This invitation is invalid',
                icon: 'error',
                canRetry: false
            };

        case 'error':
            return {
                color: 'danger' as const,
                label: 'Error',
                description: 'An error occurred processing the invitation',
                icon: 'error',
                canRetry: true
            };

        default:
            return {
                color: 'default' as const,
                label: 'Unknown',
                description: 'Unknown invitation status',
                icon: 'question',
                canRetry: false
            };
    }
}

/**
 * Validate invitation data
 */
export function validateInvitationData(invitation: Partial<InvitationData>): { isValid: boolean; errors: string[] } {
    const errors: string[] = [];

    if (!invitation.token) {
        errors.push('Invitation token is required');
    }

    if (!invitation.email) {
        errors.push('Email is required');
    } else {
        const emailValidation = validateEmail(invitation.email);
        if (!emailValidation.isValid) {
            errors.push(emailValidation.error!);
        }
    }

    if (!invitation.organizationId) {
        errors.push('Organization ID is required');
    }

    if (!invitation.organizationName) {
        errors.push('Organization name is required');
    }

    if (!invitation.roleId) {
        errors.push('Role ID is required');
    }

    if (!invitation.roleName) {
        errors.push('Role name is required');
    }

    if (!invitation.expiresAt) {
        errors.push('Expiration date is required');
    } else if (isExpired(invitation.expiresAt)) {
        errors.push('Invitation has expired');
    }

    return {
        isValid: errors.length === 0,
        errors
    };
}

// ============================================================================
// URL and Redirect Utilities
// ============================================================================

/**
 * Clean authentication parameters from URL
 */
export function cleanAuthParams(): void {
    if (typeof window === 'undefined') return;

    const authParams = [
        'invitation_token',
        'invite',
        'verification_token',
        'verify',
        'code',
        'state',
        'error',
        'error_description'
    ];

    const url = new URL(window.location.href);
    let hasChanges = false;

    authParams.forEach(param => {
        if (url.searchParams.has(param)) {
            url.searchParams.delete(param);
            hasChanges = true;
        }
    });

    // Also clean hash parameters
    if (url.hash) {
        const hashParams = new URLSearchParams(url.hash.slice(1));
        authParams.forEach(param => {
            if (hashParams.has(param)) {
                hashParams.delete(param);
                hasChanges = true;
            }
        });

        const newHash = hashParams.toString();
        url.hash = newHash ? `#${newHash}` : '';
    }

    if (hasChanges) {
        window.history.replaceState({}, '', url.toString());
    }
}

/**
 * Build redirect URL with parameters
 */
export function buildRedirectUrl(baseUrl: string, params: Record<string, string>): string {
    const url = new URL(baseUrl, window.location.origin);

    Object.entries(params).forEach(([key, value]) => {
        if (value) {
            url.searchParams.set(key, value);
        }
    });

    return url.toString();
}

/**
 * Validate redirect URL for security
 */
export function validateRedirectUrl(redirectUrl: string, allowedDomains: string[] = []): boolean {
    try {
        const url = new URL(redirectUrl);

        // Check if it's a relative URL (same origin)
        if (url.origin === window.location.origin) {
            return true;
        }

        // Check against allowed domains
        if (allowedDomains.length > 0) {
            return allowedDomains.some(domain =>
                url.hostname === domain || url.hostname.endsWith(`.${domain}`)
            );
        }

        // By default, only allow same origin
        return false;
    } catch {
        // Invalid URL
        return false;
    }
}

// ============================================================================
// Analytics and Tracking Utilities
// ============================================================================

/**
 * Track verification event
 */
export function trackVerificationEvent(
    event: 'started' | 'code_sent' | 'code_resent' | 'verified' | 'failed',
    method: VerificationMethod,
    metadata?: Record<string, any>
) {
    const eventData = {
        event: `verification_${event}`,
        method,
        timestamp: new Date().toISOString(),
        ...metadata
    };

    // Send to analytics service
    if (typeof window !== 'undefined' && (window as any).analytics) {
        (window as any).analytics.track(eventData.event, eventData);
    }

    // Send to console in development
    if (process.env.NODE_ENV === 'development') {
        console.log('🔍 Verification Event:', eventData);
    }
}

/**
 * Track invitation event
 */
export function trackInvitationEvent(
    event: 'viewed' | 'accepted' | 'declined' | 'expired' | 'error',
    invitation?: Partial<InvitationData>,
    metadata?: Record<string, any>
) {
    const eventData = {
        event: `invitation_${event}`,
        organizationId: invitation?.organizationId,
        organizationName: invitation?.organizationName,
        roleId: invitation?.roleId,
        roleName: invitation?.roleName,
        timestamp: new Date().toISOString(),
        ...metadata
    };

    // Send to analytics service
    if (typeof window !== 'undefined' && (window as any).analytics) {
        (window as any).analytics.track(eventData.event, eventData);
    }

    // Send to console in development
    if (process.env.NODE_ENV === 'development') {
        console.log('📧 Invitation Event:', eventData);
    }
}

// ============================================================================
// Export All Utilities
// ============================================================================

export const VerificationUtils = {
    // Phone utilities
    formatPhoneNumber,
    validatePhoneNumber,
    parsePhoneNumber,

    // Email utilities
    maskEmail,
    validateEmail,
    getEmailDomain,
    isDisposableEmail,

    // Code utilities
    generateVerificationCode,
    validateVerificationCode,
    formatVerificationCode,

    // Status utilities
    getVerificationStatusProps,

    // Tracking
    trackVerificationEvent
};

export const InvitationUtils = {
    // Token utilities
    parseInvitationToken,

    // Format utilities
    formatInvitationExpiration,
    getInvitationStatusProps,

    // Validation utilities
    validateInvitationData,

    // Tracking
    trackInvitationEvent
};

export const TimeUtils = {
    formatTimeRemaining,
    formatDuration,
    isExpired,
    getTimeUntilExpiration
};

export const UrlUtils = {
    cleanAuthParams,
    buildRedirectUrl,
    validateRedirectUrl
};

export const AllUtils = {
    ...VerificationUtils,
    ...InvitationUtils,
    ...TimeUtils,
    ...UrlUtils
};