/**
 * @frank-auth/react - Verification Components Index
 *
 * Main entry point for all identity verification components.
 * Provides email verification, phone verification, and combined flows.
 */

// ============================================================================
// Email Verification Components
// ============================================================================

export {
    EmailVerification,
    EmailVerificationForm,
    EmailVerificationModal,
    EmailVerificationCard,
    EmailVerificationStatus,
    ResendEmailButton,
    type EmailVerificationProps,
    type EmailVerificationFormProps,
    type EmailVerificationModalProps,
    type EmailVerificationCardProps,
    type EmailVerificationStatusProps,
    type ResendEmailButtonProps
} from './email-verification';

// ============================================================================
// Phone Verification Components
// ============================================================================

export {
    PhoneVerification,
    PhoneVerificationForm,
    PhoneVerificationModal,
    PhoneVerificationCard,
    PhoneVerificationStatus,
    ResendSMSButton,
    type PhoneVerificationProps,
    type PhoneVerificationFormProps,
    type PhoneVerificationModalProps,
    type PhoneVerificationCardProps,
    type PhoneVerificationStatusProps,
    type ResendSMSButtonProps
} from './phone-verification';


// ============================================================================
// Common Verification Components
// ============================================================================

// export {
//     VerificationInput,
//     VerificationTimer,
//     VerificationError,
//     VerificationBadge,
//     type VerificationInputProps,
//     type VerificationTimerProps,
//     type VerificationErrorProps,
//     type VerificationBadgeProps
// } from '../common/verification';

// ============================================================================
// Verification Types
// ============================================================================

export type VerificationMethod = 'email' | 'phone' | 'both';

export type VerificationStatus =
    | 'idle'
    | 'sending'
    | 'sent'
    | 'verifying'
    | 'verified'
    | 'error'
    | 'expired';

export interface VerificationConfig {
    method: VerificationMethod;
    email?: string;
    phoneNumber?: string;
    autoSubmit?: boolean;
    codeLength?: number;
    resendDelay?: number;
    maxResendAttempts?: number;
    expirationTime?: number;
}

export interface VerificationResult {
    success: boolean;
    method: VerificationMethod;
    email?: string;
    phoneNumber?: string;
    verified: boolean;
    error?: string;
}

// ============================================================================
// Verification Events
// ============================================================================

export interface VerificationEvents {
    onCodeSent?: (method: VerificationMethod) => void;
    onCodeResent?: (method: VerificationMethod, attempt: number) => void;
    onCodeSubmitted?: (code: string, method: VerificationMethod) => void;
    onVerificationSuccess?: (result: VerificationResult) => void;
    onVerificationError?: (error: Error, method: VerificationMethod) => void;
    onExpired?: (method: VerificationMethod) => void;
}

// ============================================================================
// Base Verification Props
// ============================================================================

export interface BaseVerificationProps extends VerificationEvents {
    config?: Partial<VerificationConfig>;
    className?: string;
    style?: React.CSSProperties;
    disabled?: boolean;
}