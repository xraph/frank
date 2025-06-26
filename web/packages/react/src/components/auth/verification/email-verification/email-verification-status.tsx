
// ============================================================================
// Email Verification Card Component
// ============================================================================

import {withErrorBoundary} from "../../common";
import type {EmailVerificationStatusProps} from "./email-verification";
import {Button as HeroButton, Chip} from "@heroui/react";
import {ArrowPathIcon, CheckCircleIcon, EnvelopeIcon, XCircleIcon} from "@heroicons/react/24/outline";
import {useConfig} from "@/hooks";


// ============================================================================
// Email Verification Status Component
// ============================================================================

export const EmailVerificationStatus = withErrorBoundary(function EmailVerificationStatus({
                                                                                              status,
                                                                                              email,
                                                                                              onRetry,
                                                                                              className
                                                                                          }: EmailVerificationStatusProps) {

    const { components } = useConfig();
    const Button = components.Button ?? HeroButton;

    const getStatusConfig = () => {
        switch (status) {
            case 'sent':
                return {
                    color: 'primary' as const,
                    icon: <EnvelopeIcon className="h-4 w-4" />,
                    message: `Verification code sent to ${email}`
                };
            case 'verified':
                return {
                    color: 'success' as const,
                    icon: <CheckCircleIcon className="h-4 w-4" />,
                    message: `Email ${email} verified successfully`
                };
            case 'error':
                return {
                    color: 'danger' as const,
                    icon: <XCircleIcon className="h-4 w-4" />,
                    message: 'Verification failed'
                };
            case 'expired':
                return {
                    color: 'warning' as const,
                    icon: <XCircleIcon className="h-4 w-4" />,
                    message: 'Verification code expired'
                };
            default:
                return {
                    color: 'default' as const,
                    icon: <EnvelopeIcon className="h-4 w-4" />,
                    message: 'Email verification'
                };
        }
    };

    const config = getStatusConfig();

    return (
        <div className={`flex items-center justify-between p-3 rounded-lg ${className || ''}`}>
            <div className="flex items-center gap-3">
                <Chip color={config.color} variant="flat" startContent={config.icon}>
                    {config.message}
                </Chip>
            </div>
            {(status === 'error' || status === 'expired') && onRetry && (
                <Button
                    size="sm"
                    color="primary"
                    variant="flat"
                    onClick={onRetry}
                    startContent={<ArrowPathIcon className="h-3 w-3" />}
                >
                    Retry
                </Button>
            )}
        </div>
    );
});
