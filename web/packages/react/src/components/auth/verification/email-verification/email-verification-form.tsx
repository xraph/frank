
// ============================================================================
// Email Verification Form Component
// ============================================================================

import React from "react";
import {EmailVerification, EmailVerificationFormProps} from "./email-verification";
import {withErrorBoundary} from "@/components";

export const EmailVerificationForm = withErrorBoundary(function EmailVerificationForm({
                                                                                          showHeader = true,
                                                                                          showInstructions = true,
                                                                                          ...props
                                                                                      }: EmailVerificationFormProps) {
    return (
        <div className="space-y-6">
            {showHeader && (
                <div className="text-center">
                    <h2 className="text-2xl font-bold">Email Verification</h2>
                    {showInstructions && (
                        <p className="text-default-500 mt-2">
                            Please verify your email address to continue
                        </p>
                    )}
                </div>
            )}
            <EmailVerification {...props} />
        </div>
    );
});
