/**
 * @frank-auth/react - Forgot Password and Reset Password Components
 *
 * Components for password recovery flow including forgot password request
 * and password reset with token verification.
 */

"use client";

import React, { useCallback, useEffect, useMemo, useState } from "react";
import { Button as HButton, Divider, Link, Spinner } from "@heroui/react";
import { motion } from "framer-motion";
import {
  ArrowLeftIcon,
  CheckCircleIcon,
  EnvelopeIcon,
  ExclamationTriangleIcon,
  KeyIcon,
} from "@heroicons/react/24/outline";

import { useAuth } from "../../../hooks/use-auth";
import { useConfig } from "../../../hooks/use-config";
import { useMagicLink } from "../../../hooks/use-magic-link";
import FormWrapper from "../../forms/form-wrapper";
import EmailField from "../../forms/email-field";
import PasswordField from "../../forms/password-field";
import type { RadiusT, SizeT } from "../../../types";

// ============================================================================
// Forgot Password Types
// ============================================================================

export interface ForgotPasswordProps {
  /**
   * Initial email value
   */
  email?: string;

  /**
   * Success callback
   */
  onSuccess?: (email: string) => void;

  /**
   * Error callback
   */
  onError?: (error: Error) => void;

  /**
   * Custom title
   */
  title?: string;

  /**
   * Custom subtitle
   */
  subtitle?: string;

  /**
   * Redirect URL for reset link
   */
  redirectUrl?: string;

  /**
   * Component variant
   */
  variant?: "default" | "card" | "modal";

  /**
   * Size
   */
  size?: SizeT;

  /**
   * Radius
   */
  radius?: RadiusT;

  /**
   * Custom className
   */
  className?: string;

  /**
   * Show back to sign in link
   */
  showBackLink?: boolean;

  /**
   * Organization ID for branded reset
   */
  organizationId?: string;
}

// ============================================================================
// Reset Password Types
// ============================================================================

export interface ResetPasswordProps {
  /**
   * Reset token (if not in URL)
   */
  token?: string;

  /**
   * Success callback
   */
  onSuccess?: (result: any) => void;

  /**
   * Error callback
   */
  onError?: (error: Error) => void;

  /**
   * Custom title
   */
  title?: string;

  /**
   * Custom subtitle
   */
  subtitle?: string;

  /**
   * Redirect URL after success
   */
  redirectUrl?: string;

  /**
   * Component variant
   */
  variant?: "default" | "card" | "modal";

  /**
   * Size
   */
  size?: SizeT;

  /**
   * Radius
   */
  radius?: RadiusT;

  /**
   * Custom className
   */
  className?: string;

  /**
   * Auto-verify token on mount
   */
  autoVerify?: boolean;

  /**
   * Password requirements
   */
  passwordRequirements?: {
    minLength?: number;
    requireUppercase?: boolean;
    requireLowercase?: boolean;
    requireNumbers?: boolean;
    requireSymbols?: boolean;
  };
}

// ============================================================================
// Password Strength Checker
// ============================================================================

const PasswordStrengthIndicator = React.memo(
  ({
    password,
    requirements = {
      minLength: 8,
      requireUppercase: true,
      requireLowercase: true,
      requireNumbers: true,
      requireSymbols: false,
    },
  }: {
    password: string;
    requirements?: {
      minLength?: number;
      requireUppercase?: boolean;
      requireLowercase?: boolean;
      requireNumbers?: boolean;
      requireSymbols?: boolean;
    };
  }) => {
    const checks = useMemo(() => {
      const results = [];

      if (requirements.minLength) {
        results.push({
          label: `At least ${requirements.minLength} characters`,
          passed: password.length >= requirements.minLength,
        });
      }

      if (requirements.requireUppercase) {
        results.push({
          label: "One uppercase letter",
          passed: /[A-Z]/.test(password),
        });
      }

      if (requirements.requireLowercase) {
        results.push({
          label: "One lowercase letter",
          passed: /[a-z]/.test(password),
        });
      }

      if (requirements.requireNumbers) {
        results.push({
          label: "One number",
          passed: /\d/.test(password),
        });
      }

      if (requirements.requireSymbols) {
        results.push({
          label: "One special character",
          passed: /[!@#$%^&*(),.?":{}|<>]/.test(password),
        });
      }

      return results;
    }, [password, requirements]);

    const passedCount = checks.filter((check) => check.passed).length;
    const strength = Math.round((passedCount / checks.length) * 100);

    const getStrengthColor = () => {
      if (strength < 40) return "bg-danger-500";
      if (strength < 70) return "bg-warning-500";
      return "bg-success-500";
    };

    const getStrengthText = () => {
      if (strength < 40) return "Weak";
      if (strength < 70) return "Medium";
      return "Strong";
    };

    return (
      <div className="space-y-3">
        {/* Strength Bar */}
        <div className="space-y-2">
          <div className="flex justify-between text-sm">
            <span className="text-default-600">Password strength</span>
            <span
              className={`font-medium ${
                strength < 40
                  ? "text-danger-600"
                  : strength < 70
                    ? "text-warning-600"
                    : "text-success-600"
              }`}
            >
              {getStrengthText()}
            </span>
          </div>
          <div className="w-full bg-default-200 rounded-full h-2">
            <motion.div
              className={`h-2 rounded-full ${getStrengthColor()}`}
              initial={{ width: 0 }}
              animate={{ width: `${strength}%` }}
              transition={{ duration: 0.3 }}
            />
          </div>
        </div>

        {/* Requirements Checklist */}
        <div className="space-y-1">
          {checks.map((check, index) => (
            <div key={index} className="flex items-center gap-2 text-sm">
              <CheckCircleIcon
                className={`w-4 h-4 ${
                  check.passed ? "text-success-600" : "text-default-300"
                }`}
              />
              <span
                className={
                  check.passed
                    ? "text-success-700 dark:text-success-400"
                    : "text-default-500"
                }
              >
                {check.label}
              </span>
            </div>
          ))}
        </div>
      </div>
    );
  },
);

PasswordStrengthIndicator.displayName = "PasswordStrengthIndicator";

// ============================================================================
// Forgot Password Component
// ============================================================================

export function ForgotPassword({
  email: initialEmail = "",
  onSuccess,
  onError,
  title = "Forgot Password",
  subtitle = "Enter your email address and we'll send you a link to reset your password.",
  redirectUrl,
  variant = "default",
  size = "md",
  radius = "md",
  className = "",
  showBackLink = true,
  organizationId,
}: ForgotPasswordProps) {
  const { isValidEmail } = useMagicLink();
  const { requestPasswordReset, isLoading } = useAuth();
  const { components, linksPath } = useConfig();

  const [email, setEmail] = useState(initialEmail);
  const [sent, setSent] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const Button = components.Button ?? HButton;

  // Handle form submission
  const handleSubmit = useCallback(
    async (e: React.FormEvent) => {
      e.preventDefault();
      setError(null);

      if (!email) {
        setError("Please enter your email address");
        return;
      }

      if (!isValidEmail(email)) {
        setError("Please enter a valid email address");
        return;
      }

      try {
        // Get the origin URL, fallback to relative path if window is not available
        const getResetUrl = () => {
          if (redirectUrl) return redirectUrl;

          if (typeof window !== "undefined") {
            return `${window.location.origin}/auth/reset-password`;
          }

          // Fallback for SSR - use relative path
          return "/auth/reset-password";
        };

        const resetUrl = getResetUrl();

        const result = await requestPasswordReset({
          email,
          redirectUrl: resetUrl,
          // organizationId,
        });

        if (result.success) {
          setSent(true);
          onSuccess?.(email);
        } else {
          setError(result.error || "Failed to send reset link");
          onError?.(new Error(result.error || "Failed to send reset link"));
        }
      } catch (err) {
        const errorMessage =
          err instanceof Error ? err.message : "Failed to send reset link";
        setError(errorMessage);
        onError?.(err instanceof Error ? err : new Error(errorMessage));
      }
    },
    [
      email,
      isValidEmail,
      requestPasswordReset,
      redirectUrl,
      organizationId,
      onSuccess,
      onError,
    ],
  );

  // Handle resend
  const handleResend = useCallback(async () => {
    setSent(false);
    setError(null);
  }, []);

  // Form wrapper props
  const formWrapperProps = useMemo(
    () => ({
      size,
      variant: "flat" as const,
      className: `space-y-6 ${className}`,
      title,
      subtitle: sent ? undefined : subtitle,
      showCard: variant === "card",
    }),
    [size, className, title, subtitle, variant, sent],
  );

  // Success state
  if (sent) {
    return (
      <FormWrapper {...formWrapperProps}>
        <div className="text-center space-y-4">
          <motion.div
            initial={{ scale: 0 }}
            animate={{ scale: 1 }}
            className="mx-auto w-16 h-16 rounded-full bg-success-100 dark:bg-success-900/30 flex items-center justify-center"
          >
            <EnvelopeIcon className="w-8 h-8 text-success-600" />
          </motion.div>

          <div>
            <h3 className="text-xl font-semibold text-foreground mb-2">
              Check Your Email
            </h3>
            <p className="text-default-500 text-sm">
              We've sent a password reset link to <strong>{email}</strong>
            </p>
          </div>

          <div className="space-y-3">
            <p className="text-sm text-default-400">
              Didn't receive the email? Check your spam folder.
            </p>

            <Button variant="light" size="sm" onPress={handleResend}>
              Send Another Email
            </Button>
          </div>

          {showBackLink && (
            <>
              <Divider className="my-4" />
              <Link
                href={linksPath?.signIn || "/auth/sign-in"}
                className="flex items-center justify-center gap-2 text-sm"
              >
                <ArrowLeftIcon className="w-4 h-4" />
                Back to Sign In
              </Link>
            </>
          )}
        </div>
      </FormWrapper>
    );
  }

  return (
    <FormWrapper {...formWrapperProps} onSubmit={handleSubmit}>
      <div className="space-y-4">
        <EmailField
          label="Email Address"
          name="email"
          placeholder="Enter your email address"
          value={email}
          onChange={setEmail}
          startContent={<EnvelopeIcon className="w-4 h-4 text-default-400" />}
          size={size}
          radius={radius}
          required
          disabled={isLoading}
          variant="bordered"
          autoFocus
        />

        {error && (
          <div className="text-danger-600 text-sm bg-danger-50 dark:bg-danger-900/20 rounded-lg p-3">
            {error}
          </div>
        )}

        <Button
          type="submit"
          color="primary"
          size={size}
          radius={radius}
          className="w-full"
          isLoading={isLoading}
          isDisabled={!email || isLoading}
        >
          {isLoading ? "Sending..." : "Send Reset Link"}
        </Button>

        {showBackLink && (
          <>
            <Divider className="my-4" />
            <div className="text-center">
              <Link
                href={linksPath?.signIn || "/auth/sign-in"}
                className="flex items-center justify-center gap-2 text-sm"
              >
                <ArrowLeftIcon className="w-4 h-4" />
                Back to Sign In
              </Link>
            </div>
          </>
        )}
      </div>
    </FormWrapper>
  );
}

// ============================================================================
// Reset Password Component
// ============================================================================

export function ResetPassword({
  token,
  onSuccess,
  onError,
  title = "Reset Password",
  subtitle = "Enter your new password below.",
  redirectUrl = "/auth/sign-in",
  variant = "default",
  size = "md",
  radius = "md",
  className = "",
  autoVerify = true,
  passwordRequirements = {
    minLength: 8,
    requireUppercase: true,
    requireLowercase: true,
    requireNumbers: true,
    requireSymbols: false,
  },
}: ResetPasswordProps) {
  const { signIn, validateToken } = useAuth();
  const { components, linksPath } = useConfig();
  const { extractTokenFromUrl } = useMagicLink();
  const { resetPassword } = useAuth();

  const [password, setPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [tokenStatus, setTokenStatus] = useState<
    "idle" | "verifying" | "valid" | "invalid"
  >("idle");
  const [resetToken, setResetToken] = useState<string | null>(null);

  const Button = components.Button ?? HButton;

  // Extract token from URL or use provided token
  const recoveryToken = useMemo(() => {
    return token || extractTokenFromUrl();
  }, [token, extractTokenFromUrl]);

  // Verify token on mount
  useEffect(() => {
    if (autoVerify && tokenStatus === "idle") {
      verifyResetToken();
    }
  }, [autoVerify, recoveryToken, tokenStatus]);

  // Verify reset token
  const verifyResetToken = useCallback(async () => {
    if (!recoveryToken) {
      setTokenStatus("invalid");
      setError("No reset token found in URL");
      return;
    }

    try {
      setTokenStatus("verifying");
      setError(null);

      const result = await validateToken({
        token: recoveryToken,
        type: "password",
      });

      if (result.success) {
        setTokenStatus("valid");
        setResetToken(recoveryToken);
      } else {
        setTokenStatus("invalid");
        setError(result.error || "Invalid or expired reset link");
      }
    } catch (err) {
      setTokenStatus("invalid");
      const errorMessage =
        err instanceof Error ? err.message : "Failed to verify reset token";
      setError(errorMessage);
      onError?.(err instanceof Error ? err : new Error(errorMessage));
    }
  }, [recoveryToken, validateToken, onError]);

  // Validate password
  const isPasswordValid = useMemo(() => {
    const checks = [];

    if (passwordRequirements.minLength) {
      checks.push(password.length >= passwordRequirements.minLength);
    }

    if (passwordRequirements.requireUppercase) {
      checks.push(/[A-Z]/.test(password));
    }

    if (passwordRequirements.requireLowercase) {
      checks.push(/[a-z]/.test(password));
    }

    if (passwordRequirements.requireNumbers) {
      checks.push(/\d/.test(password));
    }

    if (passwordRequirements.requireSymbols) {
      checks.push(/[!@#$%^&*(),.?":{}|<>]/.test(password));
    }

    return checks.every((check) => check);
  }, [password, passwordRequirements]);

  // Handle form submission
  const handleSubmit = useCallback(
    async (e: React.FormEvent) => {
      e.preventDefault();
      setError(null);

      if (!password || !confirmPassword) {
        setError("Please fill in all fields");
        return;
      }

      if (password !== confirmPassword) {
        setError("Passwords do not match");
        return;
      }

      if (!isPasswordValid) {
        setError("Password does not meet requirements");
        return;
      }

      if (!resetToken) {
        setError("Invalid reset token");
        return;
      }

      try {
        setIsLoading(true);

        // Here you would call your reset password API
        // For now, we'll simulate with the auth hook
        const result = await resetPassword({
          token: resetToken,
          newPassword: password,
        });

        if (result.status === "complete" && result.user) {
          onSuccess?.(result);

          // Redirect after successful reset
          setTimeout(() => {
            if (typeof window !== "undefined") {
              window.location.href = redirectUrl;
            }
          }, 2000);
        } else {
          setError(result.error?.message || "Failed to reset password");
        }
      } catch (err) {
        const errorMessage =
          err instanceof Error ? err.message : "Failed to reset password";
        setError(errorMessage);
        onError?.(err instanceof Error ? err : new Error(errorMessage));
      } finally {
        setIsLoading(false);
      }
    },
    [
      password,
      confirmPassword,
      isPasswordValid,
      resetToken,
      resetPassword,
      onSuccess,
      onError,
      redirectUrl,
    ],
  );

  // Form wrapper props
  const formWrapperProps = useMemo(
    () => ({
      size,
      variant: "flat" as const,
      className: `space-y-6 ${className}`,
      title,
      subtitle: tokenStatus === "valid" ? subtitle : undefined,
      showCard: variant === "card",
    }),
    [size, className, title, subtitle, variant, tokenStatus],
  );

  // Token verification loading
  if (tokenStatus === "verifying") {
    return (
      <FormWrapper {...formWrapperProps}>
        <div className="text-center space-y-4">
          <Spinner size="lg" />
          <div>
            <h3 className="text-xl font-semibold text-foreground mb-2">
              Verifying Reset Link
            </h3>
            <p className="text-default-500 text-sm">
              Please wait while we verify your reset link...
            </p>
          </div>
        </div>
      </FormWrapper>
    );
  }

  // Invalid token
  if (tokenStatus === "invalid") {
    return (
      <FormWrapper {...formWrapperProps}>
        <div className="text-center space-y-4">
          <motion.div
            initial={{ scale: 0 }}
            animate={{ scale: 1 }}
            className="mx-auto w-16 h-16 rounded-full bg-danger-100 dark:bg-danger-900/30 flex items-center justify-center"
          >
            <ExclamationTriangleIcon className="w-8 h-8 text-danger-600" />
          </motion.div>

          <div>
            <h3 className="text-xl font-semibold text-foreground mb-2">
              Invalid Reset Link
            </h3>
            <p className="text-default-500 text-sm">
              {error || "This password reset link is invalid or has expired."}
            </p>
          </div>

          <div className="space-y-3">
            <Button
              as={Link}
              href={linksPath?.forgotPassword || "/auth/forgot-password"}
              color="primary"
            >
              Request New Reset Link
            </Button>

            <div className="text-center">
              <Link
                href={linksPath?.signIn || "/auth/sign-in"}
                className="text-sm flex items-center justify-center gap-2"
              >
                <ArrowLeftIcon className="w-4 h-4" />
                Back to Sign In
              </Link>
            </div>
          </div>
        </div>
      </FormWrapper>
    );
  }

  // Reset password form
  return (
    <FormWrapper {...formWrapperProps} onSubmit={handleSubmit}>
      <div className="space-y-4">
        <PasswordField
          label="New Password"
          name="password"
          placeholder="Enter your new password"
          value={password}
          onChange={setPassword}
          startContent={<KeyIcon className="w-4 h-4 text-default-400" />}
          size={size}
          radius={radius}
          required
          disabled={isLoading}
          variant="bordered"
          autoFocus
        />

        {password && (
          <PasswordStrengthIndicator
            password={password}
            requirements={passwordRequirements}
          />
        )}

        <PasswordField
          label="Confirm Password"
          name="confirmPassword"
          placeholder="Confirm your new password"
          value={confirmPassword}
          onChange={setConfirmPassword}
          startContent={<KeyIcon className="w-4 h-4 text-default-400" />}
          size={size}
          radius={radius}
          required
          disabled={isLoading}
          variant="bordered"
        />

        {error && (
          <div className="text-danger-600 text-sm bg-danger-50 dark:bg-danger-900/20 rounded-lg p-3">
            {error}
          </div>
        )}

        <Button
          type="submit"
          color="primary"
          size={size}
          radius={radius}
          className="w-full"
          isLoading={isLoading}
          isDisabled={
            !password || !confirmPassword || !isPasswordValid || isLoading
          }
        >
          {isLoading ? "Resetting..." : "Reset Password"}
        </Button>

        <Divider className="my-4" />

        <div className="text-center">
          <Link
            href={linksPath?.signIn || "/auth/sign-in"}
            className="text-sm flex items-center justify-center gap-2"
          >
            <ArrowLeftIcon className="w-4 h-4" />
            Back to Sign In
          </Link>
        </div>
      </div>
    </FormWrapper>
  );
}

// ============================================================================
// Component Variants
// ============================================================================

/**
 * Forgot Password Card
 */
export function ForgotPasswordCard(
  props: Omit<ForgotPasswordProps, "variant">,
) {
  return <ForgotPassword {...props} variant="card" />;
}

/**
 * Reset Password Card
 */
export function ResetPasswordCard(props: Omit<ResetPasswordProps, "variant">) {
  return <ResetPassword {...props} variant="card" />;
}

// ============================================================================
// Export
// ============================================================================

export { ForgotPassword as default };
