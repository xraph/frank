/**
 * @frank-auth/react - Error Boundary Component
 *
 * React error boundary with authentication-specific error handling,
 * organization theming, and recovery mechanisms.
 */

"use client";

import { Button, Card, CardBody, CardHeader } from "@/components/ui";
import { motion } from "framer-motion";
import React from "react";
import { useConfig } from "../../../hooks/use-config";
import { useTheme } from "../../../hooks/use-theme";

// ============================================================================
// Error Boundary Types
// ============================================================================

export interface ErrorBoundaryProps {
	/**
	 * Child components to wrap
	 */
	children: React.ReactNode;

	/**
	 * Fallback component to render on error
	 */
	fallback?: React.ComponentType<ErrorFallbackProps>;

	/**
	 * Error handler callback
	 */
	onError?: (error: Error, errorInfo: React.ErrorInfo) => void;

	/**
	 * Whether to show error details
	 */
	showDetails?: boolean;

	/**
	 * Whether to show retry button
	 */
	showRetry?: boolean;

	/**
	 * Custom retry handler
	 */
	onRetry?: () => void;

	/**
	 * Error boundary title
	 */
	title?: string;

	/**
	 * Error boundary subtitle
	 */
	subtitle?: string;

	/**
	 * Custom className
	 */
	className?: string;

	/**
	 * Whether to log errors to console
	 */
	logErrors?: boolean;

	/**
	 * Whether to report errors to external service
	 */
	reportErrors?: boolean;

	/**
	 * Error reporting endpoint
	 */
	errorReportingUrl?: string;
}

export interface ErrorFallbackProps {
	/**
	 * The error that occurred
	 */
	error: Error;

	/**
	 * Error information from React
	 */
	errorInfo: React.ErrorInfo;

	/**
	 * Function to reset the error boundary
	 */
	resetError: () => void;

	/**
	 * Whether to show error details
	 */
	showDetails?: boolean;

	/**
	 * Custom title
	 */
	title?: string;

	/**
	 * Custom subtitle
	 */
	subtitle?: string;

	/**
	 * Custom className
	 */
	className?: string;
}

interface ErrorBoundaryState {
	hasError: boolean;
	error: Error | null;
	errorInfo: React.ErrorInfo | null;
	errorId: string;
}

// ============================================================================
// Default Error Fallback Component
// ============================================================================

function DefaultErrorFallback({
	error,
	errorInfo,
	resetError,
	showDetails = false,
	title = "Something went wrong",
	subtitle = "An unexpected error occurred while processing your request.",
	className = "",
}: ErrorFallbackProps) {
	const { getColorValue } = useTheme();
	const { organizationSettings } = useConfig();

	const [showDetailsState, setShowDetailsState] = React.useState(false);

	// Error categorization
	const errorType = React.useMemo(() => {
		const message = error.message.toLowerCase();

		if (message.includes("network") || message.includes("fetch")) {
			return "network";
		}
		if (message.includes("auth") || message.includes("unauthorized")) {
			return "auth";
		}
		if (message.includes("permission") || message.includes("forbidden")) {
			return "permission";
		}
		if (message.includes("timeout")) {
			return "timeout";
		}
		return "unknown";
	}, [error.message]);

	// Error-specific messages
	const errorMessages = {
		network: {
			title: "Connection Problem",
			subtitle: "Please check your internet connection and try again.",
			action: "Retry",
		},
		auth: {
			title: "Authentication Error",
			subtitle: "Please sign in again to continue.",
			action: "Sign In",
		},
		permission: {
			title: "Access Denied",
			subtitle: "You don't have permission to access this resource.",
			action: "Go Back",
		},
		timeout: {
			title: "Request Timeout",
			subtitle: "The request took too long to complete. Please try again.",
			action: "Retry",
		},
		unknown: {
			title,
			subtitle,
			action: "Retry",
		},
	};

	const errorMessage = errorMessages[errorType];

	// Error icon based on type
	const getErrorIcon = () => {
		switch (errorType) {
			case "network":
				return (
					<svg
						className="w-12 h-12 text-warning-500"
						fill="none"
						stroke="currentColor"
						viewBox="0 0 24 24"
					>
						<path
							strokeLinecap="round"
							strokeLinejoin="round"
							strokeWidth={2}
							d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-2.5L13.732 4c-.77-.833-1.732-.833-2.5 0L4.732 16.5c-.77.833.192 2.5 1.732 2.5z"
						/>
					</svg>
				);
			case "auth":
				return (
					<svg
						className="w-12 h-12 text-danger-500"
						fill="none"
						stroke="currentColor"
						viewBox="0 0 24 24"
					>
						<path
							strokeLinecap="round"
							strokeLinejoin="round"
							strokeWidth={2}
							d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z"
						/>
					</svg>
				);
			case "permission":
				return (
					<svg
						className="w-12 h-12 text-warning-500"
						fill="none"
						stroke="currentColor"
						viewBox="0 0 24 24"
					>
						<path
							strokeLinecap="round"
							strokeLinejoin="round"
							strokeWidth={2}
							d="M18.364 18.364A9 9 0 005.636 5.636m12.728 12.728L5.636 5.636m12.728 12.728L5.636 5.636"
						/>
					</svg>
				);
			case "timeout":
				return (
					<svg
						className="w-12 h-12 text-warning-500"
						fill="none"
						stroke="currentColor"
						viewBox="0 0 24 24"
					>
						<path
							strokeLinecap="round"
							strokeLinejoin="round"
							strokeWidth={2}
							d="M12 8v4l3 3m6-3a9 9 0 11-18 0 9 9 0 0118 0z"
						/>
					</svg>
				);
			default:
				return (
					<svg
						className="w-12 h-12 text-danger-500"
						fill="none"
						stroke="currentColor"
						viewBox="0 0 24 24"
					>
						<path
							strokeLinecap="round"
							strokeLinejoin="round"
							strokeWidth={2}
							d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-2.5L13.732 4c-.77-.833-1.732-.833-2.5 0L4.732 16.5c-.77.833.192 2.5 1.732 2.5z"
						/>
					</svg>
				);
		}
	};

	return (
		<motion.div
			initial={{ opacity: 0, y: 20 }}
			animate={{ opacity: 1, y: 0 }}
			className={`flex items-center justify-center min-h-64 p-4 ${className}`}
		>
			<Card className="w-full max-w-md">
				<CardHeader className="flex flex-col items-center text-center">
					{/* Organization Logo */}
					{organizationSettings?.branding?.logoUrl && (
						<img
							src={organizationSettings.branding.logoUrl}
							alt="Logo"
							className="h-8 w-auto mb-4"
						/>
					)}

					{/* Error Icon */}
					<div className="mb-4">{getErrorIcon()}</div>

					{/* Error Title */}
					<h3 className="text-xl font-semibold text-foreground mb-2">
						{errorMessage.title}
					</h3>

					{/* Error Subtitle */}
					<p className="text-default-500 text-sm mb-4">
						{errorMessage.subtitle}
					</p>
				</CardHeader>

				<CardBody className="pt-0">
					<div className="space-y-4">
						{/* Action Buttons */}
						<div className="flex flex-col gap-2">
							<Button
								color="primary"
								variant="solid"
								size="lg"
								className="w-full"
								onPress={resetError}
							>
								{errorMessage.action}
							</Button>

							{showDetails && (
								<Button
									variant="light"
									size="sm"
									onPress={() => setShowDetailsState(!showDetailsState)}
								>
									{showDetailsState ? "Hide Details" : "Show Details"}
								</Button>
							)}
						</div>

						{/* Error Details */}
						{showDetails && showDetailsState && (
							<motion.div
								initial={{ opacity: 0, height: 0 }}
								animate={{ opacity: 1, height: "auto" }}
								exit={{ opacity: 0, height: 0 }}
								className="mt-4 p-3 bg-default-100 dark:bg-default-800 rounded-lg"
							>
								<div className="space-y-2">
									<div>
										<span className="text-xs font-medium text-default-600">
											Error Message:
										</span>
										<p className="text-xs text-default-500 mt-1 font-mono">
											{error.message}
										</p>
									</div>

									{error.stack && (
										<div>
											<span className="text-xs font-medium text-default-600">
												Stack Trace:
											</span>
											<pre className="text-xs text-default-500 mt-1 overflow-auto max-h-32 font-mono">
												{error.stack}
											</pre>
										</div>
									)}
								</div>
							</motion.div>
						)}
					</div>
				</CardBody>
			</Card>
		</motion.div>
	);
}

// ============================================================================
// Error Boundary Class Component
// ============================================================================

export class ErrorBoundary extends React.Component<
	ErrorBoundaryProps,
	ErrorBoundaryState
> {
	private retryTimeoutId: NodeJS.Timeout | null = null;

	constructor(props: ErrorBoundaryProps) {
		super(props);
		this.state = {
			hasError: false,
			error: null,
			errorInfo: null,
			errorId: "",
		};
	}

	static getDerivedStateFromError(error: Error): Partial<ErrorBoundaryState> {
		return {
			hasError: true,
			error,
			errorId: Date.now().toString(36) + Math.random().toString(36).substr(2),
		};
	}

	componentDidCatch(error: Error, errorInfo: React.ErrorInfo) {
		const {
			onError,
			logErrors = true,
			reportErrors = false,
			errorReportingUrl,
		} = this.props;

		// Update state with error info
		this.setState({
			errorInfo,
		});

		// Log error to console
		if (logErrors) {
			console.group("🚨 Error Boundary Caught Error");
			console.error("Error:", error);
			console.error("Error Info:", errorInfo);
			console.error("Component Stack:", errorInfo.componentStack);
			console.groupEnd();
		}

		// Call custom error handler
		onError?.(error, errorInfo);

		// Report error to external service
		if (reportErrors && errorReportingUrl) {
			this.reportError(error, errorInfo);
		}
	}

	private reportError = async (error: Error, errorInfo: React.ErrorInfo) => {
		const { errorReportingUrl } = this.props;

		if (!errorReportingUrl) return;

		try {
			await fetch(errorReportingUrl, {
				method: "POST",
				headers: {
					"Content-Type": "application/json",
				},
				body: JSON.stringify({
					error: {
						message: error.message,
						stack: error.stack,
						name: error.name,
					},
					errorInfo,
					errorId: this.state.errorId,
					timestamp: new Date().toISOString(),
					userAgent: navigator.userAgent,
					url: window.location.href,
				}),
			});
		} catch (reportingError) {
			console.error("Failed to report error:", reportingError);
		}
	};

	private resetError = () => {
		const { onRetry } = this.props;

		// Clear any existing retry timeout
		if (this.retryTimeoutId) {
			clearTimeout(this.retryTimeoutId);
		}

		// Reset state
		this.setState({
			hasError: false,
			error: null,
			errorInfo: null,
			errorId: "",
		});

		// Call custom retry handler
		onRetry?.();
	};

	render() {
		const { hasError, error, errorInfo } = this.state;
		const {
			children,
			fallback: Fallback = DefaultErrorFallback,
			showDetails = false,
			title,
			subtitle,
			className,
		} = this.props;

		if (hasError && error) {
			return (
				<Fallback
					error={error}
					errorInfo={errorInfo!}
					resetError={this.resetError}
					showDetails={showDetails}
					title={title}
					subtitle={subtitle}
					className={className}
				/>
			);
		}

		return children;
	}
}

// ============================================================================
// Async Error Boundary Hook
// ============================================================================

export function useAsyncError() {
	const [error, setError] = React.useState<Error | null>(null);

	const throwError = React.useCallback((error: Error) => {
		setError(error);
	}, []);

	React.useEffect(() => {
		if (error) {
			throw error;
		}
	}, [error]);

	return throwError;
}

// ============================================================================
// Error Boundary Wrapper Component
// ============================================================================

export function withErrorBoundary<P extends object>(
	Component: React.ComponentType<P>,
	errorBoundaryProps?: Partial<ErrorBoundaryProps>,
) {
	const WrappedComponent = (props: P) => (
		<ErrorBoundary {...errorBoundaryProps}>
			<Component {...props} />
		</ErrorBoundary>
	);

	WrappedComponent.displayName = `withErrorBoundary(${Component.displayName || Component.name})`;

	return WrappedComponent;
}

// ============================================================================
// Auth-Specific Error Boundaries
// ============================================================================

export function AuthErrorBoundary({
	children,
	...props
}: Omit<ErrorBoundaryProps, "title" | "subtitle">) {
	return (
		<ErrorBoundary
			title="Authentication Error"
			subtitle="There was a problem with the authentication process."
			showDetails={process.env.NODE_ENV === "development"}
			reportErrors={process.env.NODE_ENV === "production"}
			{...props}
		>
			{children}
		</ErrorBoundary>
	);
}

export function FormErrorBoundary({
	children,
	...props
}: Omit<ErrorBoundaryProps, "title" | "subtitle">) {
	return (
		<ErrorBoundary
			title="Form Error"
			subtitle="There was a problem processing your form submission."
			showDetails={process.env.NODE_ENV === "development"}
			{...props}
		>
			{children}
		</ErrorBoundary>
	);
}

export function ApiErrorBoundary({
	children,
	...props
}: Omit<ErrorBoundaryProps, "title" | "subtitle">) {
	return (
		<ErrorBoundary
			title="Service Error"
			subtitle="There was a problem connecting to our services."
			showDetails={process.env.NODE_ENV === "development"}
			reportErrors={process.env.NODE_ENV === "production"}
			{...props}
		>
			{children}
		</ErrorBoundary>
	);
}

// ============================================================================
// Export
// ============================================================================

export default ErrorBoundary;
