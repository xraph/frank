/**
 * @frank-auth/react - Form Wrapper Component (Fully Optimized)
 *
 * Form container that provides validation context, error handling, and consistent
 * styling for authentication forms. Supports organization theming and customization.
 * Completely optimized to prevent ANY unnecessary re-renders.
 */

"use client";

import { Card, CardBody, CardHeader } from "@/components/ui";
import { cn } from "@/lib/utils";
import type { RadiusT, SizeT } from "@/types";
import { getTitleAlignment } from "@/utils";
import { motion } from "framer-motion";
import React, {
	createContext,
	useCallback,
	useContext,
	useMemo,
	useRef,
} from "react";
import { useConfig } from "../../hooks/use-config";
import { useTheme } from "../../hooks/use-theme";
import { FieldError } from "./field-error";

// ============================================================================
// Form Context
// ============================================================================

interface FormContextValue {
	isSubmitting: boolean;
	errors: Record<string, string | string[]>;
	touched: Record<string, boolean>;
	setFieldError: (field: string, error: string | string[] | null) => void;
	setFieldTouched: (field: string, touched?: boolean) => void;
	clearFieldError: (field: string) => void;
	clearAllErrors: () => void;
	hasErrors: boolean;
	getFieldError: (field: string) => string | string[] | null;
	getFieldTouched: (field: string) => boolean;
}

const FormContext = createContext<FormContextValue | null>(null);

// ============================================================================
// Animation Component (Defined Outside to Prevent Recreation)
// ============================================================================

const AnimatedContent = React.memo(
	({
		children,
		disableAnimations,
	}: {
		children: React.ReactNode;
		disableAnimations: boolean;
	}) => {
		if (disableAnimations) return <>{children}</>;

		return (
			<motion.div
				initial={{ opacity: 0, y: 20 }}
				animate={{ opacity: 1, y: 0 }}
				transition={{ duration: 0.3, ease: "easeOut" }}
			>
				{children}
			</motion.div>
		);
	},
);

AnimatedContent.displayName = "AnimatedContent";

// ============================================================================
// Form State Provider (Separated for Performance)
// ============================================================================

interface FormStateProviderProps {
	children: React.ReactNode;
	isSubmitting: boolean;
	initialErrors: Record<string, string | string[]>;
}

const FormStateProvider = React.memo(
	({ children, isSubmitting, initialErrors }: FormStateProviderProps) => {
		// Use refs for state that doesn't need to trigger re-renders immediately
		const errorsRef = useRef<Record<string, string | string[]>>(initialErrors);
		const touchedRef = useRef<Record<string, boolean>>({});

		// Initialize refs only once
		React.useEffect(() => {
			errorsRef.current = initialErrors;
		}, []); // Only on mount

		// Force re-render hook
		const [, forceUpdate] = React.useReducer((x) => x + 1, 0);

		// Stable callback functions that don't change on every render
		const setFieldError = useCallback(
			(field: string, fieldError: string | string[] | null) => {
				if (fieldError === null) {
					if (errorsRef.current[field] !== undefined) {
						const newErrors = { ...errorsRef.current };
						delete newErrors[field];
						errorsRef.current = newErrors;
						forceUpdate();
					}
				} else {
					if (errorsRef.current[field] !== fieldError) {
						errorsRef.current = { ...errorsRef.current, [field]: fieldError };
						forceUpdate();
					}
				}
			},
			[],
		);

		const setFieldTouched = useCallback(
			(field: string, fieldTouched = true) => {
				if (touchedRef.current[field] !== fieldTouched) {
					touchedRef.current = { ...touchedRef.current, [field]: fieldTouched };
					forceUpdate();
				}
			},
			[],
		);

		const clearFieldError = useCallback(
			(field: string) => {
				setFieldError(field, null);
			},
			[setFieldError],
		);

		const clearAllErrors = useCallback(() => {
			if (Object.keys(errorsRef.current).length > 0) {
				errorsRef.current = {};
				forceUpdate();
			}
		}, []);

		const getFieldError = useCallback((field: string) => {
			return errorsRef.current[field] || null;
		}, []);

		const getFieldTouched = useCallback((field: string) => {
			return touchedRef.current[field] || false;
		}, []);

		// Memoize the context value with minimal dependencies
		const contextValue = useMemo(
			() => ({
				isSubmitting,
				errors: errorsRef.current,
				touched: touchedRef.current,
				setFieldError,
				setFieldTouched,
				clearFieldError,
				clearAllErrors,
				hasErrors: Object.keys(errorsRef.current).length > 0,
				getFieldError,
				getFieldTouched,
			}),
			[
				isSubmitting, // Only dependency that should change
				setFieldError,
				setFieldTouched,
				clearFieldError,
				clearAllErrors,
				getFieldError,
				getFieldTouched,
				// Deliberately NOT including errorsRef.current or touchedRef.current
			],
		);

		return (
			<FormContext.Provider value={contextValue}>
				{children}
			</FormContext.Provider>
		);
	},
);

FormStateProvider.displayName = "FormStateProvider";

// ============================================================================
// Form Wrapper Interface
// ============================================================================

export interface FormWrapperProps {
	/**
	 * Form content
	 */
	children: React.ReactNode;

	/**
	 * Form title
	 */
	title?: string;

	/**
	 * Form subtitle or description
	 */
	subtitle?: string;

	desc?: React.ReactNode;

	/**
	 * Form header content (overrides title/subtitle)
	 */
	header?: React.ReactNode;

	/**
	 * Form footer content
	 */
	footer?: React.ReactNode;

	/**
	 * Whether form is currently submitting
	 */
	isSubmitting?: boolean;

	/**
	 * Global form error message
	 */
	error?: string | null;

	/**
	 * Success message
	 */
	success?: string | null;

	/**
	 * Form submission handler
	 */
	onSubmit?: (event: React.FormEvent<HTMLFormElement>) => void | Promise<void>;

	/**
	 * Initial field errors
	 */
	initialErrors?: Record<string, string | string[]>;

	/**
	 * Custom className
	 */
	className?: string;

	/**
	 * Card variant
	 */
	variant?: "default" | "bordered" | "shadow" | "flat";

	/**
	 * Card size
	 */
	size?: SizeT;
	radius?: RadiusT;

	/**
	 * Whether to show the card wrapper
	 */
	showCard?: boolean;

	/**
	 * Custom card props
	 */
	cardProps?: any;

	/**
	 * Loading state content
	 */
	loadingContent?: React.ReactNode;

	/**
	 * Organization logo
	 */
	logo?: string | React.ReactNode;

	/**
	 * Form width
	 */
	width?: "sm" | "md" | "lg" | "xl" | "full";

	/**
	 * Center the form
	 */
	centered?: boolean;

	/**
	 * Disable animations
	 */
	disableAnimations?: boolean;

	titleAlignment?: "left" | "center" | "right";
}

// ============================================================================
// Form Content Component (Memoized)
// ============================================================================

interface FormContentProps {
	children: React.ReactNode;
	footer?: React.ReactNode;
	onSubmit?: (event: React.FormEvent<HTMLFormElement>) => void | Promise<void>;
	isSubmitting: boolean;
	loadingContent?: React.ReactNode;
	width: "sm" | "md" | "lg" | "xl" | "full";
	centered: boolean;
}

const FormContent = React.memo(
	({
		children,
		footer,
		onSubmit,
		isSubmitting,
		loadingContent,
		width,
		centered,
	}: FormContentProps) => {
		const { clearAllErrors } = useFormContext();

		// Handle form submission
		const handleSubmit = useCallback(
			async (event: React.FormEvent<HTMLFormElement>) => {
				event.preventDefault();
				clearAllErrors();

				if (onSubmit) {
					try {
						await onSubmit(event);
					} catch (err) {
						// Let parent component handle the error
						console.error("Form submission error:", err);
					}
				}
			},
			[onSubmit, clearAllErrors],
		);

		// Width classes (memoized to prevent recreation)
		const widthClasses = useMemo(
			() => ({
				sm: "w-full max-w-sm",
				md: "w-full max-w-md",
				lg: "w-full max-w-lg",
				xl: "w-full max-w-xl",
				full: "w-full",
			}),
			[],
		);

		// Container className (memoized)
		const containerClassName = useMemo(
			() => `relative ${widthClasses[width]} ${centered ? "mx-auto" : ""}`,
			[widthClasses, width, centered],
		);

		// Loading overlay (memoized)
		const loadingOverlay = useMemo(() => {
			if (!isSubmitting) return null;

			return (
				<div className="absolute inset-0 bg-background/50 backdrop-blur-sm flex items-center justify-center z-50 rounded-inherit">
					{loadingContent || (
						<div className="flex items-center gap-3">
							<div className="w-6 h-6 border-2 border-primary border-t-transparent rounded-full animate-spin" />
							<span className="text-sm text-foreground">Processing...</span>
						</div>
					)}
				</div>
			);
		}, [isSubmitting, loadingContent]);

		return (
			<div className={containerClassName}>
				{/* Form */}
				<form onSubmit={handleSubmit} className="space-y-4" noValidate>
					{children}
					{footer}
				</form>

				{/* Loading Overlay */}
				{loadingOverlay}
			</div>
		);
	},
);

FormContent.displayName = "FormContent";

// ============================================================================
// Messages Component (Memoized)
// ============================================================================

interface MessagesProps {
	success?: string | null;
	error?: string | null;
	disableAnimations: boolean;
}

const Messages = React.memo(
	({ success, error, disableAnimations }: MessagesProps) => {
		// Early return if no messages
		if (!success && !error) return null;

		return (
			<>
				{/* Global Success Message */}
				{success && (
					<motion.div
						initial={disableAnimations ? false : { opacity: 0, y: -10 }}
						animate={{ opacity: 1, y: 0 }}
						className="mb-4 p-3 bg-success-50 dark:bg-success-100/10 border border-success-200 dark:border-success-800 rounded-lg"
					>
						<div className="flex items-center gap-2">
							<svg
								className="w-5 h-5 text-success-600 dark:text-success-400"
								fill="none"
								stroke="currentColor"
								viewBox="0 0 24 24"
							>
								<path
									strokeLinecap="round"
									strokeLinejoin="round"
									strokeWidth={2}
									d="M5 13l4 4L19 7"
								/>
							</svg>
							<p className="text-sm text-success-700 dark:text-success-300">
								{success}
							</p>
						</div>
					</motion.div>
				)}

				{/* Global Error Message */}
				{error && (
					<FieldError
						error={error}
						variant="default"
						className="mb-4 p-3 bg-danger-50 dark:bg-danger-100/10 border border-danger-200 dark:border-danger-800 rounded-lg"
					/>
				)}
			</>
		);
	},
);

Messages.displayName = "Messages";

// ============================================================================
// Header Component (Memoized)
// ============================================================================

interface HeaderProps {
	header?: React.ReactNode;
	title?: string;
	subtitle?: string;
	desc?: React.ReactNode;
	showCard: boolean;
	titleAlignment?: "left" | "center" | "right";
}

const Header = React.memo(
	({
		header,
		title,
		subtitle,
		showCard,
		desc,
		titleAlignment,
	}: HeaderProps) => {
		// Early return if no header content
		if (header) return <>{header}</>;
		if (!title && !subtitle) return null;

		if (!showCard) {
			return (
				<div
					className={cn(
						"flex flex-col text-center pb-2",
						getTitleAlignment(titleAlignment ?? "center"),
					)}
				>
					{title && (
						<h1 className="text-2xl font-bold text-foreground mb-2">{title}</h1>
					)}

					{subtitle && <p className="text-default-500">{subtitle}</p>}

					{desc}
				</div>
			);
		}

		return (
			<CardHeader className="flex flex-col items-center text-center pb-2">
				{title && (
					<h1 className="text-2xl font-bold text-foreground mb-2">{title}</h1>
				)}
				{subtitle && <p className="text-default-500 text-sm">{subtitle}</p>}
			</CardHeader>
		);
	},
);

Header.displayName = "Header";

// ============================================================================
// Logo Component (Memoized)
// ============================================================================

interface LogoProps {
	logo?: string | React.ReactNode;
	orgLogoUrl?: string;
}

const Logo = React.memo(({ logo, orgLogoUrl }: LogoProps) => {
	if (!logo) {
		// Use organization logo if available
		if (orgLogoUrl) {
			return (
				<img
					src={orgLogoUrl}
					alt="Organization Logo"
					className="h-8 w-auto mx-auto mb-6"
				/>
			);
		}
		return null;
	}

	if (typeof logo === "string") {
		return <img src={logo} alt="Logo" className="h-8 w-auto mx-auto mb-6" />;
	}

	return <div className="flex justify-center mb-6">{logo}</div>;
});

Logo.displayName = "Logo";

// ============================================================================
// Form Wrapper Component
// ============================================================================

export function FormWrapper({
	children,
	title,
	subtitle,
	desc,
	header,
	footer,
	isSubmitting = false,
	error,
	success,
	onSubmit,
	initialErrors = {},
	className = "",
	variant = "shadow",
	size = "md",
	showCard = true,
	cardProps = {},
	loadingContent,
	logo,
	width = "md",
	centered = true,
	disableAnimations = false,
	titleAlignment,
}: FormWrapperProps) {
	const { theme } = useTheme();
	const { components, organizationSettings } = useConfig();

	// Custom component override
	const CustomFormWrapper = components.FormWrapper;
	if (CustomFormWrapper) {
		return (
			<CustomFormWrapper
				{...{
					children,
					title,
					subtitle,
					header,
					footer,
					isSubmitting,
					error,
					success,
					onSubmit,
					initialErrors,
					className,
					variant,
					size,
					showCard,
					cardProps,
					loadingContent,
					logo,
					width,
					centered,
					disableAnimations,
				}}
			/>
		);
	}

	// Memoized components with stable props
	const logoElement = useMemo(
		() => (
			<Logo logo={logo} orgLogoUrl={organizationSettings?.branding?.logoUrl} />
		),
		[logo, organizationSettings?.branding?.logoUrl],
	);

	const headerElement = useMemo(
		() => (
			<Header
				header={header}
				title={title}
				subtitle={subtitle}
				desc={desc}
				showCard={showCard}
				titleAlignment={titleAlignment}
			/>
		),
		[header, title, subtitle, showCard, titleAlignment],
	);

	const messagesElement = useMemo(
		() => (
			<Messages
				success={success}
				error={error}
				disableAnimations={disableAnimations}
			/>
		),
		[success, error, disableAnimations],
	);

	// Memoize the form content JSX to prevent recreation
	const formContent = useMemo(
		() => (
			<FormStateProvider
				isSubmitting={isSubmitting}
				initialErrors={initialErrors}
			>
				{logoElement}
				{messagesElement}
				<FormContent
					onSubmit={onSubmit}
					isSubmitting={isSubmitting}
					loadingContent={loadingContent}
					width={width}
					centered={centered}
					footer={footer}
				>
					{children}
				</FormContent>
			</FormStateProvider>
		),
		[
			isSubmitting,
			initialErrors,
			logoElement,
			messagesElement,
			onSubmit,
			loadingContent,
			width,
			centered,
			footer,
			children,
		],
	);

	// Render without card
	if (!showCard) {
		return (
			<AnimatedContent disableAnimations={disableAnimations}>
				<div className={className}>
					{headerElement}
					<div className="pt-0">{formContent}</div>
				</div>
			</AnimatedContent>
		);
	}

	// Render with card
	return (
		<AnimatedContent disableAnimations={disableAnimations}>
			<Card variant={variant} className={className} {...cardProps}>
				{headerElement}
				<CardBody className="pt-0">{formContent}</CardBody>
			</Card>
		</AnimatedContent>
	);
}

// ============================================================================
// Form Context Hook
// ============================================================================

/**
 * Hook to access form context
 */
export function useFormContext(): FormContextValue {
	const context = useContext(FormContext);
	if (!context) {
		throw new Error("useFormContext must be used within a FormWrapper");
	}
	return context;
}

/**
 * Hook to manage individual field state (optimized to prevent unnecessary re-renders)
 */
export function useFormField(name: string) {
	const context = useFormContext();

	// Stable callback functions
	const setError = useCallback(
		(error: string | string[] | null) => {
			context.setFieldError(name, error);
		},
		[context.setFieldError, name],
	);

	const setTouched = useCallback(
		(touched = true) => {
			context.setFieldTouched(name, touched);
		},
		[context.setFieldTouched, name],
	);

	const clearError = useCallback(() => {
		context.clearFieldError(name);
	}, [context.clearFieldError, name]);

	// Memoize the return object to prevent recreating it
	return useMemo(
		() => ({
			name,
			error: context.getFieldError(name),
			touched: context.getFieldTouched(name),
			showError: context.getFieldTouched(name) && !!context.getFieldError(name),
			setError,
			setTouched,
			clearError,
			isSubmitting: context.isSubmitting,
		}),
		[
			name,
			context.getFieldError(name),
			context.getFieldTouched(name),
			setError,
			setTouched,
			clearError,
			context.isSubmitting,
		],
	);
}

// ============================================================================
// Export
// ============================================================================

export default FormWrapper;
export { FormContext };
