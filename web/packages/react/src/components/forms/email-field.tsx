/**
 * @frank-auth/react - Email Field Component
 *
 * Email input field with comprehensive validation, domain suggestions,
 * and organization-specific email requirements for multi-tenant authentication.
 */

"use client";

import type { FieldProps } from "@/components/forms/shared";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import {
	Chip,
	Listbox,
	ListboxItem,
	Popover,
	PopoverContent,
	PopoverTrigger,
} from "@heroui/react";
import { AnimatePresence, motion } from "framer-motion";
import React from "react";
import { useConfig } from "../../hooks/use-config";
import { FieldError } from "./field-error";
import { useFormField } from "./form-wrapper";

// ============================================================================
// Email Field Interface
// ============================================================================

export interface EmailFieldProps extends FieldProps<string> {
	/**
	 * Whether to show domain suggestions
	 */
	showSuggestions?: boolean;

	/**
	 * Whether to validate email format
	 */
	validateFormat?: boolean;

	/**
	 * Whether to validate domain
	 */
	validateDomain?: boolean;

	/**
	 * Custom allowed domains (for organization restrictions)
	 */
	allowedDomains?: string[];

	/**
	 * Custom blocked domains
	 */
	blockedDomains?: string[];

	/**
	 * Field variant
	 */
	variant?: "flat" | "bordered" | "underlined" | "faded";

	/**
	 * Custom className
	 */
	className?: string;

	/**
	 * Auto focus
	 */
	autoFocus?: boolean;

	/**
	 * Auto complete
	 */
	autoComplete?: string;

	/**
	 * Custom validation error
	 */
	error?: string | string[];

	/**
	 * Help text
	 */
	description?: string;

	/**
	 * Whether to show verification status
	 */
	showVerificationStatus?: boolean;

	/**
	 * Whether email is verified
	 */
	isVerified?: boolean;

	/**
	 * Verification handler
	 */
	onRequestVerification?: () => void;
}

// ============================================================================
// Email Validation Types
// ============================================================================

export interface EmailValidation {
	isValid: boolean;
	errors: string[];
	suggestions: string[];
	domain: string | null;
	username: string | null;
}

// ============================================================================
// Common Email Domains
// ============================================================================

const commonDomains = [
	"gmail.com",
	"yahoo.com",
	"hotmail.com",
	"outlook.com",
	"icloud.com",
	"aol.com",
	"live.com",
	"msn.com",
	"me.com",
	"mail.com",
	"protonmail.com",
	"yandex.com",
	"zoho.com",
	"fastmail.com",
];

const commonMisspellings = {
	"gmial.com": "gmail.com",
	"gmai.com": "gmail.com",
	"gmil.com": "gmail.com",
	"yahho.com": "yahoo.com",
	"yaho.com": "yahoo.com",
	"hotmial.com": "hotmail.com",
	"hotmil.com": "hotmail.com",
	"outlok.com": "outlook.com",
	"outloo.com": "outlook.com",
};

// ============================================================================
// Email Validation Functions
// ============================================================================

function validateEmail(
	email: string,
	options: {
		validateFormat?: boolean;
		validateDomain?: boolean;
		allowedDomains?: string[];
		blockedDomains?: string[];
	} = {},
): EmailValidation {
	const {
		validateFormat = true,
		validateDomain = false,
		allowedDomains = [],
		blockedDomains = [],
	} = options;

	const errors: string[] = [];
	const suggestions: string[] = [];
	let domain: string | null = null;
	let username: string | null = null;

	// Basic format validation
	if (validateFormat) {
		const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
		if (!emailRegex.test(email)) {
			errors.push("Please enter a valid email address");
		}
	}

	// Extract domain and username
	const emailParts = email.split("@");
	if (emailParts.length === 2) {
		username = emailParts[0];
		domain = emailParts[1].toLowerCase();

		// Check for domain misspellings
		if (domain && commonMisspellings[domain]) {
			suggestions.push(
				`Did you mean ${username}@${commonMisspellings[domain]}?`,
			);
		}

		// Domain validation
		if (validateDomain && domain) {
			// Check allowed domains
			if (allowedDomains.length > 0 && !allowedDomains.includes(domain)) {
				errors.push(
					`Email must be from one of these domains: ${allowedDomains.join(", ")}`,
				);
			}

			// Check blocked domains
			if (blockedDomains.includes(domain)) {
				errors.push("This email domain is not allowed");
			}

			// Basic domain format check
			if (!/^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/.test(domain)) {
				errors.push("Invalid email domain");
			}
		}

		// Generate suggestions for incomplete domains
		if (username && domain && domain.length > 0 && !domain.includes(".")) {
			const matchingDomains = commonDomains.filter((d) =>
				d.toLowerCase().startsWith(domain.toLowerCase()),
			);
			matchingDomains.slice(0, 3).forEach((d) => {
				suggestions.push(`${username}@${d}`);
			});
		}
	}

	return {
		isValid: errors.length === 0,
		errors,
		suggestions,
		domain,
		username,
	};
}

// ============================================================================
// Email Field Component
// ============================================================================

export function EmailField({
	name = "email",
	label = "Email",
	placeholder = "Enter your email address",
	value = "",
	onChange,
	onBlur,
	onFocus,
	required = false,
	disabled = false,
	showSuggestions = true,
	validateFormat = true,
	validateDomain = false,
	allowedDomains = [],
	blockedDomains = [],
	size = "md",
	radius = "md",
	variant = "bordered",
	className = "",
	autoFocus = false,
	autoComplete = "email",
	error: externalError,
	description,
	showVerificationStatus = false,
	isVerified = false,
	onRequestVerification,
	startContent,
	endContent,
}: EmailFieldProps) {
	const { components, organizationSettings } = useConfig();
	const formField = useFormField(name);

	// Custom component override
	const RootInput = React.useMemo(
		() => components.Input ?? Input,
		[components.Input],
	);
	const CustomEmailField = components.EmailField;
	if (CustomEmailField) {
		return (
			<CustomEmailField
				{...{
					name,
					label,
					placeholder,
					value,
					onChange,
					onBlur,
					onFocus,
					required,
					disabled,
					showSuggestions,
					validateFormat,
					validateDomain,
					allowedDomains,
					blockedDomains,
					size,
					variant,
					className,
					autoFocus,
					autoComplete,
					error: externalError,
					description,
					showVerificationStatus,
					isVerified,
					onRequestVerification,
					startContent,
					endContent,
				}}
			/>
		);
	}

	// State
	const [internalValue, setInternalValue] = React.useState(value);
	const [isFocused, setIsFocused] = React.useState(false);
	const [showSuggestionPopover, setShowSuggestionPopover] =
		React.useState(false);

	// Use external value if controlled
	const currentValue = onChange ? value : internalValue;

	// Apply organization email restrictions if available
	const effectiveAllowedDomains = React.useMemo(() => {
		const orgDomains = organizationSettings?.emailRestrictions?.allowedDomains;
		if (orgDomains && orgDomains.length > 0) {
			return orgDomains;
		}
		return allowedDomains;
	}, [allowedDomains, organizationSettings]);

	const effectiveBlockedDomains = React.useMemo(() => {
		const orgBlockedDomains =
			organizationSettings?.emailRestrictions?.blockedDomains;
		if (orgBlockedDomains && orgBlockedDomains.length > 0) {
			return [...blockedDomains, ...orgBlockedDomains];
		}
		return blockedDomains;
	}, [blockedDomains, organizationSettings]);

	// Email validation
	const validation = React.useMemo(() => {
		if (!currentValue) return null;
		return validateEmail(currentValue, {
			validateFormat,
			validateDomain,
			allowedDomains: effectiveAllowedDomains,
			blockedDomains: effectiveBlockedDomains,
		});
	}, [
		currentValue,
		validateFormat,
		validateDomain,
		effectiveAllowedDomains,
		effectiveBlockedDomains,
	]);

	// Combined errors
	const errors = React.useMemo(() => {
		const allErrors: string[] = [];

		if (externalError) {
			if (Array.isArray(externalError)) {
				allErrors.push(...externalError);
			} else {
				allErrors.push(externalError);
			}
		}

		if (formField.error) {
			if (Array.isArray(formField.error)) {
				allErrors.push(...formField.error);
			} else {
				allErrors.push(formField.error);
			}
		}

		if (validation && !validation.isValid) {
			allErrors.push(...validation.errors);
		}

		return allErrors.length > 0 ? allErrors : null;
	}, [externalError, formField.error, validation]);

	// Handle value change
	const handleChange = React.useCallback(
		(newValue: string) => {
			// Keep original value while typing - no transformations
			if (onChange) {
				onChange(newValue);
			} else {
				setInternalValue(newValue);
			}

			// Clear errors when user starts typing
			if (formField.clearError) {
				formField.clearError();
			}

			// Show suggestions if we have them and field is focused
			if (validation?.suggestions.length && isFocused && showSuggestions) {
				setShowSuggestionPopover(true);
			} else {
				setShowSuggestionPopover(false);
			}
		},
		[onChange, formField, validation, isFocused, showSuggestions],
	);

	// Handle blur
	const handleBlur = React.useCallback(() => {
		setIsFocused(false);
		setShowSuggestionPopover(false);

		// Apply transformations only when user finishes typing
		if (currentValue) {
			const trimmedValue = currentValue.trim().toLowerCase();
			if (trimmedValue !== currentValue) {
				if (onChange) {
					onChange(trimmedValue);
				} else {
					setInternalValue(trimmedValue);
				}
			}
		}

		if (formField.setTouched) {
			formField.setTouched(true);
		}
		onBlur?.();
	}, [formField, onBlur, currentValue, onChange]);

	// Handle focus
	const handleFocus = React.useCallback(() => {
		setIsFocused(true);
		onFocus?.();
		if (showSuggestions && validation?.suggestions.length) {
			setShowSuggestionPopover(true);
		}
	}, [onFocus]);

	// Handle suggestion selection
	const handleSuggestionSelect = React.useCallback(
		(suggestion: string) => {
			handleChange(suggestion);
			setShowSuggestionPopover(false);
		},
		[handleChange],
	);

	// Verification status content
	const verificationContent = React.useMemo(() => {
		if (!showVerificationStatus || endContent) return null;

		if (isVerified) {
			return (
				<Chip
					size="sm"
					color="success"
					variant="flat"
					startContent={
						<svg
							className="w-3 h-3"
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
					}
				>
					Verified
				</Chip>
			);
		}

		if (currentValue && validation?.isValid && onRequestVerification) {
			return (
				<Button
					size="sm"
					variant="ghost"
					color="primary"
					onPress={onRequestVerification}
				>
					Verify
				</Button>
			);
		}

		return null;
	}, [
		showVerificationStatus,
		endContent,
		isVerified,
		currentValue,
		validation,
		onRequestVerification,
	]);

	// Email icon
	const emailIcon = (
		<svg
			className="w-4 h-4 text-default-400"
			fill="none"
			stroke="currentColor"
			viewBox="0 0 24 24"
		>
			<path
				strokeLinecap="round"
				strokeLinejoin="round"
				strokeWidth={2}
				d="M16 12a4 4 0 10-8 0 4 4 0 008 0zm0 0v1.5a2.5 2.5 0 005 0V12a9 9 0 10-9 9m4.5-1.206a8.959 8.959 0 01-4.5 1.207"
			/>
		</svg>
	);

	const inputContent = (
		<RootInput
			name={name}
			label={label}
			placeholder={placeholder}
			value={currentValue}
			onChange={(e: any) => handleChange(e.target.value)}
			onBlur={handleBlur}
			onFocus={handleFocus}
			type="email"
			isRequired={required}
			required={required}
			isDisabled={disabled}
			disabled={disabled}
			size={size}
			radius={radius}
			variant={variant}
			autoFocus={autoFocus}
			autoComplete={autoComplete}
			description={description}
			isInvalid={!!errors}
			errorMessage=""
			startContent={startContent || emailIcon}
			endContent={endContent || verificationContent}
		/>
	);

	return (
		<div className={`space-y-2 ${className}`}>
			{/* Input with suggestion popover */}
			{showSuggestions && validation?.suggestions.length ? (
				<Popover
					isOpen={showSuggestionPopover}
					onOpenChange={setShowSuggestionPopover}
					placement="bottom-start"
					showArrow
				>
					<PopoverTrigger>{inputContent}</PopoverTrigger>
					<PopoverContent className="p-1">
						<Listbox
							aria-label="Email suggestions"
							onAction={(key) => handleSuggestionSelect(key as string)}
						>
							{validation.suggestions.map((suggestion, index) => (
								<ListboxItem
									key={suggestion}
									value={suggestion}
									startContent={
										<svg
											className="w-4 h-4 text-primary"
											fill="none"
											stroke="currentColor"
											viewBox="0 0 24 24"
										>
											<path
												strokeLinecap="round"
												strokeLinejoin="round"
												strokeWidth={2}
												d="M13 10V3L4 14h7v7l9-11h-7z"
											/>
										</svg>
									}
								>
									{suggestion}
								</ListboxItem>
							))}
						</Listbox>
					</PopoverContent>
				</Popover>
			) : (
				inputContent
			)}

			{/* Field Errors */}
			{errors && <FieldError error={errors} fieldName={name} />}

			{/* Domain Restrictions Info */}
			{effectiveAllowedDomains.length > 0 && (
				<div className="text-xs text-default-500">
					<span className="font-medium">Allowed domains:</span>{" "}
					{effectiveAllowedDomains.join(", ")}
				</div>
			)}

			{/* Suggestions (non-popover) */}
			<AnimatePresence>
				{!showSuggestionPopover &&
					validation?.suggestions.length &&
					isFocused && (
						<motion.div
							initial={{ opacity: 0, y: -10 }}
							animate={{ opacity: 1, y: 0 }}
							exit={{ opacity: 0, y: -10 }}
							className="space-y-1"
						>
							<div className="text-xs text-default-600 font-medium">
								Did you mean:
							</div>
							<div className="flex flex-wrap gap-1">
								{validation.suggestions.slice(0, 3).map((suggestion, index) => (
									<Button
										key={index}
										size="sm"
										variant="ghost"
										color="primary"
										onPress={() => handleSuggestionSelect(suggestion)}
										className="text-xs h-6"
									>
										{suggestion}
									</Button>
								))}
							</div>
						</motion.div>
					)}
			</AnimatePresence>
		</div>
	);
}

// ============================================================================
// Export
// ============================================================================

// export const EmailField = React.memo(EmailFieldComponent);
export default EmailField;
