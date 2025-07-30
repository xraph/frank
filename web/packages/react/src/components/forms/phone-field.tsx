/**
 * @frank-auth/react - Phone Field Component
 *
 * International phone number input with country selection, formatting,
 * and validation. Supports SMS MFA and organization restrictions.
 */

"use client";

import { Button, Chip, Input, Select } from "@/components/ui";
import React from "react";
import { useConfig } from "../../hooks/use-config";
import { FieldError } from "./field-error";
import { useFormField } from "./form-wrapper";

// ============================================================================
// Phone Field Interface
// ============================================================================

export interface PhoneFieldProps {
	/**
	 * Field name for form handling
	 */
	name?: string;

	/**
	 * Field label
	 */
	label?: string;

	/**
	 * Placeholder text
	 */
	placeholder?: string;

	/**
	 * Phone number value (E.164 format or formatted)
	 */
	value?: string;

	/**
	 * Change handler (receives E.164 format)
	 */
	onChange?: (value: string, formatted: string) => void;

	/**
	 * Blur handler
	 */
	onBlur?: () => void;

	/**
	 * Focus handler
	 */
	onFocus?: () => void;

	/**
	 * Default country code (ISO 3166-1 alpha-2)
	 */
	defaultCountry?: string;

	/**
	 * Preferred countries (shown at top of list)
	 */
	preferredCountries?: string[];

	/**
	 * Allowed countries (if restricted)
	 */
	allowedCountries?: string[];

	/**
	 * Blocked countries
	 */
	blockedCountries?: string[];

	/**
	 * Whether field is required
	 */
	required?: boolean;

	/**
	 * Whether field is disabled
	 */
	disabled?: boolean;

	/**
	 * Whether to validate phone number format
	 */
	validateFormat?: boolean;

	/**
	 * Field size
	 */
	size?: "sm" | "md" | "lg";

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
	 * Whether phone is verified
	 */
	isVerified?: boolean;

	/**
	 * Verification handler
	 */
	onRequestVerification?: () => void;

	/**
	 * End content (overrides verification status)
	 */
	endContent?: React.ReactNode;
}

// ============================================================================
// Country Data Types
// ============================================================================

export interface Country {
	code: string; // ISO 3166-1 alpha-2
	name: string;
	dialCode: string;
	flag: string;
	format?: string; // Phone number format pattern
}

// ============================================================================
// Country Data
// ============================================================================

const countries: Country[] = [
	{
		code: "US",
		name: "United States",
		dialCode: "+1",
		flag: "🇺🇸",
		format: "(###) ###-####",
	},
	{
		code: "CA",
		name: "Canada",
		dialCode: "+1",
		flag: "🇨🇦",
		format: "(###) ###-####",
	},
	{
		code: "GB",
		name: "United Kingdom",
		dialCode: "+44",
		flag: "🇬🇧",
		format: "#### ### ####",
	},
	{
		code: "AU",
		name: "Australia",
		dialCode: "+61",
		flag: "🇦🇺",
		format: "#### ### ###",
	},
	{
		code: "DE",
		name: "Germany",
		dialCode: "+49",
		flag: "🇩🇪",
		format: "### ### ####",
	},
	{
		code: "FR",
		name: "France",
		dialCode: "+33",
		flag: "🇫🇷",
		format: "## ## ## ## ##",
	},
	{
		code: "ES",
		name: "Spain",
		dialCode: "+34",
		flag: "🇪🇸",
		format: "### ### ###",
	},
	{
		code: "IT",
		name: "Italy",
		dialCode: "+39",
		flag: "🇮🇹",
		format: "### ### ####",
	},
	{
		code: "JP",
		name: "Japan",
		dialCode: "+81",
		flag: "🇯🇵",
		format: "###-####-####",
	},
	{
		code: "KR",
		name: "South Korea",
		dialCode: "+82",
		flag: "🇰🇷",
		format: "###-####-####",
	},
	{
		code: "CN",
		name: "China",
		dialCode: "+86",
		flag: "🇨🇳",
		format: "### #### ####",
	},
	{
		code: "IN",
		name: "India",
		dialCode: "+91",
		flag: "🇮🇳",
		format: "##### #####",
	},
	{
		code: "BR",
		name: "Brazil",
		dialCode: "+55",
		flag: "🇧🇷",
		format: "(##) #####-####",
	},
	{
		code: "MX",
		name: "Mexico",
		dialCode: "+52",
		flag: "🇲🇽",
		format: "### ### ####",
	},
	{
		code: "AR",
		name: "Argentina",
		dialCode: "+54",
		flag: "🇦🇷",
		format: "### ###-####",
	},
	{
		code: "RU",
		name: "Russia",
		dialCode: "+7",
		flag: "🇷🇺",
		format: "### ###-##-##",
	},
	{
		code: "ZA",
		name: "South Africa",
		dialCode: "+27",
		flag: "🇿🇦",
		format: "## ### ####",
	},
	{
		code: "EG",
		name: "Egypt",
		dialCode: "+20",
		flag: "🇪🇬",
		format: "### ### ####",
	},
	{
		code: "NG",
		name: "Nigeria",
		dialCode: "+234",
		flag: "🇳🇬",
		format: "### ### ####",
	},
	{
		code: "SG",
		name: "Singapore",
		dialCode: "+65",
		flag: "🇸🇬",
		format: "#### ####",
	},
];

// ============================================================================
// Phone Validation Functions
// ============================================================================

function parsePhoneNumber(
	phoneNumber: string,
	country: Country,
): {
	isValid: boolean;
	e164: string;
	national: string;
	formatted: string;
	errors: string[];
} {
	const errors: string[] = [];

	// Remove all non-digit characters except +
	const cleaned = phoneNumber.replace(/[^\d+]/g, "");

	// Check if it starts with the country's dial code
	let nationalNumber = cleaned;
	let e164 = cleaned;

	if (cleaned.startsWith("+")) {
		e164 = cleaned;
		if (cleaned.startsWith(country.dialCode)) {
			nationalNumber = cleaned.substring(country.dialCode.length);
		} else {
			errors.push("Phone number does not match selected country");
		}
	} else {
		// Assume it's a national number
		e164 = country.dialCode + cleaned;
		nationalNumber = cleaned;
	}

	// Basic validation - phone numbers should be 7-15 digits (excluding country code)
	if (nationalNumber.length < 7) {
		errors.push("Phone number is too short");
	} else if (nationalNumber.length > 15) {
		errors.push("Phone number is too long");
	}

	// Format the national number if format is available
	let formatted = nationalNumber;
	if (country.format && nationalNumber.length >= 7) {
		formatted = formatPhoneNumber(nationalNumber, country.format);
	}

	return {
		isValid: errors.length === 0,
		e164,
		national: nationalNumber,
		formatted: `${country.dialCode} ${formatted}`,
		errors,
	};
}

function formatPhoneNumber(number: string, format: string): string {
	let formattedNumber = format;
	let numberIndex = 0;

	for (let i = 0; i < format.length && numberIndex < number.length; i++) {
		if (format[i] === "#") {
			formattedNumber =
				formattedNumber.substring(0, i) +
				number[numberIndex] +
				formattedNumber.substring(i + 1);
			numberIndex++;
		}
	}

	return formattedNumber.substring(0, formattedNumber.lastIndexOf("#") + 1);
}

function detectCountryFromNumber(phoneNumber: string): Country | null {
	const cleaned = phoneNumber.replace(/[^\d+]/g, "");

	if (!cleaned.startsWith("+")) return null;

	// Sort by dial code length (longest first) to match more specific codes first
	const sortedCountries = [...countries].sort(
		(a, b) => b.dialCode.length - a.dialCode.length,
	);

	for (const country of sortedCountries) {
		if (cleaned.startsWith(country.dialCode)) {
			return country;
		}
	}

	return null;
}

// ============================================================================
// Phone Field Component
// ============================================================================

export function PhoneField({
	name = "phone",
	label = "Phone Number",
	placeholder = "Enter your phone number",
	value = "",
	onChange,
	onBlur,
	onFocus,
	defaultCountry = "US",
	preferredCountries = ["US", "CA", "GB"],
	allowedCountries = [],
	blockedCountries = [],
	required = false,
	disabled = false,
	validateFormat = true,
	size = "md",
	variant = "bordered",
	className = "",
	autoFocus = false,
	autoComplete = "tel",
	error: externalError,
	description,
	showVerificationStatus = false,
	isVerified = false,
	onRequestVerification,
	endContent,
}: PhoneFieldProps) {
	const { components, organizationSettings } = useConfig();
	const formField = useFormField(name);

	// Custom component override
	const CustomPhoneField = components.PhoneField;
	if (CustomPhoneField) {
		return (
			<CustomPhoneField
				{...{
					name,
					label,
					placeholder,
					value,
					onChange,
					onBlur,
					onFocus,
					defaultCountry,
					preferredCountries,
					allowedCountries,
					blockedCountries,
					required,
					disabled,
					validateFormat,
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
					endContent,
				}}
			/>
		);
	}

	// State
	const [internalValue, setInternalValue] = React.useState(value);
	const [selectedCountry, setSelectedCountry] = React.useState<Country>(() => {
		// Try to detect country from initial value
		if (value) {
			const detectedCountry = detectCountryFromNumber(value);
			if (detectedCountry) return detectedCountry;
		}
		return countries.find((c) => c.code === defaultCountry) || countries[0];
	});

	// Use external value if controlled
	const currentValue = onChange ? value : internalValue;

	// Apply organization phone restrictions if available
	const effectiveAllowedCountries = React.useMemo(() => {
		const orgCountries =
			organizationSettings?.phoneRestrictions?.allowedCountries;
		if (orgCountries && orgCountries.length > 0) {
			return orgCountries;
		}
		return allowedCountries;
	}, [allowedCountries, organizationSettings]);

	const effectiveBlockedCountries = React.useMemo(() => {
		const orgBlockedCountries =
			organizationSettings?.phoneRestrictions?.blockedCountries;
		if (orgBlockedCountries && orgBlockedCountries.length > 0) {
			return [...blockedCountries, ...orgBlockedCountries];
		}
		return blockedCountries;
	}, [blockedCountries, organizationSettings]);

	// Filter countries based on restrictions
	const availableCountries = React.useMemo(() => {
		let filtered = countries;

		if (effectiveAllowedCountries.length > 0) {
			filtered = filtered.filter((c) =>
				effectiveAllowedCountries.includes(c.code),
			);
		}

		if (effectiveBlockedCountries.length > 0) {
			filtered = filtered.filter(
				(c) => !effectiveBlockedCountries.includes(c.code),
			);
		}

		// Sort with preferred countries first
		const preferred = filtered.filter((c) =>
			preferredCountries.includes(c.code),
		);
		const others = filtered.filter((c) => !preferredCountries.includes(c.code));

		return [...preferred, ...others];
	}, [
		effectiveAllowedCountries,
		effectiveBlockedCountries,
		preferredCountries,
	]);

	// Phone validation
	const validation = React.useMemo(() => {
		if (!currentValue || !validateFormat) return null;
		return parsePhoneNumber(currentValue, selectedCountry);
	}, [currentValue, selectedCountry, validateFormat]);

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
			// Auto-detect country if value includes country code
			const detectedCountry = detectCountryFromNumber(newValue);
			if (detectedCountry && availableCountries.includes(detectedCountry)) {
				setSelectedCountry(detectedCountry);
			}

			if (onChange && validation) {
				onChange(validation.e164, validation.formatted);
			} else if (onChange) {
				// Fallback if validation not available
				const cleaned = newValue.replace(/[^\d+]/g, "");
				const e164 = cleaned.startsWith("+")
					? cleaned
					: selectedCountry.dialCode + cleaned.replace(/^\d/, "");
				onChange(e164, newValue);
			} else {
				setInternalValue(newValue);
			}

			// Clear errors when user starts typing
			if (formField.clearError) {
				formField.clearError();
			}
		},
		[onChange, validation, formField, selectedCountry, availableCountries],
	);

	// Handle country change
	const handleCountryChange = React.useCallback(
		(countryCode: string) => {
			const country = availableCountries.find((c) => c.code === countryCode);
			if (country) {
				setSelectedCountry(country);

				// Update phone number with new country code if there's a value
				if (currentValue) {
					const newValidation = parsePhoneNumber(currentValue, country);
					if (onChange) {
						onChange(newValidation.e164, newValidation.formatted);
					}
				}
			}
		},
		[availableCountries, currentValue, onChange],
	);

	// Handle blur
	const handleBlur = React.useCallback(() => {
		if (formField.setTouched) {
			formField.setTouched(true);
		}
		onBlur?.();
	}, [formField, onBlur]);

	// Handle focus
	const handleFocus = React.useCallback(() => {
		onFocus?.();
	}, [onFocus]);

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
					variant="flat"
					color="primary"
					onPress={onRequestVerification}
				>
					Send SMS
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

	// Country selector
	const countrySelector = (
		<Select
			value={selectedCountry.code}
			onChange={(e) => handleCountryChange(e.target.value)}
			className="min-w-32"
			size={size}
			variant={variant}
			isDisabled={disabled}
			placeholder="Country"
			options={availableCountries.map((country) => ({
				label: country.name,
				value: country.code,
			}))}
			// renderValue={(items) => {
			// 	const country = availableCountries.find(
			// 		(c) => c.code === selectedCountry.code,
			// 	);
			// 	return country ? (
			// 		<div className="flex items-center gap-1">
			// 			<span>{country.flag}</span>
			// 			<span className="text-sm">{country.dialCode}</span>
			// 		</div>
			// 	) : null;
			// }}
		>
			{/*{availableCountries.map((country) => (*/}
			{/*	<SelectItem*/}
			{/*		key={country.code}*/}
			{/*		value={country.code}*/}
			{/*		startContent={<span className="text-lg">{country.flag}</span>}*/}
			{/*	>*/}
			{/*		<div className="flex items-center justify-between w-full">*/}
			{/*			<span>{country.name}</span>*/}
			{/*			<span className="text-sm text-default-500">{country.dialCode}</span>*/}
			{/*		</div>*/}
			{/*	</SelectItem>*/}
			{/*))}*/}
		</Select>
	);

	return (
		<div className={`space-y-2 ${className}`}>
			<div className="flex gap-2">
				{/* Country Selector */}
				<div className="shrink-0">{countrySelector}</div>

				{/* Phone Input */}
				<div className="flex-1">
					<Input
						name={name}
						label={label}
						placeholder={placeholder}
						value={currentValue}
						onValueChange={handleChange}
						onBlur={handleBlur}
						onFocus={handleFocus}
						type="tel"
						isRequired={required}
						isDisabled={disabled}
						size={size}
						variant={variant}
						autoFocus={autoFocus}
						autoComplete={autoComplete}
						description={description}
						isInvalid={!!errors}
						errorMessage=""
						endContent={endContent || verificationContent}
					/>
				</div>
			</div>

			{/* Field Errors */}
			{errors && <FieldError error={errors} fieldName={name} />}

			{/* Format Preview */}
			{validation && validation.isValid && (
				<div className="text-xs text-default-500">
					<span className="font-medium">Format:</span> {validation.formatted}
				</div>
			)}

			{/* Country Restrictions Info */}
			{effectiveAllowedCountries.length > 0 && (
				<div className="text-xs text-default-500">
					<span className="font-medium">Allowed countries:</span>{" "}
					{effectiveAllowedCountries.join(", ")}
				</div>
			)}
		</div>
	);
}

// ============================================================================
// Export
// ============================================================================

export default PhoneField;
