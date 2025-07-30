/**
 * @frank-auth/react - Password Field Component
 *
 * Advanced password input with strength validation, visibility toggle, and
 * organization-specific password requirements. Supports MFA and security features.
 */

"use client";

import {
	type SignUpFormProps,
	generatePasswordSuggestions,
	getPasswordStrength,
} from "@/components";
import type { FieldProps } from "@/components/forms/shared";
import { Button, Input } from "@/components/ui";
import { Chip, Progress } from "@/components/ui";
import { useConfig } from "@/hooks";
import { useTheme } from "@/theme/context";
import type { StyledProps } from "@/theme/styled";
import styled from "@emotion/styled";
import {
	CheckIcon,
	ExclamationTriangleIcon,
	EyeIcon,
	EyeSlashIcon,
} from "@heroicons/react/24/outline";
import { AnimatePresence, motion } from "framer-motion";
import React from "react";
import { FieldError } from "./field-error";
import { useFormField } from "./form-wrapper";

// ============================================================================
// Password Field Interface
// ============================================================================

export interface PasswordFieldProps extends FieldProps<string> {
	/**
	 * Whether field is required
	 */
	required?: boolean;

	/**
	 * Whether field is disabled
	 */
	disabled?: boolean;

	/**
	 * Whether to show password strength indicator
	 */
	showStrength?: boolean;

	/**
	 * Whether to show password requirements
	 */
	showRequirements?: boolean;
	showSuggestions?: boolean;
	enableGenerate?: boolean;

	/**
	 * Whether to allow password visibility toggle
	 */
	allowToggle?: boolean;

	/**
	 * Custom password validation rules
	 */
	rules?: PasswordRules;

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
	 * Whether this is for password confirmation
	 */
	isConfirmation?: boolean;

	/**
	 * Original password for confirmation
	 */
	originalPassword?: string;

	/**
	 * Custom validation error
	 */
	error?: string | string[];

	/**
	 * Help text
	 */
	description?: string;

	/**
	 * Start icon
	 */
	startContent?: React.ReactNode;

	advanceRequirements?: any;
}

// ============================================================================
// Password Validation Types
// ============================================================================

export interface PasswordRules {
	minLength?: number;
	maxLength?: number;
	requireUppercase?: boolean;
	requireLowercase?: boolean;
	requireNumbers?: boolean;
	requireSpecialChars?: boolean;
	preventCommon?: boolean;
	preventUserInfo?: boolean;
	customPattern?: RegExp;
	customMessage?: string;
}

export interface PasswordStrength {
	score: number; // 0-4 (very weak to very strong)
	label: string;
	color: string;
	percentage: number;
	feedback: string[];
	requirements: PasswordRequirement[];
}

export interface PasswordRequirement {
	id: string;
	label: string;
	met: boolean;
	required: boolean;
}

// ============================================================================
// Styled Components
// ============================================================================

const PasswordFieldContainer = styled.div<StyledProps>`
	display: flex;
	flex-direction: column;
	gap: ${(props) => props.theme.spacing[2]};
`;

const ToggleButton = styled(Button)<StyledProps>`
	color: ${(props) => props.theme.colors.text.quaternary};
	
	&:hover {
		color: ${(props) => props.theme.colors.text.tertiary};
	}
`;

const StyledSvg = styled.svg<StyledProps>`
	width: ${(props) => props.theme.spacing[4]};
	height: ${(props) => props.theme.spacing[4]};
	color: ${(props) => props.theme.colors.text.quaternary};
`;

const StrengthContainer = styled(motion.div)<StyledProps>`
	display: flex;
	flex-direction: column;
	gap: ${(props) => props.theme.spacing[2]};
`;

const StrengthHeader = styled.div<StyledProps>`
	display: flex;
	align-items: center;
	justify-content: space-between;
	font-size: ${(props) => props.theme.fontSizes.sm};
`;

const StrengthLabel = styled.span<StyledProps>`
	color: ${(props) => props.theme.colors.text.secondary};
`;

const StrengthValue = styled.span<
	StyledProps & { strengthColor: keyof typeof props.theme.colors }
>`
	font-weight: ${(props) => props.theme.fontWeights.medium};
	color: ${(props) => {
		switch (props.strengthColor) {
			case "danger":
				return props.theme.colors.danger[500];
			case "warning":
				return props.theme.colors.warning[500];
			case "primary":
				return props.theme.colors.primary[500];
			case "success":
				return props.theme.colors.success[500];
			default:
				return props.theme.colors.text.primary;
		}
	}};
`;

const StrengthFeedback = styled.div<StyledProps>`
	font-size: ${(props) => props.theme.fontSizes.xs};
	color: ${(props) => props.theme.colors.text.tertiary};
`;

const RequirementsContainer = styled(motion.div)<StyledProps>`
	display: flex;
	flex-direction: column;
	gap: ${(props) => props.theme.spacing[2]};
`;

const RequirementsTitle = styled.div<StyledProps>`
	font-size: ${(props) => props.theme.fontSizes.sm};
	font-weight: ${(props) => props.theme.fontWeights.medium};
	color: ${(props) => props.theme.colors.text.primary};
`;

const RequirementsGrid = styled.div<StyledProps>`
	display: flex;
	flex-direction: column;
	gap: ${(props) => props.theme.spacing[1]};
`;

const RequirementItem = styled.div<StyledProps>`
	display: flex;
	align-items: center;
	gap: ${(props) => props.theme.spacing[2]};
	font-size: ${(props) => props.theme.fontSizes.xs};
`;

const RequirementIcon = styled.div<StyledProps & { met: boolean }>`
	width: ${(props) => props.theme.spacing[4]};
	height: ${(props) => props.theme.spacing[4]};
	border-radius: ${(props) => props.theme.borderRadius.full};
	display: flex;
	align-items: center;
	justify-content: center;
	background-color: ${(props) =>
		props.met
			? props.theme.colors.success[100]
			: props.theme.colors.background.tertiary};
	color: ${(props) =>
		props.met
			? props.theme.colors.success[600]
			: props.theme.colors.text.quaternary};
`;

const RequirementIconSvg = styled.svg<StyledProps>`
	width: ${(props) => props.theme.spacing[3]};
	height: ${(props) => props.theme.spacing[3]};
`;

const RequirementDot = styled.div<StyledProps>`
	width: 6px;
	height: 6px;
	border-radius: ${(props) => props.theme.borderRadius.full};
	background-color: currentColor;
`;

const RequirementText = styled.span<StyledProps & { met: boolean }>`
	color: ${(props) =>
		props.met
			? props.theme.colors.success[600]
			: props.theme.colors.text.tertiary};
`;

const SuggestionsContainer = styled.div<StyledProps>`
	display: flex;
	flex-direction: column;
	gap: ${(props) => props.theme.spacing[2]};
`;

const SuggestionsTitle = styled.div<StyledProps>`
	font-size: ${(props) => props.theme.fontSizes.xs};
	color: ${(props) => props.theme.colors.text.tertiary};
`;

const SuggestionsGrid = styled.div<StyledProps>`
	display: flex;
	flex-direction: column;
	gap: ${(props) => props.theme.spacing[1]};
`;

const SuggestionButton = styled.button<StyledProps>`
	font-size: ${(props) => props.theme.fontSizes.xs};
	font-family: monospace;
	color: ${(props) => props.theme.colors.primary[600]};
	background: none;
	border: none;
	cursor: pointer;
	text-align: left;
	padding: 0;
	
	&:hover {
		color: ${(props) => props.theme.colors.primary[800]};
		text-decoration: underline;
	}
`;

const FeedbackContainer = styled.div<StyledProps>`
	font-size: ${(props) => props.theme.fontSizes.xs};
	display: flex;
	flex-direction: column;
	gap: ${(props) => props.theme.spacing[1]};
`;

const FeedbackItem = styled.div<StyledProps>`
	display: flex;
	align-items: center;
	gap: ${(props) => props.theme.spacing[1]};
	color: ${(props) => props.theme.colors.text.tertiary};
`;

const FeedbackIcon = styled.svg<StyledProps>`
	width: ${(props) => props.theme.spacing[3]};
	height: ${(props) => props.theme.spacing[3]};
`;

const ChecklistContainer = styled.div<StyledProps>`
	font-size: ${(props) => props.theme.fontSizes.xs};
	display: flex;
	flex-direction: column;
	gap: ${(props) => props.theme.spacing[1]};
`;

const ChecklistItem = styled.div<StyledProps & { met: boolean }>`
	display: flex;
	align-items: center;
	gap: ${(props) => props.theme.spacing[1]};
	color: ${(props) =>
		props.met
			? props.theme.colors.success[600]
			: props.theme.colors.text.quaternary};
`;

const ChecklistIcon = styled.svg<StyledProps & { met: boolean }>`
	width: ${(props) => props.theme.spacing[3]};
	height: ${(props) => props.theme.spacing[3]};
	opacity: ${(props) => (props.met ? 1 : 0.3)};
`;

// ============================================================================
// Default Password Rules
// ============================================================================

const defaultPasswordRules: PasswordRules = {
	minLength: 8,
	maxLength: 128,
	requireUppercase: true,
	requireLowercase: true,
	requireNumbers: true,
	requireSpecialChars: true,
	preventCommon: true,
	preventUserInfo: false,
};

// Common weak passwords
const commonPasswords = [
	"password",
	"123456",
	"123456789",
	"qwerty",
	"abc123",
	"password123",
	"admin",
	"letmein",
	"welcome",
	"monkey",
	"1234567890",
	"iloveyou",
];

// ============================================================================
// Password Validation Functions
// ============================================================================

// Fixed special characters regex - dash moved to end to avoid range issues
const SPECIAL_CHARS_REGEX = /[!@#$%^&*()_+=\[\]{}|;':",./<>?~`-]/;

// Alternative: Even more comprehensive list including common symbols
// const COMPREHENSIVE_SPECIAL_CHARS_REGEX =
// 	/[!@#$%^&*()_+=\[\]{}\|\\:;'".,<>?/~`-]/;

// Alternative comprehensive regex (includes more symbols)
const COMPREHENSIVE_SPECIAL_CHARS_REGEX =
	/[!@#$%^&*()_+=\[\]{}\\|;':",./<>?~`-]/;

// Most common special characters (simpler pattern)
const COMMON_SPECIAL_CHARS_REGEX = /[!@#$%^&*()_+-=\[\]{}|;':",./<>?~]/;

function validatePassword(
	password: string,
	rules: PasswordRules,
	userInfo?: any,
): PasswordStrength {
	const requirements: PasswordRequirement[] = [];
	let score = 0;
	const feedback: string[] = [];

	// Length requirement
	if (rules.minLength) {
		const lengthMet = password.length >= rules.minLength;
		requirements.push({
			id: "length",
			label: `At least ${rules.minLength} characters`,
			met: lengthMet,
			required: true,
		});
		if (lengthMet) score += 1;
		else
			feedback.push(
				`Password must be at least ${rules.minLength} characters long`,
			);
	}

	// Uppercase requirement
	if (rules.requireUppercase) {
		const uppercaseMet = /[A-Z]/.test(password);
		requirements.push({
			id: "uppercase",
			label: "One uppercase letter",
			met: uppercaseMet,
			required: true,
		});
		if (uppercaseMet) score += 1;
		else feedback.push("Password must contain at least one uppercase letter");
	}

	// Lowercase requirement
	if (rules.requireLowercase) {
		const lowercaseMet = /[a-z]/.test(password);
		requirements.push({
			id: "lowercase",
			label: "One lowercase letter",
			met: lowercaseMet,
			required: true,
		});
		if (lowercaseMet) score += 1;
		else feedback.push("Password must contain at least one lowercase letter");
	}

	// Number requirement
	if (rules.requireNumbers) {
		const numberMet = /\d/.test(password);
		requirements.push({
			id: "number",
			label: "One number",
			met: numberMet,
			required: true,
		});
		if (numberMet) score += 1;
		else feedback.push("Password must contain at least one number");
	}

	// Fixed Special character requirement
	if (rules.requireSpecialChars) {
		// Use the fixed regex pattern
		const specialMet = SPECIAL_CHARS_REGEX.test(password);
		requirements.push({
			id: "special",
			label: "One special character",
			met: specialMet,
			required: true,
		});
		if (specialMet) score += 1;
		else
			feedback.push(
				"Password must contain at least one special character (!@#$%^&*()_+-=[]{}|;':\",./<>?~`)",
			);
	}

	// Common password check
	if (rules.preventCommon) {
		const isCommon = commonPasswords.includes(password.toLowerCase());
		requirements.push({
			id: "common",
			label: "Not a common password",
			met: !isCommon,
			required: false,
		});
		if (isCommon) {
			score = Math.max(0, score - 2);
			feedback.push("This is a commonly used password");
		}
	}

	// Additional scoring for complexity
	if (password.length >= 12) score += 1;
	if (password.length >= 16) score += 1;
	if (/[A-Z].*[A-Z]/.test(password)) score += 0.5;
	if (/\d.*\d/.test(password)) score += 0.5;
	// Use the same fixed regex for additional scoring
	if (SPECIAL_CHARS_REGEX.test(password)) {
		const specialMatches = password.match(
			new RegExp(SPECIAL_CHARS_REGEX.source, "g"),
		);
		if (specialMatches && specialMatches.length >= 2) score += 0.5;
	}

	// Cap the score at 4
	score = Math.min(4, Math.floor(score * 0.8));

	// Determine strength label and color
	let label: string;
	let color: string;
	let percentage: number;

	switch (score) {
		case 0:
		case 1:
			label = "Very Weak";
			color = "danger";
			percentage = 20;
			break;
		case 2:
			label = "Weak";
			color = "warning";
			percentage = 40;
			break;
		case 3:
			label = "Good";
			color = "primary";
			percentage = 70;
			break;
		case 4:
			label = "Strong";
			color = "success";
			percentage = 100;
			break;
		default:
			label = "Very Weak";
			color = "danger";
			percentage = 0;
	}

	return {
		score,
		label,
		color,
		percentage,
		feedback,
		requirements,
	};
}

// ============================================================================
// Password Field Component
// ============================================================================

export function PasswordFieldComponent({
	name = "password",
	label = "Password",
	placeholder = "Enter your password",
	value = "",
	onChange,
	onBlur,
	onFocus,
	required = false,
	disabled = false,
	showStrength = true,
	showRequirements = false,
	showSuggestions = false,
	enableGenerate = false,
	allowToggle = true,
	rules = defaultPasswordRules,
	size = "md",
	radius = "md",
	variant = "bordered",
	className = "",
	autoFocus = false,
	autoComplete = "current-password",
	isConfirmation = false,
	originalPassword,
	error: externalError,
	description,
	startContent,
	advanceRequirements,
}: PasswordFieldProps) {
	const { theme } = useTheme();
	const { components, organizationSettings } = useConfig();
	const formField = useFormField(name);

	// Custom component override
	const RootInput = components.Input ?? Input;
	const RootButton = components.Button ?? Button;
	const CustomPasswordField = components.PasswordField;
	if (CustomPasswordField) {
		return (
			<CustomPasswordField
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
					showStrength,
					showRequirements,
					allowToggle,
					rules,
					size,
					variant,
					className,
					autoFocus,
					autoComplete,
					isConfirmation,
					originalPassword,
					error: externalError,
					description,
				}}
			/>
		);
	}

	// State
	const [internalValue, setInternalValue] = React.useState(value);
	const [isVisible, setIsVisible] = React.useState(false);
	const [isFocused, setIsFocused] = React.useState(false);
	const [suggestedPasswords, setSuggestedPasswords] = React.useState<string[]>(
		[],
	);

	// Use external value if controlled
	const currentValue = onChange ? value : internalValue;

	// Apply organization password rules if available
	const effectiveRules = React.useMemo(() => {
		const orgRules = organizationSettings?.passwordPolicy;
		if (orgRules) {
			return {
				...defaultPasswordRules,
				...rules,
				minLength: orgRules.minLength || rules.minLength,
				requireUppercase: orgRules.requireUppercase ?? rules.requireUppercase,
				requireLowercase: orgRules.requireLowercase ?? rules.requireLowercase,
				requireNumbers: orgRules.requireNumbers ?? rules.requireNumbers,
				requireSpecialChars:
					orgRules.requireSpecialChars ?? rules.requireSpecialChars,
			};
		}
		return { ...defaultPasswordRules, ...rules };
	}, [rules, organizationSettings]);

	// Password strength validation
	const strength = React.useMemo(() => {
		if (!currentValue) return null;
		return validatePassword(currentValue, effectiveRules);
	}, [currentValue, effectiveRules]);

	// Password confirmation validation
	const confirmationError = React.useMemo(() => {
		if (!isConfirmation || !originalPassword || !currentValue) return null;
		return originalPassword !== currentValue ? "Passwords do not match" : null;
	}, [isConfirmation, originalPassword, currentValue]);

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

		if (confirmationError) {
			allErrors.push(confirmationError);
		}

		return allErrors.length > 0 ? allErrors : null;
	}, [externalError, formField.error, confirmationError]);

	// Handle value change
	const handleChange = React.useCallback(
		(newValue: string) => {
			if (onChange) {
				onChange(newValue);
			} else {
				setInternalValue(newValue);
			}

			// Clear errors when user starts typing
			if (formField.clearError) {
				formField.clearError();
			}
		},
		[onChange, formField],
	);

	// Handle blur
	const handleBlur = React.useCallback(() => {
		setIsFocused(false);
		if (formField.setTouched) {
			formField.setTouched(true);
		}
		onBlur?.();
	}, [formField, onBlur]);

	// Handle focus
	const handleFocus = React.useCallback(() => {
		setIsFocused(true);
		onFocus?.();
	}, [onFocus]);

	// Toggle visibility
	const toggleVisibility = React.useCallback(() => {
		setIsVisible((prev) => !prev);
	}, []);

	// Show requirements when focused or has value
	const shouldShowRequirements =
		showRequirements && (isFocused || currentValue);
	const shouldShowSuggestions = showSuggestions && (isFocused || currentValue);
	const shouldShowStrength = showStrength && currentValue && !isConfirmation;

	// Generate password suggestions
	const generateSuggestions = React.useCallback(() => {
		const suggestions = generatePasswordSuggestions();
		setSuggestedPasswords(suggestions);
	}, []);

	return (
		<PasswordFieldContainer theme={theme} className={className}>
			<RootInput
				name={name}
				label={label}
				placeholder={placeholder}
				value={currentValue}
				onBlur={handleBlur}
				onFocus={handleFocus}
				type={isVisible ? "text" : "password"}
				isRequired={required}
				isDisabled={disabled}
				onChange={(e: any) =>
					handleChange(typeof e === "string" ? e : e.target.value)
				}
				required={required}
				disabled={disabled}
				size={size}
				radius={radius}
				variant={variant}
				autoFocus={autoFocus}
				autoComplete={autoComplete}
				description={description}
				isInvalid={!!errors}
				errorMessage=""
				startContent={startContent}
				endContent={
					allowToggle && (
						<ToggleButton
							theme={theme}
							isIconOnly
							variant="ghost"
							size="sm"
							type="button"
							color="secondary"
							onClick={toggleVisibility}
							aria-label={isVisible ? "Hide password" : "Show password"}
						>
							{isVisible ? (
								<EyeSlashIcon>
									<StyledSvg theme={theme} as={EyeSlashIcon} />
								</EyeSlashIcon>
							) : (
								<EyeIcon>
									<StyledSvg theme={theme} as={EyeIcon} />
								</EyeIcon>
							)}
						</ToggleButton>
					)
				}
			/>

			{/* Field Errors */}
			{errors && <FieldError error={errors} fieldName={name} />}

			{/* Password Strength Indicator */}
			<AnimatePresence>
				{shouldShowStrength && strength && (
					<StrengthContainer
						theme={theme}
						initial={{ opacity: 0, height: 0 }}
						animate={{ opacity: 1, height: "auto" }}
						exit={{ opacity: 0, height: 0 }}
					>
						<StrengthHeader theme={theme}>
							<StrengthLabel theme={theme}>Password strength:</StrengthLabel>
							<StrengthValue
								theme={theme}
								strengthColor={strength.color as any}
							>
								{strength.label}
							</StrengthValue>
						</StrengthHeader>
						<Progress
							value={strength.percentage}
							color={strength.color as any}
							size="xs"
						/>
						{strength.feedback.length > 0 && (
							<StrengthFeedback theme={theme}>
								{strength.feedback[0]}
							</StrengthFeedback>
						)}
					</StrengthContainer>
				)}
			</AnimatePresence>

			{/* Password Requirements */}
			<AnimatePresence>
				{shouldShowRequirements && strength && (
					<RequirementsContainer
						theme={theme}
						initial={{ opacity: 0, height: 0 }}
						animate={{ opacity: 1, height: "auto" }}
						exit={{ opacity: 0, height: 0 }}
					>
						{!advanceRequirements ? (
							<>
								<RequirementsTitle theme={theme}>
									Password Requirements:
								</RequirementsTitle>
								<RequirementsGrid theme={theme}>
									{strength.requirements.map((req) => (
										<RequirementItem key={req.id} theme={theme}>
											<RequirementIcon theme={theme} met={req.met}>
												{req.met ? (
													<RequirementIconSvg
														theme={theme}
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
													</RequirementIconSvg>
												) : (
													<RequirementDot theme={theme} />
												)}
											</RequirementIcon>
											<RequirementText theme={theme} met={req.met}>
												{req.label}
											</RequirementText>
										</RequirementItem>
									))}
								</RequirementsGrid>
							</>
						) : (
							<PasswordStrengthIndicator
								password={value}
								requirements={advanceRequirements}
							/>
						)}
					</RequirementsContainer>
				)}
			</AnimatePresence>

			{/* Password Suggestions */}
			<AnimatePresence>
				{shouldShowSuggestions && strength && (
					<SuggestionsContainer theme={theme}>
						{suggestedPasswords.length > 0 && (
							<>
								<SuggestionsTitle theme={theme}>
									Suggested passwords:
								</SuggestionsTitle>
								<SuggestionsGrid theme={theme}>
									{suggestedPasswords.map((suggestion, index) => (
										<SuggestionButton
											key={index}
											theme={theme}
											type="button"
											// onClick={() => {
											//     handleFieldChange('password', suggestion);
											//     handleFieldChange('confirmPassword', suggestion);
											// }}
										>
											{suggestion}
										</SuggestionButton>
									))}
								</SuggestionsGrid>
							</>
						)}
					</SuggestionsContainer>
				)}
			</AnimatePresence>

			{/* Generate Suggestions Button */}
			<AnimatePresence>
				{enableGenerate && (
					<Button
						type="button"
						variant="light"
						size="sm"
						onPress={generateSuggestions}
					>
						Generate secure password
					</Button>
				)}
			</AnimatePresence>
		</PasswordFieldContainer>
	);
}

export const PasswordField = React.memo(PasswordFieldComponent);

// ============================================================================
// Password Confirmation Field
// ============================================================================

export function PasswordConfirmationField({
	originalPassword,
	...props
}: PasswordFieldProps & { originalPassword: string }) {
	return (
		<PasswordField
			{...props}
			name={props.name || "passwordConfirmation"}
			label={props.label || "Confirm Password"}
			placeholder={props.placeholder || "Confirm your password"}
			autoComplete="new-password"
			isConfirmation={true}
			originalPassword={originalPassword}
			showStrength={false}
			showRequirements={false}
		/>
	);
}

// ============================================================================
// Password Strength Indicator
// ============================================================================

function PasswordStrengthIndicator({
	password,
	requirements,
}: {
	password: string;
	requirements?: SignUpFormProps["passwordRequirements"];
}) {
	const { theme } = useTheme();
	const strength = getPasswordStrength(password);

	const getStrengthColor = (strength: string) => {
		switch (strength) {
			case "weak":
				return "danger";
			case "fair":
				return "warning";
			case "good":
				return "primary";
			case "strong":
				return "success";
			default:
				return "default";
		}
	};

	const getStrengthText = (strength: string) => {
		switch (strength) {
			case "weak":
				return "Weak";
			case "fair":
				return "Fair";
			case "good":
				return "Good";
			case "strong":
				return "Strong";
			default:
				return "";
		}
	};

	if (!password) return null;

	return (
		<StrengthContainer theme={theme}>
			{/* Strength Bar */}
			<StrengthHeader theme={theme}>
				<Progress
					value={(strength.score / 6) * 100}
					color={getStrengthColor(strength.strength) as any}
					size="xs"
					style={{ flex: 1 }}
				/>
				<Chip
					size="sm"
					color={getStrengthColor(strength.strength) as any}
					variant="flat"
				>
					{getStrengthText(strength.strength)}
				</Chip>
			</StrengthHeader>

			{/* Feedback */}
			{strength.feedback.length > 0 && (
				<FeedbackContainer theme={theme}>
					{strength.feedback.map((feedback, index) => (
						<FeedbackItem key={index} theme={theme}>
							<FeedbackIcon theme={theme} as={ExclamationTriangleIcon} />
							<span>{feedback}</span>
						</FeedbackItem>
					))}
				</FeedbackContainer>
			)}

			{/* Requirements checklist */}
			{requirements && (
				<ChecklistContainer theme={theme}>
					{requirements.minLength && (
						<RequirementItemComponent
							met={password.length >= requirements.minLength}
							text={`At least ${requirements.minLength} characters`}
						/>
					)}
					{requirements.requireUppercase && (
						<RequirementItemComponent
							met={/[A-Z]/.test(password)}
							text="One uppercase letter"
						/>
					)}
					{requirements.requireLowercase && (
						<RequirementItemComponent
							met={/[a-z]/.test(password)}
							text="One lowercase letter"
						/>
					)}
					{requirements.requireNumbers && (
						<RequirementItemComponent
							met={/\d/.test(password)}
							text="One number"
						/>
					)}
					{requirements.requireSymbols && (
						<RequirementItemComponent
							met={/[!@#$%^&*(),.?":{}|<>]/.test(password)}
							text="One symbol"
						/>
					)}
				</ChecklistContainer>
			)}
		</StrengthContainer>
	);
}

function RequirementItemComponent({
	met,
	text,
}: { met: boolean; text: string }) {
	const { theme } = useTheme();

	return (
		<ChecklistItem theme={theme} met={met}>
			<ChecklistIcon theme={theme} met={met} as={CheckIcon} />
			<span>{text}</span>
		</ChecklistItem>
	);
}

// ============================================================================
// Export
// ============================================================================

export default PasswordField;
