import { useTheme } from "@/theme/context";
import { type StyledProps, getColorVariant } from "@/theme/styled";
import { css } from "@emotion/react";
import styled from "@emotion/styled";
import React, { useState, useRef, useImperativeHandle } from "react";

export interface InputProps
	extends Omit<React.InputHTMLAttributes<HTMLInputElement>, "size"> {
	/** Input variant */
	variant?: "flat" | "bordered" | "underlined" | "faded";
	/** Input color theme */
	color?: "primary" | "secondary" | "success" | "warning" | "danger";
	/** Input size */
	size?: "sm" | "md" | "lg";
	/** Input radius */
	radius?: "none" | "sm" | "md" | "lg" | "full";
	/** Label text */
	label?: string;
	/** Placeholder text */
	placeholder?: string;
	/** Description text */
	description?: string;
	/** Error message */
	errorMessage?: string;
	/** Invalid state */
	isInvalid?: boolean;
	/** Disabled state */
	isDisabled?: boolean;
	/** Required field */
	isRequired?: boolean;
	/** Full width input */
	fullWidth?: boolean;
	/** Start content (icon) */
	startContent?: React.ReactNode;
	/** End content (icon) */
	endContent?: React.ReactNode;
	/** Custom class name */
	className?: string;
	/** Custom styles */
	css?: any;
	/** Label placement */
	labelPlacement?: "inside" | "outside" | "outside-left";
}

type StyledInputProps = StyledProps<InputProps>;

const getInputVariantStyles = (
	props: StyledInputProps & { isFocused: boolean },
) => {
	const {
		theme,
		variant = "flat",
		color = "primary",
		isInvalid,
		isFocused,
		isDisabled,
	} = props;
	const baseColor = getColorVariant(theme, color, 500);
	const errorColor = theme.colors.danger[500];

	const focusColor = isInvalid ? errorColor : baseColor;

	switch (variant) {
		case "flat":
			return css`
        background-color: ${theme.colors.background.secondary};
        border: 2px solid transparent;

        &:hover:not(:disabled) {
          background-color: ${theme.colors.background.tertiary};
        }

        ${
					isFocused &&
					css`
            background-color: ${theme.colors.background.primary};
            border-color: ${focusColor};
          `
				}

        ${
					isInvalid &&
					css`
            border-color: ${errorColor};
          `
				}

        ${
					isDisabled &&
					css`
            opacity: 0.5;
            cursor: not-allowed;
          `
				}
      `;

		case "bordered":
			return css`
        background-color: ${theme.colors.background.primary};
        border: 2px solid ${theme.colors.border.primary};

        &:hover:not(:disabled) {
          border-color: ${theme.colors.border.secondary};
        }

        ${
					isFocused &&
					css`
            border-color: ${focusColor};
          `
				}

        ${
					isInvalid &&
					css`
            border-color: ${errorColor};
          `
				}

        ${
					isDisabled &&
					css`
            opacity: 0.5;
            cursor: not-allowed;
            background-color: ${theme.colors.background.secondary};
          `
				}
      `;

		case "underlined":
			return css`
        background-color: transparent;
        border: none;
        border-bottom: 2px solid ${theme.colors.border.primary};
        /* Fixed: Don't override border-radius here, let the radius function handle it */

        &:hover:not(:disabled) {
          border-bottom-color: ${theme.colors.border.secondary};
        }

        ${
					isFocused &&
					css`
            border-bottom-color: ${focusColor};
          `
				}

        ${
					isInvalid &&
					css`
            border-bottom-color: ${errorColor};
          `
				}

        ${
					isDisabled &&
					css`
            opacity: 0.5;
            cursor: not-allowed;
          `
				}
      `;

		case "faded":
			return css`
        background-color: ${theme.colors.neutral[100]};
        border: 2px solid ${theme.colors.neutral[200]};

        &:hover:not(:disabled) {
          background-color: ${theme.colors.neutral[50]};
          border-color: ${theme.colors.neutral[300]};
        }

        ${
					isFocused &&
					css`
            background-color: ${theme.colors.background.primary};
            border-color: ${focusColor};
          `
				}

        ${
					isInvalid &&
					css`
            border-color: ${errorColor};
          `
				}

        ${
					isDisabled &&
					css`
            opacity: 0.5;
            cursor: not-allowed;
          `
				}
      `;

		default:
			return css``;
	}
};

// Fixed: Add !important to size-related properties to ensure they take precedence
const getInputSizeStyles = (props: StyledInputProps) => {
	const { theme, size = "md" } = props;

	switch (size) {
		case "sm":
			return css`
        height: ${theme.spacing[8]} !important;
        padding: 0 ${theme.spacing[3]} !important;
        font-size: ${theme.fontSizes.sm} !important;
      `;
		case "md":
			return css`
        height: ${theme.spacing[10]} !important;
        padding: 0 ${theme.spacing[4]} !important;
        font-size: ${theme.fontSizes.base} !important;
      `;
		case "lg":
			return css`
        height: ${theme.spacing[12]} !important;
        padding: 0 ${theme.spacing[6]} !important;
        font-size: ${theme.fontSizes.lg} !important;
      `;
		default:
			return css``;
	}
};

// Fixed: Always apply border-radius, even for underlined variant (unless specifically none)
// and use !important to ensure it overrides other styles
const getInputRadiusStyles = (props: StyledInputProps) => {
	const { theme, radius = "md", variant } = props;

	// For underlined variant, only apply radius if it's not the default
	// This preserves the underlined look while allowing customization
	if (variant === "underlined" && radius === "md") {
		return css`border-radius: 0 !important;`;
	}

	switch (radius) {
		case "none":
			return css`border-radius: ${theme.borderRadius.none} !important;`;
		case "sm":
			return css`border-radius: ${theme.borderRadius.sm} !important;`;
		case "md":
			return css`border-radius: ${theme.borderRadius.md} !important;`;
		case "lg":
			return css`border-radius: ${theme.borderRadius.lg} !important;`;
		case "full":
			return css`border-radius: ${theme.borderRadius.full} !important;`;
		default:
			return css`border-radius: ${theme.borderRadius.md} !important;`;
	}
};

const InputWrapper = styled.div<StyledInputProps & { isFocused: boolean }>`
  position: relative;
  display: flex;
  align-items: center;
  transition: all ${(props) => props.theme.transitions.normal};
  width: ${(props) => (props.fullWidth ? "100%" : "auto")};

  /* Apply base styles first */
  ${getInputVariantStyles}
  ${getInputSizeStyles}

    /* Apply radius styles last to ensure they take precedence */
  ${getInputRadiusStyles}

    /* Custom CSS prop - applied last */
  ${(props) => props.css}
`;

const StyledInput = styled.input<StyledProps>`
  flex: 1;
  background: transparent;
  border: none;
  outline: none;
  color: ${(props) => props.theme.colors.text.primary};
  font-family: inherit;
  font-size: inherit;
  padding: 0;

  &::placeholder {
    color: ${(props) => props.theme.colors.text.tertiary};
  }

  &:disabled {
    cursor: not-allowed;
  }
`;

const InputContainer = styled.div<StyledInputProps & { fullWidth?: boolean }>`
  display: flex;
  flex-direction: column;
  gap: ${(props) => props.theme.spacing[2]};
  width: ${(props) => (props.fullWidth ? "100%" : "auto")};
`;

const Label = styled.label<
	StyledInputProps & {
		isRequired?: boolean;
		size?: "sm" | "md" | "lg";
		placement?: "inside" | "outside" | "outside-left";
	}
>`
  color: ${(props) => props.theme.colors.text.primary};
  font-size: ${(props) => {
		switch (props.size) {
			case "sm":
				return props.theme.fontSizes.sm;
			case "lg":
				return props.theme.fontSizes.lg;
			default:
				return props.theme.fontSizes.base;
		}
	}};
  font-weight: ${(props) => props.theme.fontWeights.medium};

  ${(props) =>
		props.isRequired &&
		css`
      &::after {
        content: ' *';
        color: ${props.theme.colors.danger[500]};
      }
    `}
`;

export const HelperText = styled.div<StyledInputProps & { isError?: boolean }>`
  font-size: ${(props) => props.theme.fontSizes.sm};
  color: ${(props) =>
		props.isError
			? props.theme.colors.danger[500]
			: props.theme.colors.text.secondary};
`;

const ContentWrapper = styled.div<
	StyledInputProps & { position: "start" | "end" }
>`
  display: flex;
  align-items: center;
  color: ${(props) => props.theme.colors.text.tertiary};
  ${(props) =>
		props.position === "start"
			? css`margin-right: ${props.theme.spacing[2]};`
			: css`margin-left: ${props.theme.spacing[2]};`}
`;

export const Input = React.forwardRef<HTMLInputElement, InputProps>(
	(
		{
			variant = "flat",
			color = "primary",
			size = "md",
			radius = "md",
			label,
			placeholder,
			description,
			errorMessage,
			isInvalid = false,
			isDisabled = false,
			isRequired = false,
			fullWidth = false,
			startContent,
			endContent,
			className,
			css,
			labelPlacement = "outside",
			onFocus,
			onBlur,
			...props
		},
		ref,
	) => {
		const { theme } = useTheme();
		const [isFocused, setIsFocused] = useState(false);
		const inputRef = useRef<HTMLInputElement>(null);

		useImperativeHandle(ref, () => inputRef.current!);

		const handleFocus = (e: React.FocusEvent<HTMLInputElement>) => {
			setIsFocused(true);
			onFocus?.(e);
		};

		const handleBlur = (e: React.FocusEvent<HTMLInputElement>) => {
			setIsFocused(false);
			onBlur?.(e);
		};

		// Fixed: Ensure all props including radius are passed correctly
		const inputProps = {
			variant,
			color,
			size,
			radius, // Make sure radius is explicitly passed
			isInvalid: isInvalid || !!errorMessage,
			isDisabled,
			fullWidth,
			isFocused,
			className,
			css,
		};

		const inputElement = (
			<InputWrapper theme={theme} {...inputProps}>
				{startContent && (
					<ContentWrapper theme={theme} position="start">
						{startContent}
					</ContentWrapper>
				)}
				<StyledInput
					theme={theme}
					ref={inputRef}
					placeholder={placeholder}
					disabled={isDisabled}
					onFocus={handleFocus}
					onBlur={handleBlur}
					{...props}
				/>
				{endContent && (
					<ContentWrapper theme={theme} position="end">
						{endContent}
					</ContentWrapper>
				)}
			</InputWrapper>
		);

		if (!label && !description && !errorMessage) {
			return inputElement;
		}

		return (
			<InputContainer theme={theme} fullWidth={fullWidth}>
				{label && labelPlacement === "outside" && (
					<Label theme={theme} isRequired={isRequired} size={size}>
						{label}
					</Label>
				)}
				{inputElement}
				{(description || errorMessage) && (
					<HelperText theme={theme} isError={!!errorMessage}>
						{errorMessage || description}
					</HelperText>
				)}
			</InputContainer>
		);
	},
);

Input.displayName = "Input";
