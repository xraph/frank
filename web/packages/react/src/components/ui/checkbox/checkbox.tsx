import { useTheme } from "@/theme/context";
import { type StyledProps, getColorVariant } from "@/theme/styled";
import type { Theme } from "@/theme/theme";
import { css } from "@emotion/react";
import styled from "@emotion/styled";
import React, { useState, useRef, useImperativeHandle } from "react";

export interface CheckboxProps
	extends Omit<React.InputHTMLAttributes<HTMLInputElement>, "size"> {
	/** Checkbox color theme */
	color?: "primary" | "secondary" | "success" | "warning" | "danger";
	/** Checkbox size */
	size?: "sm" | "md" | "lg";
	/** Checkbox radius */
	radius?: "none" | "sm" | "md" | "lg" | "full";
	/** Label text */
	children?: React.ReactNode;
	/** Description text */
	description?: string;
	/** Indeterminate state */
	isIndeterminate?: boolean;
	/** Invalid state */
	isInvalid?: boolean;
	/** Disabled state */
	isDisabled?: boolean;
	/** Required field */
	isRequired?: boolean;
	/** Custom class name */
	className?: string;
	/** Custom styles */
	css?: any;
	/** Icon for checked state */
	icon?: React.ReactNode;
}

type StyledCheckboxProps = StyledProps<CheckboxProps>;

const getCheckboxSizeStyles = (props: StyledCheckboxProps) => {
	const { size = "md" } = props;

	switch (size) {
		case "sm":
			return css`
        width: 16px;
        height: 16px;
      `;
		case "md":
			return css`
        width: 20px;
        height: 20px;
      `;
		case "lg":
			return css`
        width: 24px;
        height: 24px;
      `;
		default:
			return css`
        width: 20px;
        height: 20px;
      `;
	}
};

const getCheckboxRadiusStyles = (props: StyledCheckboxProps) => {
	const { theme, radius = "sm" } = props;

	switch (radius) {
		case "none":
			return css`border-radius: ${theme.borderRadius.none};`;
		case "sm":
			return css`border-radius: ${theme.borderRadius.sm};`;
		case "md":
			return css`border-radius: ${theme.borderRadius.md};`;
		case "lg":
			return css`border-radius: ${theme.borderRadius.lg};`;
		case "full":
			return css`border-radius: ${theme.borderRadius.full};`;
		default:
			return css`border-radius: ${theme.borderRadius.sm};`;
	}
};

const getCheckboxColorStyles = (
	props: StyledCheckboxProps & {
		isChecked: boolean;
		isIndeterminate: boolean;
		isFocused: boolean;
	},
) => {
	const {
		theme,
		color = "primary",
		isInvalid,
		isDisabled,
		isChecked,
		isIndeterminate,
		isFocused,
	} = props;
	const baseColor = getColorVariant(theme, color, 500);
	const hoverColor = getColorVariant(theme, color, 600);
	const errorColor = theme.colors.danger[500];

	const activeColor = isInvalid ? errorColor : baseColor;

	if (isDisabled) {
		return css`
      opacity: 0.5;
      cursor: not-allowed;
      background-color: ${theme.colors.neutral[200]};
      border-color: ${theme.colors.neutral[300]};
    `;
	}

	if (isChecked || isIndeterminate) {
		return css`
      background-color: ${activeColor};
      border-color: ${activeColor};
      color: ${theme.colors.text.inverse};

      &:hover {
        background-color: ${isInvalid ? errorColor : hoverColor};
        border-color: ${isInvalid ? errorColor : hoverColor};
      }
    `;
	}

	return css`
    background-color: ${theme.colors.background.primary};
    border-color: ${isInvalid ? errorColor : theme.colors.border.primary};
    color: transparent;

    &:hover {
      border-color: ${isInvalid ? errorColor : theme.colors.border.secondary};
    }

    ${
			isFocused &&
			css`
        border-color: ${activeColor};
        box-shadow: 0 0 0 2px ${activeColor}20;
      `
		}
  `;
};

// Updated container with better alignment
const CheckboxContainer = styled.label<{ isDisabled?: boolean; theme: Theme }>`
  display: inline-flex;
  align-items: flex-start;
  gap: ${(props) => props.theme.spacing[2]};
  cursor: ${(props) => (props.isDisabled ? "not-allowed" : "pointer")};
  user-select: none;
  line-height: 1;
`;

const HiddenInput = styled.input`
  position: absolute;
  opacity: 0;
  pointer-events: none;
  margin: 0;
  width: 0;
  height: 0;
  top: 1px;
`;

// Updated wrapper with better vertical alignment
const CheckboxWrapper = styled.div<
	StyledCheckboxProps & {
		isChecked: boolean;
		isIndeterminate: boolean;
		isFocused: boolean;
	}
>`
  position: relative;
  display: inline-flex;
  align-items: center;
  justify-content: center;
  border: 2px solid;
  transition: all ${(props) => props.theme.transitions.normal};
  flex-shrink: 0;

  /* Improved alignment with text baseline */
  margin-top: ${(props) => {
		switch (props.size) {
			case "sm":
				return "1px"; // Small offset for sm size
			case "md":
				return "2px"; // Medium offset for md size
			case "lg":
				return "3px"; // Larger offset for lg size
			default:
				return "2px";
		}
	}};

  ${getCheckboxSizeStyles}
  ${getCheckboxRadiusStyles}
  ${getCheckboxColorStyles}

    /* Custom CSS prop */
  ${(props) => props.css}
`;

const CheckIcon = () => (
	<svg
		width="100%"
		height="100%"
		viewBox="0 0 24 24"
		fill="none"
		stroke="currentColor"
		strokeWidth="3"
		strokeLinecap="round"
		strokeLinejoin="round"
		aria-hidden="true"
	>
		<polyline points="20,6 9,17 4,12" />
	</svg>
);

const IndeterminateIcon = () => (
	<svg
		width="100%"
		height="100%"
		viewBox="0 0 24 24"
		fill="none"
		stroke="currentColor"
		strokeWidth="3"
		strokeLinecap="round"
		strokeLinejoin="round"
		aria-hidden="true"
	>
		<line x1="5" y1="12" x2="19" y2="12" />
	</svg>
);

const IconWrapper = styled.div<{ size?: "sm" | "md" | "lg" }>`
  width: ${(props) => {
		switch (props.size) {
			case "sm":
				return "10px";
			case "lg":
				return "16px";
			default:
				return "12px";
		}
	}};
  height: ${(props) => {
		switch (props.size) {
			case "sm":
				return "10px";
			case "lg":
				return "16px";
			default:
				return "12px";
		}
	}};
`;

// Updated label content with better line height
const LabelContent = styled.div<{ theme: Theme }>`
  display: flex;
  flex-direction: column;
  gap: ${(props) => props.theme.spacing[1]};
  min-height: 0; /* Allows proper flex behavior */
`;

// Updated label text with proper line height for alignment
const LabelText = styled.span<{
	size?: "sm" | "md" | "lg";
	isRequired?: boolean;
	theme: Theme;
}>`
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
  line-height: ${(props) => {
		switch (props.size) {
			case "sm":
				return "1.25"; // Tighter line height for small
			case "lg":
				return "1.4"; // More relaxed for large
			default:
				return "1.5"; // Standard line height
		}
	}};
  margin: 0; /* Remove default margins */

  ${(props) =>
		props.isRequired &&
		css`
      &::after {
        content: ' *';
        color: ${props.theme.colors.danger[500]};
      }
    `}
`;

// Updated description with consistent spacing
const Description = styled.span<{ size?: "sm" | "md" | "lg"; theme: Theme }>`
  color: ${(props) => props.theme.colors.text.secondary};
  font-size: ${(props) => {
		switch (props.size) {
			case "sm":
				return props.theme.fontSizes.xs;
			case "lg":
				return props.theme.fontSizes.sm;
			default:
				return props.theme.fontSizes.sm;
		}
	}};
  line-height: ${(props) => {
		switch (props.size) {
			case "sm":
				return "1.3";
			case "lg":
				return "1.4";
			default:
				return "1.4";
		}
	}};
  margin: 0; /* Remove default margins */
`;

export const Checkbox = React.forwardRef<HTMLInputElement, CheckboxProps>(
	(
		{
			children,
			color = "primary",
			size = "md",
			radius = "sm",
			description,
			isIndeterminate = false,
			isInvalid = false,
			isDisabled = false,
			isRequired = false,
			className,
			css,
			icon,
			checked,
			defaultChecked,
			onChange,
			onFocus,
			onBlur,
			...props
		},
		ref,
	) => {
		const { theme } = useTheme();
		const [isChecked, setIsChecked] = useState(defaultChecked || false);
		const [isFocused, setIsFocused] = useState(false);
		const inputRef = useRef<HTMLInputElement>(null);

		useImperativeHandle(ref, () => inputRef.current!);

		const controlledChecked = checked !== undefined ? checked : isChecked;

		const handleChange = (e: React.ChangeEvent<HTMLInputElement>) => {
			if (checked === undefined) {
				setIsChecked(e.target.checked);
			}
			onChange?.(e);
		};

		const handleFocus = (e: React.FocusEvent<HTMLInputElement>) => {
			setIsFocused(true);
			onFocus?.(e);
		};

		const handleBlur = (e: React.FocusEvent<HTMLInputElement>) => {
			setIsFocused(false);
			onBlur?.(e);
		};

		const checkboxProps = {
			color,
			size,
			radius,
			isInvalid,
			isDisabled,
			isChecked: controlledChecked,
			isIndeterminate,
			isFocused,
			className,
			css,
		};

		return (
			<CheckboxContainer theme={theme} isDisabled={isDisabled}>
				<CheckboxWrapper theme={theme} {...checkboxProps}>
					<HiddenInput
						ref={inputRef}
						type="checkbox"
						checked={controlledChecked}
						disabled={isDisabled}
						onChange={handleChange}
						onFocus={handleFocus}
						onBlur={handleBlur}
						{...props}
					/>
					{(controlledChecked || isIndeterminate) && (
						<IconWrapper size={size}>
							{icon ||
								(isIndeterminate ? <IndeterminateIcon /> : <CheckIcon />)}
						</IconWrapper>
					)}
				</CheckboxWrapper>
				{(children || description) && (
					<LabelContent theme={theme}>
						{children && (
							<LabelText theme={theme} size={size} isRequired={isRequired}>
								{children}
							</LabelText>
						)}
						{description && (
							<Description theme={theme} size={size}>
								{description}
							</Description>
						)}
					</LabelContent>
				)}
			</CheckboxContainer>
		);
	},
);

Checkbox.displayName = "Checkbox";
