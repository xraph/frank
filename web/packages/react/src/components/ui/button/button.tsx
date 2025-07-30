"use client";

import { useTheme } from "@/theme/context";
import { type StyledProps, getColorVariant } from "@/theme/styled";
import { css } from "@emotion/react";
import styled from "@emotion/styled";
import React from "react";

export interface ButtonProps
	extends React.ButtonHTMLAttributes<HTMLButtonElement> {
	/** Button variant */
	variant?: "solid" | "outlined" | "light" | "flat" | "ghost";
	/** Button color theme */
	color?: "primary" | "secondary" | "success" | "warning" | "danger";
	/** Button size */
	size?: "sm" | "md" | "lg";
	/** Button radius */
	radius?: "none" | "sm" | "md" | "lg" | "full";
	/** Loading state */
	isLoading?: boolean;
	/** Disabled state */
	isDisabled?: boolean;
	/** Full width button */
	fullWidth?: boolean;
	/** Icon only button */
	isIconOnly?: boolean;
	/** Start content (icon) */
	startContent?: React.ReactNode;
	/** End content (icon) */
	endContent?: React.ReactNode;
	/** Custom class name */
	className?: string;
	/** Custom styles */
	css?: any;
	onPress?: (e: MouseEvent) => void;
}

type StyledButtonProps = StyledProps<ButtonProps>;

const getButtonVariantStyles = (props: StyledButtonProps) => {
	const { theme, variant = "solid", color = "primary", isDisabled } = props;
	const baseColor = getColorVariant(theme, color, 500);
	const hoverColor = getColorVariant(theme, color, 600);
	const lightColor = getColorVariant(theme, color, 50);
	const darkColor = getColorVariant(theme, color, 700);

	const disabledStyles = css`
    opacity: 0.5;
    cursor: not-allowed;
    pointer-events: none;
  `;

	switch (variant) {
		case "solid":
			return css`
        background-color: ${baseColor};
        color: ${theme.colors.text.inverse};
        border: 2px solid ${baseColor};

        &:hover:not(:disabled) {
          background-color: ${hoverColor};
          border-color: ${hoverColor};
        }

        &:active:not(:disabled) {
          background-color: ${darkColor};
          border-color: ${darkColor};
        }

        ${isDisabled && disabledStyles}
      `;

		case "outlined":
			return css`
        background-color: transparent;
        color: ${baseColor};
        border: 2px solid ${baseColor};

        &:hover:not(:disabled) {
          background-color: ${lightColor};
        }

        &:active:not(:disabled) {
          background-color: ${getColorVariant(theme, color, 100)};
        }

        ${isDisabled && disabledStyles}
      `;

		case "light":
			return css`
        background-color: ${lightColor};
        color: ${darkColor};
        border: 2px solid transparent;

        &:hover:not(:disabled) {
          background-color: ${getColorVariant(theme, color, 100)};
        }

        &:active:not(:disabled) {
          background-color: ${getColorVariant(theme, color, 200)};
        }

        ${isDisabled && disabledStyles}
      `;

		case "flat":
			return css`
        background-color: ${getColorVariant(theme, color, 100)};
        color: ${baseColor};
        border: 2px solid transparent;

        &:hover:not(:disabled) {
          background-color: ${getColorVariant(theme, color, 200)};
        }

        &:active:not(:disabled) {
          background-color: ${getColorVariant(theme, color, 300)};
        }

        ${isDisabled && disabledStyles}
      `;

		case "ghost":
			return css`
        background-color: transparent;
        color: ${baseColor};
        border: 2px solid transparent;

        &:hover:not(:disabled) {
          background-color: ${lightColor};
        }

        &:active:not(:disabled) {
          background-color: ${getColorVariant(theme, color, 100)};
        }

        ${isDisabled && disabledStyles}
      `;

		default:
			return css`
        background-color: transparent;
        color: ${baseColor};
        border: 2px solid ${baseColor};

        &:hover:not(:disabled) {
          background-color: ${lightColor};
        }

        &:active:not(:disabled) {
          background-color: ${getColorVariant(theme, color, 100)};
        }

        ${isDisabled && disabledStyles}
			`;
	}
};

// Fixed: Add !important to size-related properties to ensure they take precedence
const getButtonSizeStyles = (props: StyledButtonProps) => {
	const { theme, size = "md", isIconOnly } = props;

	if (isIconOnly) {
		switch (size) {
			case "sm":
				return css`
          min-width: ${theme.spacing[8]} !important;
          height: ${theme.spacing[8]} !important;
          padding: 0 !important;
        `;
			case "md":
				return css`
          min-width: ${theme.spacing[10]} !important;
          height: ${theme.spacing[10]} !important;
          padding: 0 !important;
        `;
			case "lg":
				return css`
          min-width: ${theme.spacing[12]} !important;
          height: ${theme.spacing[12]} !important;
          padding: 0 !important;
        `;
			default:
				return css``;
		}
	}

	switch (size) {
		case "sm":
			return css`
        height: ${theme.spacing[8]} !important;
        padding: 0 ${theme.spacing[3]} !important;
        font-size: ${theme.fontSizes.sm} !important;
        min-width: ${theme.spacing[16]} !important;
      `;
		case "md":
			return css`
        height: ${theme.spacing[10]} !important;
        padding: 0 ${theme.spacing[4]} !important;
        font-size: ${theme.fontSizes.base} !important;
        min-width: ${theme.spacing[20]} !important;
      `;
		case "lg":
			return css`
        height: ${theme.spacing[12]} !important;
        padding: 0 ${theme.spacing[6]} !important;
        font-size: ${theme.fontSizes.lg} !important;
        min-width: ${theme.spacing[24]} !important;
      `;
		default:
			return css``;
	}
};

// Fixed: Ensure border-radius is applied with !important to override any conflicting styles
const getButtonRadiusStyles = (props: StyledButtonProps) => {
	const { theme, radius = "md" } = props;

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

const StyledButton = styled.button<StyledButtonProps>`
  display: inline-flex;
  align-items: center;
  justify-content: center;
  gap: ${(props) => props.theme.spacing[2]};
  font-family: inherit;
  font-weight: ${(props) => props.theme.fontWeights.medium};
  line-height: ${(props) => props.theme.lineHeights.tight};
  text-decoration: none;
  cursor: pointer;
  transition: all ${(props) => props.theme.transitions.normal};
  position: relative;
  overflow: hidden;
  white-space: nowrap;
  user-select: none;
  outline: none;

  /* Apply base styles first */
  ${getButtonVariantStyles}
  ${getButtonSizeStyles}

    /* Apply radius styles last to ensure they take precedence */
  ${getButtonRadiusStyles}

  ${(props) =>
		props.fullWidth &&
		css`
      width: 100%;
    `}

  &:focus-visible {
    outline: 2px solid ${(props) => props.theme.colors.border.focus};
    outline-offset: 2px;
  }

  /* Custom CSS prop - applied last */
  ${(props) => props.css}
`;

const LoadingSpinner = styled.div<{ size?: "sm" | "md" | "lg" }>`
  width: ${(props) => {
		switch (props.size) {
			case "sm":
				return "12px";
			case "lg":
				return "20px";
			default:
				return "16px";
		}
	}};
  height: ${(props) => {
		switch (props.size) {
			case "sm":
				return "12px";
			case "lg":
				return "20px";
			default:
				return "16px";
		}
	}};
  border: 2px solid currentColor;
  border-radius: 50%;
  border-top-color: transparent;
  animation: spin 1s linear infinite;

  @keyframes spin {
    to {
      transform: rotate(360deg);
    }
  }
`;

export const Button = React.forwardRef<HTMLButtonElement, ButtonProps>(
	(
		{
			children,
			variant = "solid",
			color = "primary",
			size = "md",
			radius = "md",
			isLoading = false,
			isDisabled = false,
			fullWidth = false,
			isIconOnly = false,
			startContent,
			endContent,
			className,
			css,
			onPress,
			...props
		},
		ref,
	) => {
		const { theme } = useTheme();
		const optionalProps = {} as Record<string, any>;
		if (onPress) {
			optionalProps.onClick = onPress;
		}

		// Fixed: Ensure all props including radius are passed correctly
		const buttonProps = {
			...optionalProps,
			...props,
			variant,
			color,
			size,
			radius, // Make sure radius is explicitly passed
			isDisabled: isDisabled || isLoading,
			fullWidth,
			isIconOnly,
			className,
			disabled: isDisabled || isLoading,
			css,
		};

		return (
			<StyledButton theme={theme} ref={ref} {...buttonProps}>
				{isLoading && <LoadingSpinner size={size} />}
				{!isLoading && startContent && startContent}
				{children}
				{!isLoading && endContent && endContent}
			</StyledButton>
		);
	},
);

Button.displayName = "Button";
