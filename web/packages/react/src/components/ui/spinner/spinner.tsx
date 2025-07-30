import { useTheme } from "@/theme/context";
import { type StyledProps, getColorVariant } from "@/theme/styled";
import type { Theme } from "@/theme/theme";
import { css, keyframes } from "@emotion/react";
import styled from "@emotion/styled";
import React from "react";

export interface SpinnerProps extends React.HTMLAttributes<HTMLDivElement> {
	/** Spinner color theme */
	color?:
		| "primary"
		| "secondary"
		| "success"
		| "warning"
		| "danger"
		| "current";
	/** Spinner size */
	size?: "sm" | "md" | "lg" | number;
	/** Label text */
	label?: string;
	/** Label placement */
	labelPlacement?: "start" | "end" | "top" | "bottom";
	/** Custom class name */
	className?: string;
	/** Custom styles */
	css?: any;
}

type StyledSpinnerProps = StyledProps<SpinnerProps>;

const spin = keyframes`
  0% {
    transform: rotate(0deg);
  }
  100% {
    transform: rotate(360deg);
  }
`;

const getSpinnerColorStyles = (props: StyledSpinnerProps) => {
	const { theme, color = "primary" } = props;

	if (color === "current") {
		return css`
      border-color: currentColor;
      border-top-color: transparent;
    `;
	}

	const baseColor = getColorVariant(theme, color, 500);
	const lightColor = getColorVariant(theme, color, 200);

	return css`
    border-color: ${lightColor};
    border-top-color: ${baseColor};
  `;
};

const getSpinnerSizeStyles = (props: StyledSpinnerProps) => {
	const { size = "md" } = props;

	if (typeof size === "number") {
		return css`
      width: ${size}px;
      height: ${size}px;
      border-width: ${Math.max(2, size / 8)}px;
    `;
	}

	switch (size) {
		case "sm":
			return css`
        width: 16px;
        height: 16px;
        border-width: 2px;
      `;
		case "md":
			return css`
        width: 24px;
        height: 24px;
        border-width: 2px;
      `;
		case "lg":
			return css`
        width: 32px;
        height: 32px;
        border-width: 3px;
      `;
		default:
			return css`
        width: 24px;
        height: 24px;
        border-width: 2px;
      `;
	}
};

const StyledSpinner = styled.div<StyledSpinnerProps>`
  border-style: solid;
  border-radius: 50%;
  animation: ${spin} 1s linear infinite;

  ${getSpinnerColorStyles}
  ${getSpinnerSizeStyles}

  /* Custom CSS prop */
  ${(props) => props.css}
`;

const SpinnerContainer = styled.div<{
	labelPlacement?: "start" | "end" | "top" | "bottom";
	theme: Theme;
}>`
  display: inline-flex;
  align-items: center;
  gap: ${(props) => props.theme.spacing[2]};

  ${(props) => {
		switch (props.labelPlacement) {
			case "top":
				return css`
          flex-direction: column-reverse;
        `;
			case "bottom":
				return css`
          flex-direction: column;
        `;
			case "start":
				return css`
          flex-direction: row-reverse;
        `;
			default:
				return css`
          flex-direction: row;
        `;
		}
	}}
`;

const Label = styled.span<{ size?: "sm" | "md" | "lg" | number; theme: Theme }>`
  color: ${(props) => props.theme.colors.text.secondary};
  font-size: ${(props) => {
		if (typeof props.size === "number") {
			return `${Math.max(12, props.size * 0.6)}px`;
		}

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
`;

export const Spinner = React.forwardRef<HTMLDivElement, SpinnerProps>(
	(
		{
			color = "primary",
			size = "md",
			label,
			labelPlacement = "end",
			className,
			css,
			...props
		},
		ref,
	) => {
		const { theme } = useTheme();

		const spinnerProps = {
			...props,
			color,
			size,
			className,
			css,
		};

		const spinnerElement = <StyledSpinner theme={theme} {...spinnerProps} />;

		if (!label) {
			return React.cloneElement(spinnerElement, { ref });
		}

		return (
			<SpinnerContainer theme={theme} labelPlacement={labelPlacement}>
				{spinnerElement}
				<Label theme={theme} size={size}>
					{label}
				</Label>
			</SpinnerContainer>
		);
	},
);

Spinner.displayName = "Spinner";
