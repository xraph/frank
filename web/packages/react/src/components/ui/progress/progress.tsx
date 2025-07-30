import { useTheme } from "@/theme/context";
import { type StyledProps, getColorVariant } from "@/theme/styled";
import type { Theme } from "@/theme/theme";
import { css, keyframes } from "@emotion/react";
import styled from "@emotion/styled";
import React from "react";

export interface ProgressProps extends React.HTMLAttributes<HTMLDivElement> {
	/** Progress value (0-100) */
	value?: number;
	/** Min value */
	minValue?: number;
	/** Max value */
	maxValue?: number;
	/** Progress color theme */
	color?: "primary" | "secondary" | "success" | "warning" | "danger";
	/** Progress size */
	size?: "xs" | "sm" | "md" | "lg";
	/** Progress radius */
	radius?: "none" | "sm" | "md" | "lg" | "full";
	/** Show value label */
	showValueLabel?: boolean;
	/** Custom label */
	label?: string;
	/** Value label format function */
	formatOptions?: {
		style?: "decimal" | "percent";
		minimumFractionDigits?: number;
		maximumFractionDigits?: number;
	};
	/** Indeterminate state (loading) */
	isIndeterminate?: boolean;
	/** Disabled state */
	isDisabled?: boolean;
	/** Striped progress bar */
	isStriped?: boolean;
	/** Custom class name */
	className?: string;
	/** Custom styles */
	css?: any;
}

type StyledProgressProps = StyledProps<ProgressProps>;

// Fixed: Add !important to size properties to ensure they take precedence
const getProgressSizeStyles = (props: StyledProgressProps) => {
	const { theme, size = "md" } = props;

	switch (size) {
		case "xs":
			return css`
        height: ${theme.spacing[1]} !important;
      `;
		case "sm":
			return css`
        height: ${theme.spacing[2]} !important;
      `;
		case "md":
			return css`
        height: ${theme.spacing[3]} !important;
      `;
		case "lg":
			return css`
        height: ${theme.spacing[4]} !important;
      `;
		default:
			return css`
        height: ${theme.spacing[3]} !important;
      `;
	}
};

// Fixed: Add !important to radius properties to ensure they take precedence
const getProgressRadiusStyles = (props: StyledProgressProps) => {
	const { theme, radius = "full" } = props;

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
			return css`border-radius: ${theme.borderRadius.full} !important;`;
	}
};

const getProgressColorStyles = (props: StyledProgressProps) => {
	const { theme, color = "primary", isDisabled } = props;

	if (isDisabled) {
		return css`
      opacity: 0.5;
    `;
	}

	const baseColor = getColorVariant(theme, color, 500);

	return css`
    background-color: ${baseColor};
  `;
};

// Indeterminate animation
const indeterminateAnimation = keyframes`
  0% {
    transform: translateX(-100%);
  }
  100% {
    transform: translateX(400%);
  }
`;

// Striped animation
const stripedAnimation = keyframes`
  0% {
    background-position: 0 0;
  }
  100% {
    background-position: 40px 0;
  }
`;

const ProgressContainer = styled.div<{
	showValueLabel?: boolean;
	theme: Theme;
}>`
  display: flex;
  flex-direction: column;
  gap: ${(props) => (props.showValueLabel ? props.theme.spacing[2] : 0)};
  width: 100%;
`;

const ProgressTrack = styled.div<StyledProgressProps>`
  position: relative;
  overflow: hidden;
  background-color: ${(props) => props.theme.colors.neutral[200]};
  width: 100%;

  /* Apply size and radius styles to ensure they take precedence */
  ${getProgressSizeStyles}
  ${getProgressRadiusStyles}

  ${(props) =>
		props.isDisabled &&
		css`
      opacity: 0.5;
    `}

    /* Custom CSS prop - applied last */
  ${(props) => props.css}
`;

const ProgressFill = styled.div<
	StyledProgressProps & {
		progressValue: number;
		isIndeterminate?: boolean;
		isStriped?: boolean;
	}
>`
  height: 100%;
  border-radius: inherit;
  transition: width ${(props) => props.theme.transitions.normal};
  position: relative;

  ${getProgressColorStyles}

  ${(props) =>
		props.isIndeterminate
			? css`
        width: 40%;
        position: absolute;
        animation: ${indeterminateAnimation} 1.5s infinite ease-in-out;
      `
			: css`
        width: ${props.progressValue}%;
      `}

  ${(props) =>
		props.isStriped &&
		css`
      background-image: linear-gradient(
        45deg,
        rgba(255, 255, 255, 0.15) 25%,
        transparent 25%,
        transparent 50%,
        rgba(255, 255, 255, 0.15) 50%,
        rgba(255, 255, 255, 0.15) 75%,
        transparent 75%,
        transparent
      );
      background-size: 40px 40px;
      animation: ${stripedAnimation} 1s linear infinite;
    `}
`;

const LabelContainer = styled.div`
  display: flex;
  justify-content: space-between;
  align-items: center;
`;

// Fixed: Updated to handle "xs" size
const Label = styled.span<{ size?: "xs" | "sm" | "md" | "lg"; theme: Theme }>`
  color: ${(props) => props.theme.colors.text.primary};
  font-size: ${(props) => {
		switch (props.size) {
			case "xs":
				return props.theme.fontSizes.xs;
			case "sm":
				return props.theme.fontSizes.xs;
			case "lg":
				return props.theme.fontSizes.base;
			default:
				return props.theme.fontSizes.sm;
		}
	}};
  font-weight: ${(props) => props.theme.fontWeights.medium};
`;

// Fixed: Updated to handle "xs" size
const ValueLabel = styled.span<{
	size?: "xs" | "sm" | "md" | "lg";
	theme: Theme;
}>`
  color: ${(props) => props.theme.colors.text.secondary};
  font-size: ${(props) => {
		switch (props.size) {
			case "xs":
				return props.theme.fontSizes.xs;
			case "sm":
				return props.theme.fontSizes.xs;
			case "lg":
				return props.theme.fontSizes.base;
			default:
				return props.theme.fontSizes.sm;
		}
	}};
  font-weight: ${(props) => props.theme.fontWeights.medium};
`;

export const Progress = React.forwardRef<HTMLDivElement, ProgressProps>(
	(
		{
			value = 0,
			minValue = 0,
			maxValue = 100,
			color = "primary",
			size = "md",
			radius = "full",
			showValueLabel = false,
			label,
			formatOptions = { style: "percent", maximumFractionDigits: 0 },
			isIndeterminate = false,
			isDisabled = false,
			isStriped = false,
			className,
			css,
			...props
		},
		ref,
	) => {
		const { theme } = useTheme();

		// Calculate progress percentage
		const progressValue = isIndeterminate
			? 0
			: Math.min(
					Math.max(((value - minValue) / (maxValue - minValue)) * 100, 0),
					100,
				);

		// Format value label
		const formatValue = (val: number) => {
			if (formatOptions.style === "percent") {
				return `${Math.round(progressValue)}%`;
			}
			return new Intl.NumberFormat(undefined, formatOptions).format(val);
		};

		// Fixed: Ensure all props including size and radius are passed correctly
		const progressProps = {
			...props,
			color,
			size, // Make sure size is explicitly passed
			radius, // Make sure radius is explicitly passed
			isDisabled,
			className,
			css,
		};

		const fillProps = {
			...progressProps,
			progressValue,
			isIndeterminate,
			isStriped: isStriped && !isIndeterminate,
		};

		return (
			<ProgressContainer
				theme={theme}
				ref={ref}
				showValueLabel={showValueLabel || !!label}
				role="progressbar"
				aria-valuenow={isIndeterminate ? undefined : value}
				aria-valuemin={minValue}
				aria-valuemax={maxValue}
				aria-label={label}
			>
				{(label || showValueLabel) && (
					<LabelContainer>
						{label && (
							<Label theme={theme} size={size}>
								{label}
							</Label>
						)}
						{showValueLabel && !isIndeterminate && (
							<ValueLabel theme={theme} size={size}>
								{formatValue(value)}
							</ValueLabel>
						)}
					</LabelContainer>
				)}

				<ProgressTrack theme={theme} {...progressProps}>
					<ProgressFill theme={theme} {...fillProps} />
				</ProgressTrack>
			</ProgressContainer>
		);
	},
);

Progress.displayName = "Progress";
