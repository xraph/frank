import { useTheme } from "@/theme/context";
import { type StyledProps, getColorVariant } from "@/theme/styled";
import { css } from "@emotion/react";
import styled from "@emotion/styled";
import React from "react";

export interface ChipProps extends React.HTMLAttributes<HTMLDivElement> {
	/** Chip variant */
	variant?:
		| "solid"
		| "bordered"
		| "light"
		| "flat"
		| "faded"
		| "shadow"
		| "dot";
	/** Chip color theme */
	color?: "primary" | "secondary" | "success" | "warning" | "danger";
	/** Chip size */
	size?: "sm" | "md" | "lg";
	/** Chip radius */
	radius?: "none" | "sm" | "md" | "lg" | "full";
	/** Disabled state */
	isDisabled?: boolean;
	/** Closable chip with close button */
	isClosable?: boolean;
	/** Close button callback */
	onClose?: () => void;
	/** Start content (icon or avatar) */
	startContent?: React.ReactNode;
	/** End content (icon) */
	endContent?: React.ReactNode;
	/** Custom class name */
	className?: string;
	/** Custom styles */
	css?: any;
}

type StyledChipProps = StyledProps<ChipProps>;

const getChipVariantStyles = (props: StyledChipProps) => {
	const { theme, variant = "solid", color = "primary", isDisabled } = props;
	const baseColor = getColorVariant(theme, color, 500);
	const lightColor = getColorVariant(theme, color, 50);
	const darkColor = getColorVariant(theme, color, 700);

	if (isDisabled) {
		return css`
      opacity: 0.5;
      cursor: not-allowed;
      pointer-events: none;
    `;
	}

	switch (variant) {
		case "solid":
			return css`
        background-color: ${baseColor};
        color: ${theme.colors.text.inverse};
        border: 1px solid transparent;
      `;

		case "bordered":
			return css`
        background-color: transparent;
        color: ${baseColor};
        border: 1px solid ${baseColor};
      `;

		case "light":
			return css`
        background-color: ${lightColor};
        color: ${darkColor};
        border: 1px solid transparent;
      `;

		case "flat":
			return css`
        background-color: ${getColorVariant(theme, color, 100)};
        color: ${baseColor};
        border: 1px solid transparent;
      `;

		case "faded":
			return css`
        background-color: ${theme.colors.neutral[100]};
        color: ${baseColor};
        border: 1px solid ${theme.colors.neutral[200]};
      `;

		case "shadow":
			return css`
        background-color: ${baseColor};
        color: ${theme.colors.text.inverse};
        border: 1px solid transparent;
        box-shadow: ${theme.shadows.md};
      `;

		case "dot":
			return css`
        background-color: ${theme.colors.background.secondary};
        color: ${theme.colors.text.primary};
        border: 1px solid ${theme.colors.border.primary};
        position: relative;

        &::before {
          content: '';
          position: absolute;
          left: 8px;
          top: 50%;
          transform: translateY(-50%);
          width: 6px;
          height: 6px;
          border-radius: 50%;
          background-color: ${baseColor};
        }
      `;

		default:
			return css``;
	}
};

const getChipSizeStyles = (props: StyledChipProps) => {
	const { theme, size = "md", variant } = props;

	const dotPadding = variant === "dot" ? theme.spacing[5] : theme.spacing[3];

	switch (size) {
		case "sm":
			return css`
        height: ${theme.spacing[6]};
        padding: 0 ${variant === "dot" ? theme.spacing[4] : theme.spacing[2]};
        padding-left: ${variant === "dot" ? theme.spacing[4] : theme.spacing[2]};
        font-size: ${theme.fontSizes.xs};
        gap: ${theme.spacing[1]};
      `;
		case "md":
			return css`
        height: ${theme.spacing[8]};
        padding: 0 ${variant === "dot" ? dotPadding : theme.spacing[3]};
        padding-left: ${variant === "dot" ? dotPadding : theme.spacing[3]};
        font-size: ${theme.fontSizes.sm};
        gap: ${theme.spacing[2]};
      `;
		case "lg":
			return css`
        height: ${theme.spacing[10]};
        padding: 0 ${variant === "dot" ? theme.spacing[6] : theme.spacing[4]};
        padding-left: ${variant === "dot" ? theme.spacing[6] : theme.spacing[4]};
        font-size: ${theme.fontSizes.base};
        gap: ${theme.spacing[2]};
      `;
		default:
			return css``;
	}
};

const getChipRadiusStyles = (props: StyledChipProps) => {
	const { theme, radius = "full" } = props;

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
			return css`border-radius: ${theme.borderRadius.full};`;
	}
};

const StyledChip = styled.div<StyledChipProps>`
  display: inline-flex;
  align-items: center;
  justify-content: center;
  font-family: inherit;
  font-weight: ${(props) => props.theme.fontWeights.medium};
  line-height: ${(props) => props.theme.lineHeights.tight};
  white-space: nowrap;
  user-select: none;
  position: relative;
  transition: all ${(props) => props.theme.transitions.normal};

  ${getChipVariantStyles}
  ${getChipSizeStyles}
  ${getChipRadiusStyles}

  /* Custom CSS prop */
  ${(props) => props.css}
`;

const CloseButton = styled.button<
	StyledChipProps & { size?: "sm" | "md" | "lg" }
>`
  display: inline-flex;
  align-items: center;
  justify-content: center;
  background: none;
  border: none;
  cursor: pointer;
  padding: 0;
  margin: 0;
  color: inherit;
  opacity: 0.7;
  transition: opacity ${(props) => props.theme.transitions.fast};
  width: ${(props) => {
		switch (props.size) {
			case "sm":
				return "14px";
			case "lg":
				return "18px";
			default:
				return "16px";
		}
	}};
  height: ${(props) => {
		switch (props.size) {
			case "sm":
				return "14px";
			case "lg":
				return "18px";
			default:
				return "16px";
		}
	}};

  &:hover {
    opacity: 1;
  }

  &:focus {
    outline: none;
  }
`;

const CloseIcon = ({ size }: { size?: "sm" | "md" | "lg" }) => (
	// biome-ignore lint/a11y/noSvgWithoutTitle: <explanation>
	<svg
		width="100%"
		height="100%"
		viewBox="0 0 24 24"
		fill="none"
		stroke="currentColor"
		strokeWidth="2"
		strokeLinecap="round"
		strokeLinejoin="round"
	>
		<line x1="18" y1="6" x2="6" y2="18" />
		<line x1="6" y1="6" x2="18" y2="18" />
	</svg>
);

export const Chip = React.forwardRef<HTMLDivElement, ChipProps>(
	(
		{
			children,
			variant = "solid",
			color = "primary",
			size = "md",
			radius = "full",
			isDisabled = false,
			isClosable = false,
			onClose,
			startContent,
			endContent,
			className,
			css,
			...props
		},
		ref,
	) => {
		const { theme } = useTheme();

		const chipProps = {
			...props,
			variant,
			color,
			size,
			radius,
			isDisabled,
			className,
			css,
		};

		const handleClose = (e: React.MouseEvent) => {
			e.stopPropagation();
			onClose?.();
		};

		return (
			<StyledChip theme={theme} ref={ref} {...chipProps}>
				{startContent}
				{children}
				{endContent}
				{isClosable && !isDisabled && (
					<CloseButton
						theme={theme}
						size={size}
						onClick={handleClose}
						aria-label="Remove"
					>
						<CloseIcon size={size} />
					</CloseButton>
				)}
			</StyledChip>
		);
	},
);

Chip.displayName = "Chip";
