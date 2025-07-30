import { useTheme } from "@/theme/context";
import { type StyledProps, getColorVariant } from "@/theme/styled";
import { css } from "@emotion/react";
import styled from "@emotion/styled";
import React from "react";

export interface AlertProps extends React.HTMLAttributes<HTMLDivElement> {
	/** Alert variant */
	variant?: "solid" | "bordered" | "light" | "flat";
	/** Alert color theme */
	color?: "primary" | "secondary" | "success" | "warning" | "danger";
	/** Alert radius */
	radius?: "none" | "sm" | "md" | "lg" | "xl";
	/** Alert title */
	title?: string;
	/** Alert description */
	description?: string;
	/** Custom icon */
	icon?: React.ReactNode;
	/** Hide default icon */
	hideIcon?: boolean;
	/** Closable alert */
	isClosable?: boolean;
	/** Close callback */
	onClose?: () => void;
	/** Visible state */
	isVisible?: boolean;
	/** Custom class name */
	className?: string;
	/** Custom styles */
	css?: any;
}

type StyledAlertProps = StyledProps<AlertProps>;

const getAlertVariantStyles = (props: StyledAlertProps) => {
	const { theme, variant = "flat", color = "primary" } = props;
	const baseColor = getColorVariant(theme, color, 500);
	const lightColor = getColorVariant(theme, color, 50);
	const borderColor = getColorVariant(theme, color, 200);

	switch (variant) {
		case "solid":
			return css`
        background-color: ${baseColor};
        color: ${theme.colors.text.inverse};
        border: 1px solid ${baseColor};
      `;

		case "bordered":
			return css`
        background-color: ${theme.colors.background.primary};
        color: ${baseColor};
        border: 1px solid ${baseColor};
      `;

		case "light":
			return css`
        background-color: ${lightColor};
        color: ${getColorVariant(theme, color, 700)};
        border: 1px solid transparent;
      `;

		case "flat":
			return css`
        background-color: ${getColorVariant(theme, color, 100)};
        color: ${baseColor};
        border: 1px solid ${borderColor};
      `;

		default:
			return css``;
	}
};

const getAlertRadiusStyles = (props: StyledAlertProps) => {
	const { theme, radius = "md" } = props;

	switch (radius) {
		case "none":
			return css`border-radius: ${theme.borderRadius.none};`;
		case "sm":
			return css`border-radius: ${theme.borderRadius.sm};`;
		case "md":
			return css`border-radius: ${theme.borderRadius.md};`;
		case "lg":
			return css`border-radius: ${theme.borderRadius.lg};`;
		case "xl":
			return css`border-radius: ${theme.borderRadius.xl};`;
		default:
			return css`border-radius: ${theme.borderRadius.md};`;
	}
};

const StyledAlert = styled.div<StyledAlertProps & { isVisible?: boolean }>`
  display: ${(props) => (props.isVisible === false ? "none" : "flex")};
  align-items: flex-start;
  gap: ${(props) => props.theme.spacing[3]};
  padding: ${(props) => props.theme.spacing[4]};
  position: relative;
  transition: all ${(props) => props.theme.transitions.normal};

  ${getAlertVariantStyles}
  ${getAlertRadiusStyles}

  /* Custom CSS prop */
  ${(props) => props.css}
`;

const IconWrapper = styled.div`
  display: flex;
  align-items: center;
  justify-content: center;
  flex-shrink: 0;
  width: 20px;
  height: 20px;
  margin-top: 2px;
`;

const ContentWrapper = styled.div<StyledProps>`
  display: flex;
  flex-direction: column;
  gap: ${(props) => props.theme.spacing[1]};
  flex: 1;
  min-width: 0;
`;

const Title = styled.div<StyledProps>`
  font-weight: ${(props) => props.theme.fontWeights.semibold};
  font-size: ${(props) => props.theme.fontSizes.base};
  line-height: ${(props) => props.theme.lineHeights.tight};
`;

const Description = styled.div<StyledProps>`
  font-size: ${(props) => props.theme.fontSizes.sm};
  line-height: ${(props) => props.theme.lineHeights.normal};
  opacity: 0.9;
`;

const CloseButton = styled.button<StyledProps>`
  display: flex;
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
  width: 18px;
  height: 18px;
  flex-shrink: 0;
  margin-top: 1px;

  &:hover {
    opacity: 1;
  }

  &:focus {
    outline: none;
  }
`;

// Default icons for different alert types
const CheckCircleIcon = () => (
	// biome-ignore lint/a11y/noSvgWithoutTitle: <explanation>
	<svg viewBox="0 0 24 24" fill="currentColor" width="20" height="20">
		<path d="M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm-2 15l-5-5 1.41-1.41L10 14.17l7.59-7.59L19 8l-9 9z" />
	</svg>
);

const InfoIcon = () => (
	// biome-ignore lint/a11y/noSvgWithoutTitle: <explanation>
	<svg viewBox="0 0 24 24" fill="currentColor" width="20" height="20">
		<path d="M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm1 15h-2v-6h2v6zm0-8h-2V7h2v2z" />
	</svg>
);

const WarningIcon = () => (
	// biome-ignore lint/a11y/noSvgWithoutTitle: <explanation>
	<svg viewBox="0 0 24 24" fill="currentColor" width="20" height="20">
		<path d="M1 21h22L12 2 1 21zm12-3h-2v-2h2v2zm0-4h-2v-4h2v4z" />
	</svg>
);

const ErrorIcon = () => (
	// biome-ignore lint/a11y/noSvgWithoutTitle: <explanation>
	<svg viewBox="0 0 24 24" fill="currentColor" width="20" height="20">
		<path d="M12 2C6.47 2 2 6.47 2 12s4.47 10 10 10 10-4.47 10-10S17.53 2 12 2zm5 13.59L15.59 17 12 13.41 8.41 17 7 15.59 10.59 12 7 8.41 8.41 7 12 10.59 15.59 7 17 8.41 13.41 12 17 15.59z" />
	</svg>
);

const CloseIcon = () => (
	// biome-ignore lint/a11y/noSvgWithoutTitle: <explanation>
	<svg
		viewBox="0 0 24 24"
		fill="none"
		stroke="currentColor"
		strokeWidth="2"
		width="18"
		height="18"
	>
		<line x1="18" y1="6" x2="6" y2="18" />
		<line x1="6" y1="6" x2="18" y2="18" />
	</svg>
);

const getDefaultIcon = (color: string) => {
	switch (color) {
		case "success":
			return <CheckCircleIcon />;
		case "warning":
			return <WarningIcon />;
		case "danger":
			return <ErrorIcon />;
		// case "primary":
		// case "secondary":
		default:
			return <InfoIcon />;
	}
};

export const Alert = React.forwardRef<HTMLDivElement, AlertProps>(
	(
		{
			children,
			variant = "flat",
			color = "primary",
			radius = "md",
			title,
			description,
			icon,
			hideIcon = false,
			isClosable = false,
			onClose,
			isVisible = true,
			className,
			css,
			...props
		},
		ref,
	) => {
		const { theme } = useTheme();

		const alertProps = {
			...props,
			variant,
			color,
			radius,
			isVisible,
			className,
			css,
		};

		const handleClose = () => {
			onClose?.();
		};

		const displayIcon = icon || getDefaultIcon(color);
		const hasContent = title || description || children;

		return (
			<StyledAlert theme={theme} ref={ref} {...alertProps}>
				{!hideIcon && <IconWrapper>{displayIcon}</IconWrapper>}

				{hasContent && (
					<ContentWrapper theme={theme}>
						{title && <Title theme={theme}>{title}</Title>}
						{description && (
							<Description theme={theme}>{description}</Description>
						)}
						{children}
					</ContentWrapper>
				)}

				{isClosable && (
					<CloseButton
						theme={theme}
						onClick={handleClose}
						aria-label="Close alert"
					>
						<CloseIcon />
					</CloseButton>
				)}
			</StyledAlert>
		);
	},
);

Alert.displayName = "Alert";
