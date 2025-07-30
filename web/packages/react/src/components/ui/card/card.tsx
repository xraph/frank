import { useTheme } from "@/theme/context";
import type { StyledProps } from "@/theme/styled";
import { css } from "@emotion/react";
import styled from "@emotion/styled";
import React from "react";

export interface CardProps extends React.HTMLAttributes<HTMLDivElement> {
	/** Card variant */
	variant?: "elevated" | "bordered" | "shadow" | "flat";
	/** Card radius */
	radius?: "none" | "sm" | "md" | "lg" | "xl";
	/** Card shadow level */
	shadow?: "none" | "sm" | "md" | "lg" | "xl";
	/** Full width card */
	fullWidth?: boolean;
	/** Hoverable card */
	isHoverable?: boolean;
	/** Pressable card */
	isPressable?: boolean;
	/** Disabled state */
	isDisabled?: boolean;
	/** Custom class name */
	className?: string;
	/** Custom styles */
	css?: any;
}

type StyledCardProps = StyledProps<CardProps>;

const getCardVariantStyles = (props: StyledCardProps) => {
	const { theme, variant = "elevated", shadow = "sm" } = props;

	switch (variant) {
		case "elevated":
			return css`
        background-color: ${theme.colors.background.primary};
        border: 1px solid transparent;
        box-shadow: ${theme.shadows[shadow]};
      `;

		case "bordered":
			return css`
        background-color: ${theme.colors.background.primary};
        border: 1px solid ${theme.colors.border.primary};
        box-shadow: none;
      `;

		case "shadow":
			return css`
        background-color: ${theme.colors.background.primary};
        border: 1px solid transparent;
        box-shadow: ${theme.shadows[shadow]};
      `;

		case "flat":
			return css`
        background-color: ${theme.colors.background.secondary};
        border: 1px solid transparent;
        box-shadow: none;
      `;

		default:
			return css``;
	}
};

const getCardRadiusStyles = (props: StyledCardProps) => {
	const { theme, radius = "lg" } = props;

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
			return css`border-radius: ${theme.borderRadius.lg};`;
	}
};

const StyledCard = styled.div<StyledCardProps>`
  display: flex;
  flex-direction: column;
  position: relative;
  overflow: hidden;
  width: ${(props) => (props.fullWidth ? "100%" : "auto")};
  transition: all ${(props) => props.theme.transitions.normal};

  ${getCardVariantStyles}
  ${getCardRadiusStyles}

  ${(props) =>
		props.isHoverable &&
		css`
    cursor: pointer;
    
    &:hover {
      transform: translateY(-2px);
      box-shadow: ${props.theme.shadows.lg};
    }
  `}

  ${(props) =>
		props.isPressable &&
		css`
    cursor: pointer;
    user-select: none;
    
    &:hover {
      opacity: 0.9;
    }
    
    &:active {
      transform: scale(0.98);
    }
  `}

  ${(props) =>
		props.isDisabled &&
		css`
    opacity: 0.5;
    cursor: not-allowed;
    pointer-events: none;
  `}

  /* Custom CSS prop */
  ${(props) => props.css}
`;

export const Card = React.forwardRef<HTMLDivElement, CardProps>(
	(
		{
			children,
			variant = "elevated",
			radius = "lg",
			shadow = "sm",
			fullWidth = false,
			isHoverable = false,
			isPressable = false,
			isDisabled = false,
			className,
			css,
			...props
		},
		ref,
	) => {
		const { theme } = useTheme();

		const cardProps = {
			...props,
			variant,
			radius,
			shadow,
			fullWidth,
			isHoverable,
			isPressable,
			isDisabled,
			className,
			css,
		};

		return (
			<StyledCard theme={theme} ref={ref} {...cardProps}>
				{children}
			</StyledCard>
		);
	},
);

Card.displayName = "Card";

// Card subcomponents
export interface CardHeaderProps extends React.HTMLAttributes<HTMLDivElement> {
	className?: string;
	css?: any;
}

export const CardHeader = styled.div<StyledProps<CardHeaderProps>>`
  display: flex;
  padding: ${(props) => props.theme.spacing[6]} ${(props) => props.theme.spacing[6]} 0;
  flex-direction: column;
  gap: ${(props) => props.theme.spacing[2]};

  ${(props) => props.css}
`;

export interface CardBodyProps extends React.HTMLAttributes<HTMLDivElement> {
	className?: string;
	css?: any;
}

export const CardBody = styled.div<StyledProps<CardBodyProps>>`
  display: flex;
  padding: ${(props) => props.theme.spacing[6]};
  flex-direction: column;
  gap: ${(props) => props.theme.spacing[4]};
  flex: 1;

  ${(props) => props.css}
`;

export interface CardFooterProps extends React.HTMLAttributes<HTMLDivElement> {
	className?: string;
	css?: any;
}

export const CardFooter = styled.div<StyledProps<CardFooterProps>>`
  display: flex;
  padding: 0 ${(props) => props.theme.spacing[6]} ${(props) => props.theme.spacing[6]};
  flex-direction: row;
  align-items: center;
  gap: ${(props) => props.theme.spacing[3]};

  ${(props) => props.css}
`;
