import { useTheme } from "@/theme/context";
import type { StyledProps } from "@/theme/styled";
import { css } from "@emotion/react";
import styled from "@emotion/styled";
import type React from "react";
import { Children, cloneElement, isValidElement } from "react";
import type { ButtonProps } from "../button";
import type { InputProps } from "../input";

export interface ButtonGroupProps {
	/** Button group orientation */
	orientation?: "horizontal" | "vertical";
	/** Button group size - applies to all children */
	size?: "sm" | "md" | "lg";
	/** Button group variant - applies to Button children */
	variant?: "solid" | "outlined" | "light" | "flat" | "ghost";
	/** Button group color - applies to all children */
	color?: "primary" | "secondary" | "success" | "warning" | "danger";
	/** Button group radius */
	radius?: "none" | "sm" | "md" | "lg" | "full";
	/** Whether buttons are attached (no gaps) */
	isAttached?: boolean;
	/** Disabled state - applies to all children */
	isDisabled?: boolean;
	/** Full width group */
	fullWidth?: boolean;
	/** Custom class name */
	className?: string;
	/** Custom styles */
	css?: any;
	/** Children components (Button, Input) */
	children: React.ReactNode;
}

type StyledButtonGroupProps = StyledProps<ButtonGroupProps>;

const getGroupOrientation = (props: StyledButtonGroupProps) => {
	const { orientation = "horizontal", theme, isAttached = true } = props;

	if (orientation === "vertical") {
		return css`
      flex-direction: column;
      
      ${
				!isAttached &&
				css`
        gap: ${theme.spacing[2]};
      `
			}
    `;
	}

	return css`
    flex-direction: row;
    
    ${
			!isAttached &&
			css`
      gap: ${theme.spacing[2]};
    `
		}
  `;
};

const StyledButtonGroup = styled.div<StyledButtonGroupProps>`
  display: inline-flex;
  position: relative;
  
  ${getGroupOrientation}
  
  ${(props) =>
		props.fullWidth &&
		css`
    width: 100%;
  `}
  
  ${(props) => props.css}
`;

const getChildRadius = (
	isFirst: boolean,
	isLast: boolean,
	orientation: "horizontal" | "vertical",
	radius: string,
	isAttached: boolean,
) => {
	if (!isAttached) {
		return css`border-radius: ${radius} !important;`;
	}

	if (orientation === "horizontal") {
		if (isFirst && isLast) {
			return css`border-radius: ${radius} !important;`;
		} else if (isFirst) {
			return css`
        border-top-left-radius: ${radius} !important;
        border-bottom-left-radius: ${radius} !important;
        border-top-right-radius: 0 !important;
        border-bottom-right-radius: 0 !important;
      `;
		} else if (isLast) {
			return css`
        border-top-left-radius: 0 !important;
        border-bottom-left-radius: 0 !important;
        border-top-right-radius: ${radius} !important;
        border-bottom-right-radius: ${radius} !important;
      `;
		} else {
			return css`border-radius: 0 !important;`;
		}
	} else {
		// vertical orientation
		if (isFirst && isLast) {
			return css`border-radius: ${radius} !important;`;
		} else if (isFirst) {
			return css`
        border-top-left-radius: ${radius} !important;
        border-top-right-radius: ${radius} !important;
        border-bottom-left-radius: 0 !important;
        border-bottom-right-radius: 0 !important;
      `;
		} else if (isLast) {
			return css`
        border-top-left-radius: 0 !important;
        border-top-right-radius: 0 !important;
        border-bottom-left-radius: ${radius} !important;
        border-bottom-right-radius: ${radius} !important;
      `;
		} else {
			return css`border-radius: 0 !important;`;
		}
	}
};

const getChildBorder = (
	isFirst: boolean,
	isLast: boolean,
	orientation: "horizontal" | "vertical",
	isAttached: boolean,
) => {
	if (!isAttached) {
		return css``;
	}

	if (orientation === "horizontal") {
		if (!isLast) {
			return css`
        border-right-width: 0 !important;
        
        /* Handle focus states to show border */
        &:focus-within,
        &:focus-visible {
          border-right-width: 2px !important;
          z-index: 1;
        }
      `;
		}
	} else {
		// vertical orientation
		if (!isLast) {
			return css`
        border-bottom-width: 0 !important;
        
        /* Handle focus states to show border */
        &:focus-within,
        &:focus-visible {
          border-bottom-width: 2px !important;
          z-index: 1;
        }
      `;
		}
	}

	return css``;
};

export const ButtonGroup: React.FC<ButtonGroupProps> = ({
	children,
	orientation = "horizontal",
	size,
	variant,
	color,
	radius = "md",
	isAttached = true,
	isDisabled,
	fullWidth,
	className,
	css,
}) => {
	const { theme } = useTheme();

	// Get the actual border radius value from theme
	const getBorderRadiusValue = (r: string) => {
		switch (r) {
			case "none":
				return theme.borderRadius.none;
			case "sm":
				return theme.borderRadius.sm;
			case "md":
				return theme.borderRadius.md;
			case "lg":
				return theme.borderRadius.lg;
			case "full":
				return theme.borderRadius.full;
			default:
				return theme.borderRadius.md;
		}
	};

	const borderRadiusValue = getBorderRadiusValue(radius);

	const childrenArray = Children.toArray(children).filter((child) =>
		isValidElement(child),
	);

	const processedChildren = childrenArray.map((child, index) => {
		if (!isValidElement(child)) return child;

		const isFirst = index === 0;
		const isLast = index === childrenArray.length - 1;
		const isButton =
			child.type === "button" || (child.type as any)?.displayName === "Button";
		const isInput = (child.type as any)?.displayName === "Input";

		if (isButton || isInput) {
			const childProps: Partial<ButtonProps & InputProps> = {
				...child.props,
			};

			// Apply group props to children
			if (size) childProps.size = size;
			if (color) childProps.color = color;
			if (isDisabled) childProps.isDisabled = isDisabled;
			if (fullWidth && orientation === "vertical") childProps.fullWidth = true;

			// Apply variant only to buttons
			if (isButton && variant) {
				childProps.variant = variant;
			}

			// Create custom CSS for positioning and borders
			const childCss = css`
        ${getChildRadius(isFirst, isLast, orientation, borderRadiusValue, isAttached)}
        ${getChildBorder(isFirst, isLast, orientation, isAttached)}
        
        ${
					fullWidth &&
					orientation === "horizontal" &&
					css`
          flex: 1;
        `
				}
        
        /* Ensure proper stacking for focus states */
        position: relative;
        
        ${child.props.css || ""}
      `;

			return cloneElement(child, {
				...childProps,
				key: index,
				css: childCss,
			});
		}

		return child;
	});

	const groupProps = {
		orientation,
		radius,
		isAttached,
		fullWidth,
		className,
		css,
	};

	return (
		<StyledButtonGroup theme={theme} {...groupProps}>
			{processedChildren}
		</StyledButtonGroup>
	);
};

ButtonGroup.displayName = "ButtonGroup";
