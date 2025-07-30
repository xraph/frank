import type { StyledProps } from "@/theme/styled";
import { css } from "@emotion/react";
import styled from "@emotion/styled";

import { useTheme } from "@/theme/context";
import React from "react";

export interface DividerProps extends React.HTMLAttributes<HTMLDivElement> {
	/** Divider orientation */
	orientation?: "horizontal" | "vertical";
	/** Divider color */
	color?:
		| "primary"
		| "secondary"
		| "success"
		| "warning"
		| "danger"
		| "default";
	/** Divider size (thickness) */
	size?: "sm" | "md" | "lg";
	/** Content to display in the middle of the divider */
	children?: React.ReactNode;
	/** Alignment of the middle content */
	contentAlign?: "start" | "center" | "end";
	/** Custom class name */
	className?: string;
	/** Custom styles */
	css?: any;
}

type StyledDividerProps = StyledProps<DividerProps>;

const getDividerColorStyles = (props: StyledDividerProps) => {
	const { theme, color = "default" } = props;

	switch (color) {
		case "primary":
			return css`
				background-color: ${theme.colors.primary[500]};
			`;
		case "secondary":
			return css`
				background-color: ${theme.colors.secondary[500]};
			`;
		case "success":
			return css`
				background-color: ${theme.colors.success[500]};
			`;
		case "warning":
			return css`
				background-color: ${theme.colors.warning[500]};
			`;
		case "danger":
			return css`
				background-color: ${theme.colors.danger[500]};
			`;
		default:
			return css`
				background-color: ${theme.colors.border.primary};
			`;
	}
};

const getDividerSizeStyles = (props: StyledDividerProps) => {
	const { size = "md", orientation = "horizontal" } = props;

	const sizeMap = {
		sm: "1px",
		md: "2px",
		lg: "3px",
	};

	const thickness = sizeMap[size];

	if (orientation === "vertical") {
		return css`
			width: ${thickness};
			height: auto;
			min-height: 100%;
		`;
	}

	return css`
		height: ${thickness};
		width: 100%;
	`;
};

// Simple divider without content
const StyledDivider = styled.div<StyledDividerProps>`
	border: none;
	margin: 0;
	flex-shrink: 0;

	${getDividerColorStyles}
	${getDividerSizeStyles}

		/* Custom CSS prop */
	${(props) => props.css}
`;

// Container for divider with content
const DividerWithContentContainer = styled.div<
	StyledDividerProps & { contentAlign: "start" | "center" | "end" }
>`
  display: flex;
  align-items: center;
  width: 100%;
  
  ${(props) =>
		props.orientation === "vertical" &&
		css`
    flex-direction: column;
    height: 100%;
    width: auto;
  `}

  ${(props) => {
		const justifyContent = {
			start: "flex-start",
			center: "center",
			end: "flex-end",
		}[props.contentAlign];

		return css`
      justify-content: ${justifyContent};
    `;
	}}

  /* Custom CSS prop */
  ${(props) => props.css}
`;

// Divider line segments (before and after content)
const DividerSegment = styled.div<
	StyledDividerProps & { isFlexible?: boolean }
>`
  border: none;
  margin: 0;
  flex-shrink: 0;

  ${getDividerColorStyles}
  ${getDividerSizeStyles}

  ${(props) =>
		props.isFlexible &&
		css`
    flex: 1;
  `}
`;

// Content wrapper
const DividerContent = styled.div<StyledDividerProps>`
  display: flex;
  align-items: center;
  justify-content: center;
  padding: ${(props) =>
		props.orientation === "vertical"
			? `${props.theme.spacing[2]} 0`
			: `0 ${props.theme.spacing[2]}`};
  background-color: ${(props) => props.theme.colors.background.primary};
  color: ${(props) => props.theme.colors.text.secondary};
  font-size: ${(props) => props.theme.fontSizes.sm};
  font-weight: ${(props) => props.theme.fontWeights.medium};
  white-space: nowrap;
  flex-shrink: 0;

  /* Add subtle styling for text content */
  ${(props) =>
		typeof props.children === "string" &&
		css`
    text-transform: uppercase;
    letter-spacing: 0.05em;
  `}
`;

export const Divider = React.forwardRef<HTMLDivElement, DividerProps>(
	(
		{
			orientation = "horizontal",
			color = "default",
			size = "md",
			children,
			contentAlign = "center",
			className,
			css,
			...props
		},
		ref,
	) => {
		const { theme } = useTheme();

		// If no content, render simple divider
		if (!children) {
			const dividerProps = {
				...props,
				orientation,
				color,
				size,
				className,
				css,
				role: "separator",
				"aria-orientation": orientation,
			};

			return <StyledDivider theme={theme} ref={ref} {...dividerProps} />;
		}

		// Render divider with content
		const containerProps = {
			...props,
			orientation,
			color,
			size,
			contentAlign,
			className,
			css,
			role: "separator",
			"aria-orientation": orientation,
		};

		const segmentProps = {
			orientation,
			color,
			size,
			theme,
		};

		const contentProps = {
			orientation,
			theme,
			children,
		};

		// For center alignment, both segments are flexible
		// For start/end alignment, only one segment is flexible
		const beforeFlexible = contentAlign === "center" || contentAlign === "end";
		const afterFlexible = contentAlign === "center" || contentAlign === "start";

		return (
			<DividerWithContentContainer theme={theme} ref={ref} {...containerProps}>
				{/* Before segment */}
				{(contentAlign === "center" || contentAlign === "end") && (
					<DividerSegment {...segmentProps} isFlexible={beforeFlexible} />
				)}

				{/* Content */}
				<DividerContent {...contentProps} />

				{/* After segment */}
				{(contentAlign === "center" || contentAlign === "start") && (
					<DividerSegment {...segmentProps} isFlexible={afterFlexible} />
				)}
			</DividerWithContentContainer>
		);
	},
);

Divider.displayName = "Divider";
