import { useTheme } from "@/theme/context";
import { type StyledProps, getColorVariant } from "@/theme/styled";
import { css } from "@emotion/react";
import styled from "@emotion/styled";
import React from "react";

export interface TypographyProps extends React.HTMLAttributes<HTMLElement> {
	/** HTML element to render */
	as?:
		| "h1"
		| "h2"
		| "h3"
		| "h4"
		| "h5"
		| "h6"
		| "p"
		| "span"
		| "div"
		| "label"
		| "small"
		| "strong"
		| "em"
		| "mark"
		| "del"
		| "ins"
		| "sub"
		| "sup";
	/** Typography variant (predefined combinations) */
	variant?:
		| "h1"
		| "h2"
		| "h3"
		| "h4"
		| "h5"
		| "h6"
		| "subtitle1"
		| "subtitle2"
		| "body1"
		| "body2"
		| "caption"
		| "overline"
		| "inherit";
	/** Font size */
	size?: "xs" | "sm" | "base" | "lg" | "xl" | "2xl" | "3xl" | "4xl";
	/** Font weight */
	weight?: "light" | "normal" | "medium" | "semibold" | "bold";
	/** Line height */
	lineHeight?: "tight" | "normal" | "relaxed";
	/** Text color */
	color?:
		| "primary"
		| "secondary"
		| "success"
		| "warning"
		| "danger"
		| "foreground"
		| "muted"
		| "disabled"
		| "inverse";
	/** Text alignment */
	align?: "left" | "center" | "right" | "justify";
	/** Text transform */
	transform?: "none" | "capitalize" | "uppercase" | "lowercase";
	/** Text decoration */
	decoration?: "none" | "underline" | "line-through" | "overline";
	/** Text overflow behavior */
	truncate?: boolean | number; // true for single line, number for max lines
	/** White space handling */
	whitespace?: "normal" | "nowrap" | "pre" | "pre-line" | "pre-wrap";
	/** Disable text selection */
	noSelect?: boolean;
	/** Italic style */
	italic?: boolean;
	/** Gradient text (requires color variants) */
	gradient?: boolean;
	/** Text shadow */
	shadow?: boolean;
	/** Custom class name */
	className?: string;
	/** Custom styles */
	css?: any;
	/** Children content */
	children?: React.ReactNode;
}

type StyledTypographyProps = StyledProps<TypographyProps>;

// Variant configurations
const variantConfig = {
	h1: { as: "h1", size: "4xl", weight: "bold", lineHeight: "tight" },
	h2: { as: "h2", size: "3xl", weight: "bold", lineHeight: "tight" },
	h3: { as: "h3", size: "2xl", weight: "semibold", lineHeight: "tight" },
	h4: { as: "h4", size: "xl", weight: "semibold", lineHeight: "tight" },
	h5: { as: "h5", size: "lg", weight: "semibold", lineHeight: "normal" },
	h6: { as: "h6", size: "base", weight: "semibold", lineHeight: "normal" },
	subtitle1: { as: "p", size: "lg", weight: "medium", lineHeight: "normal" },
	subtitle2: { as: "p", size: "base", weight: "medium", lineHeight: "normal" },
	body1: { as: "p", size: "base", weight: "normal", lineHeight: "relaxed" },
	body2: { as: "p", size: "sm", weight: "normal", lineHeight: "normal" },
	caption: { as: "span", size: "xs", weight: "normal", lineHeight: "tight" },
	overline: {
		as: "span",
		size: "xs",
		weight: "medium",
		lineHeight: "tight",
		transform: "uppercase",
	},
	inherit: { as: "span" },
} as const;

const getTypographySize = (props: StyledTypographyProps) => {
	const { theme, size } = props;

	if (!size) return css``;

	return css`
    font-size: ${theme.fontSizes[size]};
  `;
};

const getTypographyWeight = (props: StyledTypographyProps) => {
	const { theme, weight } = props;

	if (!weight) return css``;

	return css`
    font-weight: ${theme.fontWeights[weight]};
  `;
};

const getTypographyLineHeight = (props: StyledTypographyProps) => {
	const { theme, lineHeight } = props;

	if (!lineHeight) return css``;

	return css`
    line-height: ${theme.lineHeights[lineHeight]};
  `;
};

const getTypographyColor = (props: StyledTypographyProps) => {
	const { theme, color, gradient } = props;

	if (!color) return css``;

	// Handle theme color variants
	if (
		["primary", "secondary", "success", "warning", "danger"].includes(color)
	) {
		const colorValue = getColorVariant(theme, color as any, 500);

		if (gradient) {
			const lightColor = getColorVariant(theme, color as any, 400);
			const darkColor = getColorVariant(theme, color as any, 600);

			return css`
        background: linear-gradient(135deg, ${lightColor} 0%, ${darkColor} 100%);
        background-clip: text;
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
        color: transparent;
      `;
		}

		return css`
      color: ${colorValue};
    `;
	}

	// Handle semantic colors
	switch (color) {
		case "foreground":
			return css`color: ${theme.colors.text.primary};`;
		case "muted":
			return css`color: ${theme.colors.text.secondary};`;
		case "disabled":
			return css`
        color: ${theme.colors.text.tertiary};
        opacity: 0.6;
      `;
		case "inverse":
			return css`color: ${theme.colors.text.inverse};`;
		default:
			return css``;
	}
};

const getTypographyAlign = (props: StyledTypographyProps) => {
	const { align } = props;

	if (!align) return css``;

	return css`
    text-align: ${align};
  `;
};

const getTypographyTransform = (props: StyledTypographyProps) => {
	const { transform } = props;

	if (!transform) return css``;

	return css`
    text-transform: ${transform};
  `;
};

const getTypographyDecoration = (props: StyledTypographyProps) => {
	const { decoration } = props;

	if (!decoration) return css``;

	return css`
    text-decoration: ${decoration};
  `;
};

const getTypographyTruncate = (props: StyledTypographyProps) => {
	const { truncate } = props;

	if (!truncate) return css``;

	if (truncate === true) {
		// Single line truncation
		return css`
      overflow: hidden;
      text-overflow: ellipsis;
      white-space: nowrap;
    `;
	}

	if (typeof truncate === "number") {
		// Multi-line truncation
		return css`
      display: -webkit-box;
      -webkit-line-clamp: ${truncate};
      -webkit-box-orient: vertical;
      overflow: hidden;
      text-overflow: ellipsis;
    `;
	}

	return css``;
};

const getTypographyWhitespace = (props: StyledTypographyProps) => {
	const { whitespace } = props;

	if (!whitespace) return css``;

	return css`
    white-space: ${whitespace};
  `;
};

const getTypographyExtras = (props: StyledTypographyProps) => {
	const { theme, noSelect, italic, shadow } = props;

	return css`
    ${
			noSelect &&
			css`
      user-select: none;
    `
		}
    
    ${
			italic &&
			css`
      font-style: italic;
    `
		}
    
    ${
			shadow &&
			css`
      text-shadow: 0 1px 2px rgba(0, 0, 0, 0.1);
    `
		}
  `;
};

const StyledTypography = styled.span<StyledTypographyProps>`
  font-family: inherit;
  margin: 0;
  
  ${getTypographySize}
  ${getTypographyWeight}
  ${getTypographyLineHeight}
  ${getTypographyColor}
  ${getTypographyAlign}
  ${getTypographyTransform}
  ${getTypographyDecoration}
  ${getTypographyTruncate}
  ${getTypographyWhitespace}
  ${getTypographyExtras}
  
  /* Custom CSS prop */
  ${(props) => props.css}
`;

export const Typography = React.forwardRef<HTMLElement, TypographyProps>(
	({ as, variant = "inherit", children, className, css, ...props }, ref) => {
		const { theme } = useTheme();

		// Get variant configuration
		const config = variant !== "inherit" ? variantConfig[variant] : {};

		// Merge props with variant config (props override config)
		const mergedProps = {
			as: as || config.as || "span",
			size: props.size || config.size,
			weight: props.weight || config.weight,
			lineHeight: props.lineHeight || config.lineHeight,
			transform: props.transform || config.transform,
			...props,
		};

		return (
			<StyledTypography
				ref={ref}
				as={mergedProps.as}
				theme={theme}
				className={className}
				css={css}
				{...mergedProps}
			>
				{children}
			</StyledTypography>
		);
	},
);

Typography.displayName = "Typography";

// Convenience components for common use cases
export const Heading = React.forwardRef<
	HTMLHeadingElement,
	Omit<TypographyProps, "variant"> & { level?: 1 | 2 | 3 | 4 | 5 | 6 }
>(({ level = 1, ...props }, ref) => (
	<Typography
		ref={ref}
		variant={`h${level}` as keyof typeof variantConfig}
		{...props}
	/>
));

Heading.displayName = "Heading";

export const Text = React.forwardRef<
	HTMLElement,
	Omit<TypographyProps, "variant"> & { variant?: "body1" | "body2" | "caption" }
>(({ variant = "body1", ...props }, ref) => (
	<Typography ref={ref} variant={variant} {...props} />
));

Text.displayName = "Text";

export const Title = React.forwardRef<
	HTMLElement,
	Omit<TypographyProps, "variant"> & { level?: 1 | 2 }
>(({ level = 1, ...props }, ref) => (
	<Typography
		ref={ref}
		variant={level === 1 ? "subtitle1" : "subtitle2"}
		{...props}
	/>
));

Title.displayName = "Title";

// Pre-configured typography components
export const Display = React.forwardRef<
	HTMLHeadingElement,
	Omit<TypographyProps, "variant" | "size" | "weight">
>((props, ref) => (
	<Typography
		ref={ref}
		as="h1"
		size="4xl"
		weight="bold"
		lineHeight="tight"
		{...props}
	/>
));

Display.displayName = "Display";

export const Label = React.forwardRef<
	HTMLLabelElement,
	Omit<TypographyProps, "as">
>(({ weight = "medium", ...props }, ref) => (
	<Typography ref={ref} as="label" weight={weight} {...props} />
));

Label.displayName = "Label";

export const Code = React.forwardRef<HTMLElement, Omit<TypographyProps, "as">>(
	({ as = "code", size = "sm", css, ...props }, ref) => {
		const { theme } = useTheme();

		const codeStyles = css`
    font-family: 'Monaco', 'Menlo', 'Ubuntu Mono', monospace;
    background-color: ${theme.colors.background.secondary};
    border: 1px solid ${theme.colors.border.primary};
    border-radius: ${theme.borderRadius.sm};
    padding: 0.125rem 0.25rem;
    ${css}
  `;

		return (
			<Typography ref={ref} as={as} size={size} css={codeStyles} {...props} />
		);
	},
);

Code.displayName = "Code";

export const Link = React.forwardRef<
	HTMLAnchorElement,
	Omit<TypographyProps, "as"> & {
		href?: string;
		external?: boolean;
		underline?: "none" | "hover" | "always";
	}
>(
	(
		{
			color = "primary",
			decoration = "none",
			underline = "hover",
			external = false,
			css,
			...props
		},
		ref,
	) => {
		const { theme } = useTheme();

		const linkStyles = css`
    cursor: pointer;
    transition: all ${theme.transitions.normal};
    
    ${
			underline === "always" &&
			css`
      text-decoration: underline;
    `
		}
    
    ${
			underline === "hover" &&
			css`
      &:hover {
        text-decoration: underline;
      }
    `
		}
    
    &:hover {
      opacity: 0.8;
    }
    
    &:focus-visible {
      outline: 2px solid ${theme.colors.border.focus};
      outline-offset: 2px;
      border-radius: ${theme.borderRadius.sm};
    }
    
    ${css}
  `;

		const linkProps = external
			? {
					target: "_blank",
					rel: "noopener noreferrer",
				}
			: {};

		return (
			<Typography
				ref={ref}
				as="a"
				color={color}
				decoration={decoration}
				css={linkStyles}
				{...linkProps}
				{...props}
			/>
		);
	},
);

Link.displayName = "Link";
