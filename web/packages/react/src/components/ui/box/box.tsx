import { type StyledProps, responsive } from "@/theme/styled";
import type { Theme } from "@/theme/theme";
import type { tokens } from "@/theme/tokens";
import { css } from "@emotion/react";
import styled from "@emotion/styled";
import React from "react";

// Type definitions for responsive values
type ResponsiveValue<T> =
	| T
	| {
			base?: T;
			sm?: T;
			md?: T;
			lg?: T;
			xl?: T;
	  };

// Spacing values from theme - now accepts both numbers and strings
type SpacingValue = keyof typeof tokens.spacing | number | "auto";

// Display values
type DisplayValue =
	| "block"
	| "inline-block"
	| "inline"
	| "flex"
	| "inline-flex"
	| "grid"
	| "inline-grid"
	| "none"
	| "contents"
	| "table"
	| "table-cell"
	| "table-row"
	| "table-column"
	| "table-header-group"
	| "table-footer-group"
	| "table-row-group"
	| "table-column-group"
	| "list-item";

// Position values
type PositionValue = "static" | "relative" | "absolute" | "fixed" | "sticky";

// Size values - now accepts both numbers and strings
type SizeValue =
	| SpacingValue
	| "full"
	| "screen"
	| "min"
	| "max"
	| "fit"
	| "prose"
	| string;

// Flex values
type FlexValue = "1" | "auto" | "initial" | "none" | string;
type FlexDirectionValue = "row" | "row-reverse" | "column" | "column-reverse";
type FlexWrapValue = "nowrap" | "wrap" | "wrap-reverse";
type JustifyContentValue =
	| "flex-start"
	| "flex-end"
	| "center"
	| "space-between"
	| "space-around"
	| "space-evenly"
	| "start"
	| "end"
	| "stretch";
type AlignItemsValue =
	| "flex-start"
	| "flex-end"
	| "center"
	| "baseline"
	| "stretch"
	| "start"
	| "end";
type AlignContentValue =
	| "flex-start"
	| "flex-end"
	| "center"
	| "space-between"
	| "space-around"
	| "space-evenly"
	| "stretch"
	| "start"
	| "end";

// Color values
type ColorValue = string;

// Border radius values - now accepts both numbers and strings
type BorderRadiusValue = keyof typeof tokens.borderRadius | number;

// Font size values - now accepts both numbers and strings
type FontSizeValue = keyof typeof tokens.fontSizes | number;

// Font weight values - now accepts both numbers and strings
type FontWeightValue = keyof typeof tokens.fontWeights | number;

// Line height values - now accepts both numbers and strings
type LineHeightValue = keyof typeof tokens.lineHeights | number;

// Cursor values
type CursorValue =
	| "auto"
	| "default"
	| "pointer"
	| "wait"
	| "text"
	| "move"
	| "help"
	| "not-allowed"
	| "none"
	| "context-menu"
	| "progress"
	| "cell"
	| "crosshair"
	| "vertical-text"
	| "alias"
	| "copy"
	| "no-drop"
	| "grab"
	| "grabbing"
	| "all-scroll"
	| "col-resize"
	| "row-resize"
	| "n-resize"
	| "e-resize"
	| "s-resize"
	| "w-resize"
	| "ne-resize"
	| "nw-resize"
	| "se-resize"
	| "sw-resize"
	| "ew-resize"
	| "ns-resize"
	| "nesw-resize"
	| "nwse-resize"
	| "zoom-in"
	| "zoom-out";

// User select values
type UserSelectValue = "none" | "text" | "all" | "auto";

// Pointer events values
type PointerEventsValue = "none" | "auto";

// Object fit values
type ObjectFitValue = "contain" | "cover" | "fill" | "none" | "scale-down";

// Object position values
type ObjectPositionValue =
	| "top"
	| "bottom"
	| "left"
	| "right"
	| "center"
	| "top left"
	| "top right"
	| "bottom left"
	| "bottom right"
	| string;

// Background size values
type BackgroundSizeValue = "auto" | "cover" | "contain" | string;

// Background position values
type BackgroundPositionValue =
	| "top"
	| "bottom"
	| "left"
	| "right"
	| "center"
	| "top left"
	| "top right"
	| "bottom left"
	| "bottom right"
	| string;

// Background repeat values
type BackgroundRepeatValue =
	| "repeat"
	| "no-repeat"
	| "repeat-x"
	| "repeat-y"
	| "space"
	| "round";

// Border style values
type BorderStyleValue =
	| "none"
	| "solid"
	| "dashed"
	| "dotted"
	| "double"
	| "groove"
	| "ridge"
	| "inset"
	| "outset";

// List style type values
type ListStyleTypeValue =
	| "none"
	| "disc"
	| "circle"
	| "square"
	| "decimal"
	| "decimal-leading-zero"
	| "lower-roman"
	| "upper-roman"
	| "lower-greek"
	| "lower-latin"
	| "upper-latin"
	| "armenian"
	| "georgian"
	| "lower-alpha"
	| "upper-alpha";

// List style position values
type ListStylePositionValue = "inside" | "outside";

// White space values
type WhiteSpaceValue =
	| "normal"
	| "nowrap"
	| "pre"
	| "pre-line"
	| "pre-wrap"
	| "break-spaces";

// Word break values
type WordBreakValue = "normal" | "break-all" | "keep-all" | "break-word";

// Hyphens values
type HyphensValue = "none" | "manual" | "auto";

// Writing mode values
type WritingModeValue = "horizontal-tb" | "vertical-rl" | "vertical-lr";

// Text orientation values
type TextOrientationValue =
	| "mixed"
	| "upright"
	| "sideways-right"
	| "sideways"
	| "use-glyph-orientation";

// Resize values
type ResizeValue = "none" | "both" | "horizontal" | "vertical";

// Scroll behavior values
type ScrollBehaviorValue = "auto" | "smooth";

// Appearance values
type AppearanceValue = "none" | "auto";

// Backdrop filter and filter values
type FilterValue = string;

// Transform values
type TransformValue = string;

// Transition values
type TransitionValue = string;

// Animation values
type AnimationValue = string;

export interface BoxProps
	extends Omit<React.HTMLAttributes<HTMLDivElement>, "content" | "color"> {
	// Element type
	as?: keyof JSX.IntrinsicElements;

	// Spacing
	m?: ResponsiveValue<SpacingValue>;
	mt?: ResponsiveValue<SpacingValue>;
	mr?: ResponsiveValue<SpacingValue>;
	mb?: ResponsiveValue<SpacingValue>;
	ml?: ResponsiveValue<SpacingValue>;
	mx?: ResponsiveValue<SpacingValue>;
	my?: ResponsiveValue<SpacingValue>;

	p?: ResponsiveValue<SpacingValue>;
	pt?: ResponsiveValue<SpacingValue>;
	pr?: ResponsiveValue<SpacingValue>;
	pb?: ResponsiveValue<SpacingValue>;
	pl?: ResponsiveValue<SpacingValue>;
	px?: ResponsiveValue<SpacingValue>;
	py?: ResponsiveValue<SpacingValue>;

	// Display & Layout
	display?: ResponsiveValue<DisplayValue>;
	position?: ResponsiveValue<PositionValue>;
	top?: ResponsiveValue<SizeValue>;
	right?: ResponsiveValue<SizeValue>;
	bottom?: ResponsiveValue<SizeValue>;
	left?: ResponsiveValue<SizeValue>;
	zIndex?: ResponsiveValue<keyof typeof tokens.zIndex | number>;

	// Size
	w?: ResponsiveValue<SizeValue>;
	h?: ResponsiveValue<SizeValue>;
	minW?: ResponsiveValue<SizeValue>;
	minH?: ResponsiveValue<SizeValue>;
	maxW?: ResponsiveValue<SizeValue>;
	maxH?: ResponsiveValue<SizeValue>;

	// Flexbox
	flex?: ResponsiveValue<FlexValue>;
	flexDirection?: ResponsiveValue<FlexDirectionValue>;
	flexWrap?: ResponsiveValue<FlexWrapValue>;
	flexGrow?: ResponsiveValue<number>;
	flexShrink?: ResponsiveValue<number>;
	flexBasis?: ResponsiveValue<SizeValue>;
	justifyContent?: ResponsiveValue<JustifyContentValue>;
	alignItems?: ResponsiveValue<AlignItemsValue>;
	alignContent?: ResponsiveValue<AlignContentValue>;
	alignSelf?: ResponsiveValue<AlignItemsValue>;
	gap?: ResponsiveValue<SpacingValue>;
	rowGap?: ResponsiveValue<SpacingValue>;
	columnGap?: ResponsiveValue<SpacingValue>;

	// Grid
	gridTemplate?: ResponsiveValue<string>;
	gridTemplateColumns?: ResponsiveValue<string>;
	gridTemplateRows?: ResponsiveValue<string>;
	gridTemplateAreas?: ResponsiveValue<string>;
	gridColumn?: ResponsiveValue<string>;
	gridRow?: ResponsiveValue<string>;
	gridArea?: ResponsiveValue<string>;
	gridAutoColumns?: ResponsiveValue<string>;
	gridAutoRows?: ResponsiveValue<string>;
	gridAutoFlow?: ResponsiveValue<
		"row" | "column" | "row dense" | "column dense"
	>;
	justifyItems?: ResponsiveValue<JustifyContentValue>;
	justifySelf?: ResponsiveValue<JustifyContentValue>;
	placeContent?: ResponsiveValue<string>;
	placeItems?: ResponsiveValue<string>;
	placeSelf?: ResponsiveValue<string>;

	// Background
	bg?: ResponsiveValue<ColorValue>;
	bgColor?: ResponsiveValue<ColorValue>;
	bgImage?: ResponsiveValue<string>;
	bgSize?: ResponsiveValue<BackgroundSizeValue>;
	bgPosition?: ResponsiveValue<BackgroundPositionValue>;
	bgRepeat?: ResponsiveValue<BackgroundRepeatValue>;
	bgAttachment?: ResponsiveValue<"fixed" | "local" | "scroll">;
	bgClip?: ResponsiveValue<
		"border-box" | "padding-box" | "content-box" | "text"
	>;
	bgOrigin?: ResponsiveValue<"border-box" | "padding-box" | "content-box">;

	// Border
	border?: ResponsiveValue<string>;
	borderTop?: ResponsiveValue<string>;
	borderRight?: ResponsiveValue<string>;
	borderBottom?: ResponsiveValue<string>;
	borderLeft?: ResponsiveValue<string>;
	borderWidth?: ResponsiveValue<string>;
	borderTopWidth?: ResponsiveValue<string>;
	borderRightWidth?: ResponsiveValue<string>;
	borderBottomWidth?: ResponsiveValue<string>;
	borderLeftWidth?: ResponsiveValue<string>;
	borderColor?: ResponsiveValue<ColorValue>;
	borderTopColor?: ResponsiveValue<ColorValue>;
	borderRightColor?: ResponsiveValue<ColorValue>;
	borderBottomColor?: ResponsiveValue<ColorValue>;
	borderLeftColor?: ResponsiveValue<ColorValue>;
	borderStyle?: ResponsiveValue<BorderStyleValue>;
	borderTopStyle?: ResponsiveValue<BorderStyleValue>;
	borderRightStyle?: ResponsiveValue<BorderStyleValue>;
	borderBottomStyle?: ResponsiveValue<BorderStyleValue>;
	borderLeftStyle?: ResponsiveValue<BorderStyleValue>;
	borderRadius?: ResponsiveValue<BorderRadiusValue>;
	borderTopLeftRadius?: ResponsiveValue<BorderRadiusValue>;
	borderTopRightRadius?: ResponsiveValue<BorderRadiusValue>;
	borderBottomLeftRadius?: ResponsiveValue<BorderRadiusValue>;
	borderBottomRightRadius?: ResponsiveValue<BorderRadiusValue>;
	borderCollapse?: ResponsiveValue<"collapse" | "separate">;
	borderSpacing?: ResponsiveValue<string>;

	// Typography
	color?: ResponsiveValue<ColorValue>;
	fontSize?: ResponsiveValue<FontSizeValue>;
	fontWeight?: ResponsiveValue<FontWeightValue>;
	lineHeight?: ResponsiveValue<LineHeightValue>;
	fontFamily?: ResponsiveValue<string>;
	fontStyle?: ResponsiveValue<"normal" | "italic" | "oblique">;
	fontVariant?: ResponsiveValue<string>;
	textAlign?: ResponsiveValue<
		"left" | "center" | "right" | "justify" | "start" | "end"
	>;
	textTransform?: ResponsiveValue<
		"uppercase" | "lowercase" | "capitalize" | "none"
	>;
	textDecoration?: ResponsiveValue<string>;
	textDecorationLine?: ResponsiveValue<
		"none" | "underline" | "overline" | "line-through"
	>;
	textDecorationColor?: ResponsiveValue<ColorValue>;
	textDecorationStyle?: ResponsiveValue<
		"solid" | "double" | "dotted" | "dashed" | "wavy"
	>;
	textDecorationThickness?: ResponsiveValue<string>;
	textUnderlineOffset?: ResponsiveValue<string>;
	textIndent?: ResponsiveValue<string>;
	textShadow?: ResponsiveValue<string>;
	letterSpacing?: ResponsiveValue<string>;
	wordSpacing?: ResponsiveValue<string>;
	whiteSpace?: ResponsiveValue<WhiteSpaceValue>;
	wordBreak?: ResponsiveValue<WordBreakValue>;
	wordWrap?: ResponsiveValue<"normal" | "break-word">;
	hyphens?: ResponsiveValue<HyphensValue>;
	writingMode?: ResponsiveValue<WritingModeValue>;
	textOrientation?: ResponsiveValue<TextOrientationValue>;
	verticalAlign?: ResponsiveValue<string>;

	// List styles
	listStyle?: ResponsiveValue<string>;
	listStyleType?: ResponsiveValue<ListStyleTypeValue>;
	listStylePosition?: ResponsiveValue<ListStylePositionValue>;
	listStyleImage?: ResponsiveValue<string>;

	// Overflow and clipping
	overflow?: ResponsiveValue<"visible" | "hidden" | "scroll" | "auto">;
	overflowX?: ResponsiveValue<"visible" | "hidden" | "scroll" | "auto">;
	overflowY?: ResponsiveValue<"visible" | "hidden" | "scroll" | "auto">;
	overflowWrap?: ResponsiveValue<"normal" | "break-word" | "anywhere">;
	textOverflow?: ResponsiveValue<"clip" | "ellipsis" | string>;
	clip?: ResponsiveValue<string>;
	clipPath?: ResponsiveValue<string>;

	// Opacity & Visibility
	opacity?: ResponsiveValue<number>;
	visibility?: ResponsiveValue<"visible" | "hidden" | "collapse">;

	// Shadow and filters
	boxShadow?: ResponsiveValue<keyof typeof tokens.shadows | string>;
	textShadow?: ResponsiveValue<string>;
	filter?: ResponsiveValue<FilterValue>;
	backdropFilter?: ResponsiveValue<FilterValue>;

	// Transform
	transform?: ResponsiveValue<TransformValue>;
	transformOrigin?: ResponsiveValue<string>;
	transformStyle?: ResponsiveValue<"flat" | "preserve-3d">;
	perspective?: ResponsiveValue<string>;
	perspectiveOrigin?: ResponsiveValue<string>;
	backfaceVisibility?: ResponsiveValue<"visible" | "hidden">;

	// Transitions and animations
	transition?: ResponsiveValue<TransitionValue>;
	transitionProperty?: ResponsiveValue<string>;
	transitionDuration?: ResponsiveValue<string>;
	transitionTimingFunction?: ResponsiveValue<string>;
	transitionDelay?: ResponsiveValue<string>;
	animation?: ResponsiveValue<AnimationValue>;
	animationName?: ResponsiveValue<string>;
	animationDuration?: ResponsiveValue<string>;
	animationTimingFunction?: ResponsiveValue<string>;
	animationDelay?: ResponsiveValue<string>;
	animationIterationCount?: ResponsiveValue<string | number>;
	animationDirection?: ResponsiveValue<
		"normal" | "reverse" | "alternate" | "alternate-reverse"
	>;
	animationFillMode?: ResponsiveValue<
		"none" | "forwards" | "backwards" | "both"
	>;
	animationPlayState?: ResponsiveValue<"running" | "paused">;

	// Interactivity
	cursor?: ResponsiveValue<CursorValue>;
	userSelect?: ResponsiveValue<UserSelectValue>;
	pointerEvents?: ResponsiveValue<PointerEventsValue>;
	resize?: ResponsiveValue<ResizeValue>;
	scrollBehavior?: ResponsiveValue<ScrollBehaviorValue>;
	scrollMargin?: ResponsiveValue<string>;
	scrollPadding?: ResponsiveValue<string>;
	touchAction?: ResponsiveValue<string>;
	willChange?: ResponsiveValue<string>;

	// Aspect ratio and object properties
	aspectRatio?: ResponsiveValue<string>;
	objectFit?: ResponsiveValue<ObjectFitValue>;
	objectPosition?: ResponsiveValue<ObjectPositionValue>;

	// Table properties
	tableLayout?: ResponsiveValue<"auto" | "fixed">;
	captionSide?: ResponsiveValue<"top" | "bottom">;
	emptyCells?: ResponsiveValue<"show" | "hide">;

	// Outline
	outline?: ResponsiveValue<string>;
	outlineColor?: ResponsiveValue<ColorValue>;
	outlineStyle?: ResponsiveValue<BorderStyleValue>;
	outlineWidth?: ResponsiveValue<string>;
	outlineOffset?: ResponsiveValue<string>;

	// Appearance and system
	appearance?: ResponsiveValue<AppearanceValue>;
	content?: ResponsiveValue<string>;
	quotes?: ResponsiveValue<string>;
	counterReset?: ResponsiveValue<string>;
	counterIncrement?: ResponsiveValue<string>;

	// CSS Grid specific
	gridGap?: ResponsiveValue<SpacingValue>; // Legacy support
	gridRowGap?: ResponsiveValue<SpacingValue>; // Legacy support
	gridColumnGap?: ResponsiveValue<SpacingValue>; // Legacy support

	// Custom CSS
	css?: any;
}

type StyledBoxProps = StyledProps<BoxProps>;

// Helper function to resolve color values
const resolveColor = (theme: any, color: ColorValue): string => {
	if (typeof color === "string") {
		// Check if it's a theme color path (e.g., "background.primary")
		if (color.includes(".")) {
			const parts = color.split(".");
			let current = theme.colors;
			for (const part of parts) {
				current = current?.[part];
				if (!current) break;
			}
			return current || color;
		}
		// Return as-is (hex, rgb, etc.)
		return color;
	}
	return color;
};

// Helper function to resolve size values
const resolveSize = (theme: any, size: SizeValue): string => {
	if (typeof size === "number") {
		// Convert number to string and check if it's a spacing token
		const sizeKey = String(size);
		if (theme.spacing[sizeKey]) {
			return theme.spacing[sizeKey];
		}
		// If not found in spacing, return as-is (will be treated as px)
		return `${size}px`;
	}

	if (typeof size === "string") {
		switch (size) {
			case "full":
				return "100%";
			case "screen":
				return "100vh";
			case "min":
				return "min-content";
			case "max":
				return "max-content";
			case "fit":
				return "fit-content";
			case "prose":
				return "65ch";
			case "auto":
				return "auto";
			default:
				// Check if it's a spacing token
				if (theme.spacing[size]) {
					return theme.spacing[size];
				}
				// Return as-is (px, rem, %, etc.)
				return size;
		}
	}
	return String(size);
};

function createResponsiveStyles<T>(
	value: ResponsiveValue<T> | undefined,
	property: string,
	resolver?: (theme: Theme, val: T) => string,
): (props: StyledProps) => string {
	return (props: StyledProps) => {
		if (!value) return "";

		if (typeof value === "object" && !Array.isArray(value)) {
			const styles: Record<string, string> = {};

			if (value.base !== undefined) {
				const resolvedValue = resolver
					? resolver(props.theme, value.base)
					: String(value.base);
				styles.base = `${property}: ${resolvedValue};`;
			}
			if (value.sm !== undefined) {
				const resolvedValue = resolver
					? resolver(props.theme, value.sm)
					: String(value.sm);
				styles.sm = `${property}: ${resolvedValue};`;
			}
			if (value.md !== undefined) {
				const resolvedValue = resolver
					? resolver(props.theme, value.md)
					: String(value.md);
				styles.md = `${property}: ${resolvedValue};`;
			}
			if (value.lg !== undefined) {
				const resolvedValue = resolver
					? resolver(props.theme, value.lg)
					: String(value.lg);
				styles.lg = `${property}: ${resolvedValue};`;
			}
			if (value.xl !== undefined) {
				const resolvedValue = resolver
					? resolver(props.theme, value.xl)
					: String(value.xl);
				styles.xl = `${property}: ${resolvedValue};`;
			}

			return responsive(styles).join(" ");
		}

		const resolvedValue = resolver
			? resolver(props.theme, value as T)
			: String(value);
		return `${property}: ${resolvedValue};`;
	};
}

// Helper function to resolve spacing values
const resolveSpacing = (theme: any, spacing: SpacingValue): string => {
	if (spacing === "auto") return "auto";

	if (typeof spacing === "number") {
		// Convert number to string and look up in theme
		const spacingKey = String(spacing);
		return theme.spacing[spacingKey] || `${spacing}px`;
	}

	if (typeof spacing === "string") {
		return theme.spacing[spacing] || spacing;
	}

	return String(spacing);
};

// Helper function to resolve border radius values
const resolveBorderRadius = (theme: any, radius: BorderRadiusValue): string => {
	if (typeof radius === "number") {
		// Convert number to string and look up in theme
		const radiusKey = String(radius);
		return theme.borderRadius[radiusKey] || `${radius}px`;
	}

	if (typeof radius === "string") {
		return theme.borderRadius[radius] || radius;
	}

	return String(radius);
};

// Helper function to resolve font size values
const resolveFontSize = (theme: any, size: FontSizeValue): string => {
	if (typeof size === "number") {
		// Convert number to string and look up in theme
		const sizeKey = String(size);
		return theme.fontSizes[sizeKey] || `${size}px`;
	}

	if (typeof size === "string") {
		return theme.fontSizes[size] || size;
	}

	return String(size);
};

// Helper function to resolve font weight values
const resolveFontWeight = (theme: any, weight: FontWeightValue): string => {
	if (typeof weight === "number") {
		// For font weights, numbers should be returned as-is
		return String(weight);
	}

	if (typeof weight === "string") {
		return String(theme.fontWeights[weight]) || weight;
	}

	return String(weight);
};

// Helper function to resolve line height values
const resolveLineHeight = (theme: any, height: LineHeightValue): string => {
	if (typeof height === "number") {
		// For line heights, numbers should be returned as-is (unitless)
		return String(height);
	}

	if (typeof height === "string") {
		return String(theme.lineHeights[height]) || height;
	}

	return String(height);
};

const getBoxStyles = (props: StyledBoxProps) => css`
  /* Base styles */
  box-sizing: border-box;
  
  /* Spacing - Margin */
  ${props.m && createResponsiveStyles(props.m, "margin", resolveSpacing)(props)}
  ${props.mt && createResponsiveStyles(props.mt, "margin-top", resolveSpacing)(props)}
  ${props.mr && createResponsiveStyles(props.mr, "margin-right", resolveSpacing)(props)}
  ${props.mb && createResponsiveStyles(props.mb, "margin-bottom", resolveSpacing)(props)}
  ${props.ml && createResponsiveStyles(props.ml, "margin-left", resolveSpacing)(props)}
  ${
		props.mx &&
		css`
    ${createResponsiveStyles(props.mx, "margin-left", resolveSpacing)(props)}
    ${createResponsiveStyles(props.mx, "margin-right", resolveSpacing)(props)}
  `
	}
  ${
		props.my &&
		css`
    ${createResponsiveStyles(props.my, "margin-top", resolveSpacing)(props)}
    ${createResponsiveStyles(props.my, "margin-bottom", resolveSpacing)(props)}
  `
	}
  
  /* Spacing - Padding */
  ${props.p && createResponsiveStyles(props.p, "padding", resolveSpacing)(props)}
  ${props.pt && createResponsiveStyles(props.pt, "padding-top", resolveSpacing)(props)}
  ${props.pr && createResponsiveStyles(props.pr, "padding-right", resolveSpacing)(props)}
  ${props.pb && createResponsiveStyles(props.pb, "padding-bottom", resolveSpacing)(props)}
  ${props.pl && createResponsiveStyles(props.pl, "padding-left", resolveSpacing)(props)}
  ${
		props.px &&
		css`
    ${createResponsiveStyles(props.px, "padding-left", resolveSpacing)(props)}
    ${createResponsiveStyles(props.px, "padding-right", resolveSpacing)(props)}
  `
	}
  ${
		props.py &&
		css`
    ${createResponsiveStyles(props.py, "padding-top", resolveSpacing)(props)}
    ${createResponsiveStyles(props.py, "padding-bottom", resolveSpacing)(props)}
  `
	}
  
  /* Display & Layout */
  ${props.display && createResponsiveStyles(props.display, "display")(props)}
  ${props.position && createResponsiveStyles(props.position, "position")(props)}
  ${props.top && createResponsiveStyles(props.top, "top", resolveSize)(props)}
  ${props.right && createResponsiveStyles(props.right, "right", resolveSize)(props)}
  ${props.bottom && createResponsiveStyles(props.bottom, "bottom", resolveSize)(props)}
  ${props.left && createResponsiveStyles(props.left, "left", resolveSize)(props)}
  ${
		props.zIndex &&
		createResponsiveStyles(props.zIndex, "z-index", (theme, val) =>
			typeof val === "number" ? String(val) : String(theme.zIndex[val]),
		)(props)
	}
  
  /* Size */
  ${props.w && createResponsiveStyles(props.w, "width", resolveSize)(props)}
  ${props.h && createResponsiveStyles(props.h, "height", resolveSize)(props)}
  ${props.minW && createResponsiveStyles(props.minW, "min-width", resolveSize)(props)}
  ${props.minH && createResponsiveStyles(props.minH, "min-height", resolveSize)(props)}
  ${props.maxW && createResponsiveStyles(props.maxW, "max-width", resolveSize)(props)}
  ${props.maxH && createResponsiveStyles(props.maxH, "max-height", resolveSize)(props)}
  
  /* Flexbox */
  ${props.flex && createResponsiveStyles(props.flex, "flex")(props)}
  ${props.flexDirection && createResponsiveStyles(props.flexDirection, "flex-direction")(props)}
  ${props.flexWrap && createResponsiveStyles(props.flexWrap, "flex-wrap")(props)}
  ${props.flexGrow && createResponsiveStyles(props.flexGrow, "flex-grow")(props)}
  ${props.flexShrink && createResponsiveStyles(props.flexShrink, "flex-shrink")(props)}
  ${props.flexBasis && createResponsiveStyles(props.flexBasis, "flex-basis", resolveSize)(props)}
  ${props.justifyContent && createResponsiveStyles(props.justifyContent, "justify-content")(props)}
  ${props.alignItems && createResponsiveStyles(props.alignItems, "align-items")(props)}
  ${props.alignContent && createResponsiveStyles(props.alignContent, "align-content")(props)}
  ${props.alignSelf && createResponsiveStyles(props.alignSelf, "align-self")(props)}
  ${props.gap && createResponsiveStyles(props.gap, "gap", resolveSpacing)(props)}
  ${props.rowGap && createResponsiveStyles(props.rowGap, "row-gap", resolveSpacing)(props)}
  ${props.columnGap && createResponsiveStyles(props.columnGap, "column-gap", resolveSpacing)(props)}
  
  /* Grid */
  ${props.gridTemplate && createResponsiveStyles(props.gridTemplate, "grid-template")(props)}
  ${props.gridTemplateColumns && createResponsiveStyles(props.gridTemplateColumns, "grid-template-columns")(props)}
  ${props.gridTemplateRows && createResponsiveStyles(props.gridTemplateRows, "grid-template-rows")(props)}
  ${props.gridTemplateAreas && createResponsiveStyles(props.gridTemplateAreas, "grid-template-areas")(props)}
  ${props.gridColumn && createResponsiveStyles(props.gridColumn, "grid-column")(props)}
  ${props.gridRow && createResponsiveStyles(props.gridRow, "grid-row")(props)}
  ${props.gridArea && createResponsiveStyles(props.gridArea, "grid-area")(props)}
  ${props.gridAutoColumns && createResponsiveStyles(props.gridAutoColumns, "grid-auto-columns")(props)}
  ${props.gridAutoRows && createResponsiveStyles(props.gridAutoRows, "grid-auto-rows")(props)}
  ${props.gridAutoFlow && createResponsiveStyles(props.gridAutoFlow, "grid-auto-flow")(props)}
  ${props.justifyItems && createResponsiveStyles(props.justifyItems, "justify-items")(props)}
  ${props.justifySelf && createResponsiveStyles(props.justifySelf, "justify-self")(props)}
  ${props.placeContent && createResponsiveStyles(props.placeContent, "place-content")(props)}
  ${props.placeItems && createResponsiveStyles(props.placeItems, "place-items")(props)}
  ${props.placeSelf && createResponsiveStyles(props.placeSelf, "place-self")(props)}
  ${props.gridGap && createResponsiveStyles(props.gridGap, "grid-gap", resolveSpacing)(props)}
  ${props.gridRowGap && createResponsiveStyles(props.gridRowGap, "grid-row-gap", resolveSpacing)(props)}
  ${props.gridColumnGap && createResponsiveStyles(props.gridColumnGap, "grid-column-gap", resolveSpacing)(props)}
  
  /* Background */
  ${(props.bg || props.bgColor) && createResponsiveStyles(props.bg || props.bgColor, "background-color", resolveColor)(props)}
  ${props.bgImage && createResponsiveStyles(props.bgImage, "background-image")(props)}
  ${props.bgSize && createResponsiveStyles(props.bgSize, "background-size")(props)}
  ${props.bgPosition && createResponsiveStyles(props.bgPosition, "background-position")(props)}
  ${props.bgRepeat && createResponsiveStyles(props.bgRepeat, "background-repeat")(props)}
  ${props.bgAttachment && createResponsiveStyles(props.bgAttachment, "background-attachment")(props)}
  ${props.bgClip && createResponsiveStyles(props.bgClip, "background-clip")(props)}
  ${props.bgOrigin && createResponsiveStyles(props.bgOrigin, "background-origin")(props)}
  
  /* Border */
  ${props.border && createResponsiveStyles(props.border, "border")(props)}
  ${props.borderTop && createResponsiveStyles(props.borderTop, "border-top")(props)}
  ${props.borderRight && createResponsiveStyles(props.borderRight, "border-right")(props)}
  ${props.borderBottom && createResponsiveStyles(props.borderBottom, "border-bottom")(props)}
  ${props.borderLeft && createResponsiveStyles(props.borderLeft, "border-left")(props)}
  ${props.borderWidth && createResponsiveStyles(props.borderWidth, "border-width")(props)}
  ${props.borderTopWidth && createResponsiveStyles(props.borderTopWidth, "border-top-width")(props)}
  ${props.borderRightWidth && createResponsiveStyles(props.borderRightWidth, "border-right-width")(props)}
  ${props.borderBottomWidth && createResponsiveStyles(props.borderBottomWidth, "border-bottom-width")(props)}
  ${props.borderLeftWidth && createResponsiveStyles(props.borderLeftWidth, "border-left-width")(props)}
  ${props.borderColor && createResponsiveStyles(props.borderColor, "border-color", resolveColor)(props)}
  ${props.borderTopColor && createResponsiveStyles(props.borderTopColor, "border-top-color", resolveColor)(props)}
  ${props.borderRightColor && createResponsiveStyles(props.borderRightColor, "border-right-color", resolveColor)(props)}
  ${props.borderBottomColor && createResponsiveStyles(props.borderBottomColor, "border-bottom-color", resolveColor)(props)}
  ${props.borderLeftColor && createResponsiveStyles(props.borderLeftColor, "border-left-color", resolveColor)(props)}
  ${props.borderStyle && createResponsiveStyles(props.borderStyle, "border-style")(props)}
  ${props.borderTopStyle && createResponsiveStyles(props.borderTopStyle, "border-top-style")(props)}
  ${props.borderRightStyle && createResponsiveStyles(props.borderRightStyle, "border-right-style")(props)}
  ${props.borderBottomStyle && createResponsiveStyles(props.borderBottomStyle, "border-bottom-style")(props)}
  ${props.borderLeftStyle && createResponsiveStyles(props.borderLeftStyle, "border-left-style")(props)}
  ${props.borderRadius && createResponsiveStyles(props.borderRadius, "border-radius", resolveBorderRadius)(props)}
  ${props.borderTopLeftRadius && createResponsiveStyles(props.borderTopLeftRadius, "border-top-left-radius", resolveBorderRadius)(props)}
  ${props.borderTopRightRadius && createResponsiveStyles(props.borderTopRightRadius, "border-top-right-radius", resolveBorderRadius)(props)}
  ${props.borderBottomLeftRadius && createResponsiveStyles(props.borderBottomLeftRadius, "border-bottom-left-radius", resolveBorderRadius)(props)}
  ${props.borderBottomRightRadius && createResponsiveStyles(props.borderBottomRightRadius, "border-bottom-right-radius", resolveBorderRadius)(props)}
  ${props.borderCollapse && createResponsiveStyles(props.borderCollapse, "border-collapse")(props)}
  ${props.borderSpacing && createResponsiveStyles(props.borderSpacing, "border-spacing")(props)}
  
  /* Typography */
  ${props.color && createResponsiveStyles(props.color, "color", resolveColor)(props)}
  ${props.fontSize && createResponsiveStyles(props.fontSize, "font-size", resolveFontSize)(props)}
  ${props.fontWeight && createResponsiveStyles(props.fontWeight, "font-weight", resolveFontWeight)(props)}
  ${props.lineHeight && createResponsiveStyles(props.lineHeight, "line-height", resolveLineHeight)(props)}
  ${props.fontFamily && createResponsiveStyles(props.fontFamily, "font-family")(props)}
  ${props.fontStyle && createResponsiveStyles(props.fontStyle, "font-style")(props)}
  ${props.fontVariant && createResponsiveStyles(props.fontVariant, "font-variant")(props)}
  ${props.textAlign && createResponsiveStyles(props.textAlign, "text-align")(props)}
  ${props.textTransform && createResponsiveStyles(props.textTransform, "text-transform")(props)}
  ${props.textDecoration && createResponsiveStyles(props.textDecoration, "text-decoration")(props)}
  ${props.textDecorationLine && createResponsiveStyles(props.textDecorationLine, "text-decoration-line")(props)}
  ${props.textDecorationColor && createResponsiveStyles(props.textDecorationColor, "text-decoration-color", resolveColor)(props)}
  ${props.textDecorationStyle && createResponsiveStyles(props.textDecorationStyle, "text-decoration-style")(props)}
  ${props.textDecorationThickness && createResponsiveStyles(props.textDecorationThickness, "text-decoration-thickness")(props)}
  ${props.textUnderlineOffset && createResponsiveStyles(props.textUnderlineOffset, "text-underline-offset")(props)}
  ${props.textIndent && createResponsiveStyles(props.textIndent, "text-indent")(props)}
  ${props.textShadow && createResponsiveStyles(props.textShadow, "text-shadow")(props)}
  ${props.letterSpacing && createResponsiveStyles(props.letterSpacing, "letter-spacing")(props)}
  ${props.wordSpacing && createResponsiveStyles(props.wordSpacing, "word-spacing")(props)}
  ${props.whiteSpace && createResponsiveStyles(props.whiteSpace, "white-space")(props)}
  ${props.wordBreak && createResponsiveStyles(props.wordBreak, "word-break")(props)}
  ${props.wordWrap && createResponsiveStyles(props.wordWrap, "word-wrap")(props)}
  ${props.hyphens && createResponsiveStyles(props.hyphens, "hyphens")(props)}
  ${props.writingMode && createResponsiveStyles(props.writingMode, "writing-mode")(props)}
  ${props.textOrientation && createResponsiveStyles(props.textOrientation, "text-orientation")(props)}
  ${props.verticalAlign && createResponsiveStyles(props.verticalAlign, "vertical-align")(props)}
  
  /* List styles */
  ${props.listStyle && createResponsiveStyles(props.listStyle, "list-style")(props)}
  ${props.listStyleType && createResponsiveStyles(props.listStyleType, "list-style-type")(props)}
  ${props.listStylePosition && createResponsiveStyles(props.listStylePosition, "list-style-position")(props)}
  ${props.listStyleImage && createResponsiveStyles(props.listStyleImage, "list-style-image")(props)}
  
  /* Overflow and clipping */
  ${props.overflow && createResponsiveStyles(props.overflow, "overflow")(props)}
  ${props.overflowX && createResponsiveStyles(props.overflowX, "overflow-x")(props)}
  ${props.overflowY && createResponsiveStyles(props.overflowY, "overflow-y")(props)}
  ${props.overflowWrap && createResponsiveStyles(props.overflowWrap, "overflow-wrap")(props)}
  ${props.textOverflow && createResponsiveStyles(props.textOverflow, "text-overflow")(props)}
  ${props.clip && createResponsiveStyles(props.clip, "clip")(props)}
  ${props.clipPath && createResponsiveStyles(props.clipPath, "clip-path")(props)}
  
  /* Opacity & Visibility */
  ${props.opacity && createResponsiveStyles(props.opacity, "opacity")(props)}
  ${props.visibility && createResponsiveStyles(props.visibility, "visibility")(props)}
  
  /* Shadow and filters */
  ${props.boxShadow && createResponsiveStyles(props.boxShadow, "box-shadow", (theme, val) => theme.shadows[val] || val)(props)}
  ${props.filter && createResponsiveStyles(props.filter, "filter")(props)}
  ${props.backdropFilter && createResponsiveStyles(props.backdropFilter, "backdrop-filter")(props)}
  
  /* Transform */
  ${props.transform && createResponsiveStyles(props.transform, "transform")(props)}
  ${props.transformOrigin && createResponsiveStyles(props.transformOrigin, "transform-origin")(props)}
  ${props.transformStyle && createResponsiveStyles(props.transformStyle, "transform-style")(props)}
  ${props.perspective && createResponsiveStyles(props.perspective, "perspective")(props)}
  ${props.perspectiveOrigin && createResponsiveStyles(props.perspectiveOrigin, "perspective-origin")(props)}
  ${props.backfaceVisibility && createResponsiveStyles(props.backfaceVisibility, "backface-visibility")(props)}
  
  /* Transitions and animations */
  ${props.transition && createResponsiveStyles(props.transition, "transition")(props)}
  ${props.transitionProperty && createResponsiveStyles(props.transitionProperty, "transition-property")(props)}
  ${props.transitionDuration && createResponsiveStyles(props.transitionDuration, "transition-duration")(props)}
  ${props.transitionTimingFunction && createResponsiveStyles(props.transitionTimingFunction, "transition-timing-function")(props)}
  ${props.transitionDelay && createResponsiveStyles(props.transitionDelay, "transition-delay")(props)}
  ${props.animation && createResponsiveStyles(props.animation, "animation")(props)}
  ${props.animationName && createResponsiveStyles(props.animationName, "animation-name")(props)}
  ${props.animationDuration && createResponsiveStyles(props.animationDuration, "animation-duration")(props)}
  ${props.animationTimingFunction && createResponsiveStyles(props.animationTimingFunction, "animation-timing-function")(props)}
  ${props.animationDelay && createResponsiveStyles(props.animationDelay, "animation-delay")(props)}
  ${props.animationIterationCount && createResponsiveStyles(props.animationIterationCount, "animation-iteration-count")(props)}
  ${props.animationDirection && createResponsiveStyles(props.animationDirection, "animation-direction")(props)}
  ${props.animationFillMode && createResponsiveStyles(props.animationFillMode, "animation-fill-mode")(props)}
  ${props.animationPlayState && createResponsiveStyles(props.animationPlayState, "animation-play-state")(props)}
  
  /* Interactivity */
  ${props.cursor && createResponsiveStyles(props.cursor, "cursor")(props)}
  ${props.userSelect && createResponsiveStyles(props.userSelect, "user-select")(props)}
  ${props.pointerEvents && createResponsiveStyles(props.pointerEvents, "pointer-events")(props)}
  ${props.resize && createResponsiveStyles(props.resize, "resize")(props)}
  ${props.scrollBehavior && createResponsiveStyles(props.scrollBehavior, "scroll-behavior")(props)}
  ${props.scrollMargin && createResponsiveStyles(props.scrollMargin, "scroll-margin")(props)}
  ${props.scrollPadding && createResponsiveStyles(props.scrollPadding, "scroll-padding")(props)}
  ${props.touchAction && createResponsiveStyles(props.touchAction, "touch-action")(props)}
  ${props.willChange && createResponsiveStyles(props.willChange, "will-change")(props)}
  
  /* Aspect ratio and object properties */
  ${props.aspectRatio && createResponsiveStyles(props.aspectRatio, "aspect-ratio")(props)}
  ${props.objectFit && createResponsiveStyles(props.objectFit, "object-fit")(props)}
  ${props.objectPosition && createResponsiveStyles(props.objectPosition, "object-position")(props)}
  
  /* Table properties */
  ${props.tableLayout && createResponsiveStyles(props.tableLayout, "table-layout")(props)}
  ${props.captionSide && createResponsiveStyles(props.captionSide, "caption-side")(props)}
  ${props.emptyCells && createResponsiveStyles(props.emptyCells, "empty-cells")(props)}
  
  /* Outline */
  ${props.outline && createResponsiveStyles(props.outline, "outline")(props)}
  ${props.outlineColor && createResponsiveStyles(props.outlineColor, "outline-color", resolveColor)(props)}
  ${props.outlineStyle && createResponsiveStyles(props.outlineStyle, "outline-style")(props)}
  ${props.outlineWidth && createResponsiveStyles(props.outlineWidth, "outline-width")(props)}
  ${props.outlineOffset && createResponsiveStyles(props.outlineOffset, "outline-offset")(props)}
  
  /* Appearance and system */
  ${props.appearance && createResponsiveStyles(props.appearance, "appearance")(props)}
  ${props.content && createResponsiveStyles(props.content, "content")(props)}
  ${props.quotes && createResponsiveStyles(props.quotes, "quotes")(props)}
  ${props.counterReset && createResponsiveStyles(props.counterReset, "counter-reset")(props)}
  ${props.counterIncrement && createResponsiveStyles(props.counterIncrement, "counter-increment")(props)}
  
  /* Custom CSS */
  ${props.css}
`;

const StyledBox = styled.div<StyledBoxProps>`
  ${getBoxStyles}
`;

export const Box = React.forwardRef<HTMLElement, BoxProps>(
	({ as = "div", children, ...props }, ref) => {
		return (
			<StyledBox as={as} ref={ref} {...props}>
				{children}
			</StyledBox>
		);
	},
);

Box.displayName = "Box";
