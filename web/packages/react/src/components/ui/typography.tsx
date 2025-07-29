import { cn } from "@/lib/utils";
import { type VariantProps, cva } from "class-variance-authority";
import type React from "react";
import { type HTMLAttributes, forwardRef, memo } from "react";
import { Box, type BoxProps } from "./box"; // Import the Box component

/**
 * Heading component for displaying titles and section headers
 * Supports h1-h6 sizes with responsive scaling and custom element types
 * @example
 * <Heading size="h1">Page Title</Heading>
 * <Heading size="h3" color="muted">Section Header</Heading>
 */
const headingVariants = cva("font-heading leading-tight tracking-tight", {
	variants: {
		size: {
			h1: "text-4xl md:text-5xl lg:text-6xl font-bold",
			h2: "text-3xl md:text-4xl font-bold",
			h3: "text-2xl md:text-3xl font-semibold",
			h4: "text-xl md:text-2xl font-semibold",
			h5: "text-lg md:text-xl font-medium",
			h6: "text-base md:text-lg font-medium",
		},
		color: {
			default: "text-foreground",
			muted: "text-muted-foreground",
			accent: "text-primary",
			success: "text-green-600 dark:text-green-500",
			warning: "text-amber-600 dark:text-amber-500",
			error: "text-red-600 dark:text-red-500",
		},
		align: {
			left: "text-left",
			center: "text-center",
			right: "text-right",
		},
	},
	defaultVariants: {
		size: "h1",
		color: "default",
		align: "left",
	},
});

/**
 * Paragraph component for displaying body text in various sizes
 * Supports different weights, colors, and text overflow handling
 * @example
 * <Paragraph size="medium">Standard paragraph text</Paragraph>
 * <Paragraph size="small" color="muted" truncate>Truncated text with ellipsis</Paragraph>
 */
const paragraphVariants = cva("font-body", {
	variants: {
		size: {
			large: "text-lg leading-relaxed",
			medium: "text-base leading-relaxed",
			small: "text-sm leading-normal",
			xs: "text-xs leading-normal",
		},
		weight: {
			regular: "font-normal",
			medium: "font-medium",
			semibold: "font-semibold",
			bold: "font-bold",
		},
		color: {
			default: "text-foreground",
			muted: "text-muted-foreground",
			accent: "text-primary",
			success: "text-green-600 dark:text-green-500",
			warning: "text-amber-600 dark:text-amber-500",
			error: "text-red-600 dark:text-red-500",
		},
		align: {
			left: "text-left",
			center: "text-center",
			right: "text-right",
			justify: "text-justify",
		},
		font: {
			sans: "font-sans",
			serif: "font-serif",
			mono: "font-mono",
		},
		truncate: {
			true: "truncate",
		},
		lineClamp: {
			1: "line-clamp-1",
			2: "line-clamp-2",
			3: "line-clamp-3",
			4: "line-clamp-4",
		},
	},
	defaultVariants: {
		size: "medium",
		weight: "regular",
		color: "default",
		align: "left",
		font: "sans",
	},
	compoundVariants: [
		{
			truncate: true,
			className: "overflow-hidden text-ellipsis whitespace-nowrap",
		},
	],
});

/**
 * Label component for interface labels, form fields, and short text elements
 * @example
 * <Label size="1" htmlFor="email">Email Address</Label>
 * <Label size="3" color="error">Required field</Label>
 */
const labelVariants = cva("font-display", {
	variants: {
		size: {
			"1": "text-lg font-medium leading-snug",
			"2": "text-base font-medium leading-snug",
			"3": "text-sm font-medium leading-snug",
			"4": "text-xs font-medium leading-tight",
		},
		weight: {
			regular: "font-normal",
			medium: "font-medium",
			semibold: "font-semibold",
			bold: "font-bold",
		},
		color: {
			default: "text-foreground",
			muted: "text-muted-foreground",
			accent: "text-primary",
			success: "text-green-600 dark:text-green-500",
			warning: "text-amber-600 dark:text-amber-500",
			error: "text-red-600 dark:text-red-500",
		},
		required: {
			true: "after:content-['*'] after:ml-0.5 after:text-red-500",
		},
		srOnly: {
			true: "sr-only",
		},
	},
	defaultVariants: {
		size: "2",
		weight: "medium",
		color: "default",
	},
});

/**
 * Caption component for supplementary text, image descriptions, and metadata
 * @example
 * <Caption>Photo taken in 2023</Caption>
 * <Caption size="small" color="muted">Last updated: Yesterday</Caption>
 */
const captionVariants = cva("font-mono", {
	variants: {
		size: {
			default: "text-sm",
			small: "text-xs",
		},
		color: {
			default: "text-foreground",
			muted: "text-muted-foreground",
			accent: "text-primary",
			success: "text-green-600 dark:text-green-500",
			warning: "text-amber-600 dark:text-amber-500",
			error: "text-red-600 dark:text-red-500",
		},
		align: {
			left: "text-left",
			center: "text-center",
			right: "text-right",
		},
	},
	defaultVariants: {
		size: "default",
		color: "muted",
		align: "left",
	},
});

// Common props shared across all typography components - extended from BoxProps
export interface BaseTypographyProps extends Omit<BoxProps, "color"> {
	color?: "default" | "muted" | "accent" | "success" | "warning" | "error";
}

// Heading specific props
export interface HeadingProps
	extends Omit<BaseTypographyProps, "align">,
		Omit<VariantProps<typeof headingVariants>, "color"> {
	align?: "left" | "center" | "right";
}

// Paragraph specific props
export interface ParagraphProps
	extends Omit<BaseTypographyProps, "align">,
		Omit<VariantProps<typeof paragraphVariants>, "color"> {
	weight?: "regular" | "medium" | "semibold" | "bold";
	align?: "left" | "center" | "right" | "justify";
	font?: "sans" | "serif" | "mono";
	truncate?: boolean;
	lineClamp?: 1 | 2 | 3 | 4;
}

// Label specific props
export interface LabelProps
	extends BaseTypographyProps,
		Omit<VariantProps<typeof labelVariants>, "color"> {
	weight?: "regular" | "medium" | "semibold" | "bold";
	required?: boolean;
	srOnly?: boolean;
}

// Caption specific props
export interface CaptionProps
	extends Omit<BaseTypographyProps, "align">,
		Omit<VariantProps<typeof captionVariants>, "color"> {
	align?: "left" | "center" | "right";
}

// Animation wrapper for typography components
const withFadeAnimation = <P extends BaseTypographyProps>(
	Component: React.ComponentType<P>,
) => {
	return forwardRef<HTMLElement, P & { animate?: boolean }>(
		({ animate, ...props }, ref) => {
			return (
				<Component ref={ref} animate={animate} {...(props as unknown as P)} />
			);
		},
	);
};

// Heading Components
export const Heading = memo(
	forwardRef<HTMLHeadingElement, HeadingProps>(
		({ className, size, color, align, as, children, ...props }, ref) => {
			const Component =
				as ||
				(size === "h1"
					? "h1"
					: size === "h2"
						? "h2"
						: size === "h3"
							? "h3"
							: size === "h4"
								? "h4"
								: size === "h5"
									? "h5"
									: "h6");

			// Accessibility improvement for non-standard heading elements
			const ariaProps =
				as && ["h1", "h2", "h3", "h4", "h5", "h6"].includes(String(size))
					? { role: "heading", "aria-level": Number(String(size).substring(1)) }
					: {};

			return (
				<Box
					as={Component}
					ref={ref}
					className={cn(headingVariants({ size, color, align, className }))}
					{...ariaProps}
					{...props}
				>
					{children}
				</Box>
			);
		},
	),
);
Heading.displayName = "Heading";

// Paragraph Components
export const Paragraph = memo(
	forwardRef<HTMLParagraphElement, ParagraphProps>(
		(
			{
				className,
				size,
				weight,
				color,
				align,
				font,
				truncate,
				lineClamp,
				as = "p",
				children,
				...props
			},
			ref,
		) => {
			// Warning for incompatible props in development
			if (process.env.NODE_ENV === "development" && truncate && lineClamp) {
				console.warn(
					"Typography: Both truncate and lineClamp props are set. truncate will take precedence.",
				);
			}

			return (
				<Box
					as={as}
					ref={ref}
					className={cn(
						paragraphVariants({
							size,
							weight,
							color,
							align,
							font,
							truncate,
							lineClamp,
							className,
						}),
					)}
					dir={props.dir}
					{...props}
				>
					{children}
				</Box>
			);
		},
	),
);
Paragraph.displayName = "Paragraph";

// Pre-configured Paragraph components
export const ParagraphLarge = memo(
	forwardRef<HTMLParagraphElement, Omit<ParagraphProps, "size">>(
		(props, ref) => <Paragraph ref={ref} size="large" {...props} />,
	),
);
ParagraphLarge.displayName = "ParagraphLarge";

export const ParagraphMedium = memo(
	forwardRef<HTMLParagraphElement, Omit<ParagraphProps, "size">>(
		(props, ref) => <Paragraph ref={ref} size="medium" {...props} />,
	),
);
ParagraphMedium.displayName = "ParagraphMedium";

export const ParagraphSmall = memo(
	forwardRef<HTMLParagraphElement, Omit<ParagraphProps, "size">>(
		(props, ref) => <Paragraph ref={ref} size="small" {...props} />,
	),
);
ParagraphSmall.displayName = "ParagraphSmall";

export const ParagraphXS = memo(
	forwardRef<HTMLParagraphElement, Omit<ParagraphProps, "size">>(
		(props, ref) => <Paragraph ref={ref} size="xs" {...props} />,
	),
);
ParagraphXS.displayName = "ParagraphXS";

// Label Components
export const Label = memo(
	forwardRef<HTMLSpanElement, LabelProps>(
		(
			{
				className,
				size,
				weight,
				color,
				required,
				srOnly,
				as = "span",
				children,
				...props
			},
			ref,
		) => {
			return (
				<Box
					as={as}
					ref={ref as any}
					className={cn(
						labelVariants({ size, weight, color, required, srOnly, className }),
					)}
					{...props}
				>
					{children}
				</Box>
			);
		},
	),
);
Label.displayName = "Label";

// Pre-configured Label components
export const Label1 = memo(
	forwardRef<HTMLSpanElement, Omit<LabelProps, "size">>((props, ref) => (
		<Label ref={ref} size="1" {...props} />
	)),
);
Label1.displayName = "Label1";

export const Label2 = memo(
	forwardRef<HTMLSpanElement, Omit<LabelProps, "size">>((props, ref) => (
		<Label ref={ref} size="2" {...props} />
	)),
);
Label2.displayName = "Label2";

export const Label3 = memo(
	forwardRef<HTMLSpanElement, Omit<LabelProps, "size">>((props, ref) => (
		<Label ref={ref} size="3" {...props} />
	)),
);
Label3.displayName = "Label3";

export const Label4 = memo(
	forwardRef<HTMLSpanElement, Omit<LabelProps, "size">>((props, ref) => (
		<Label ref={ref} size="4" {...props} />
	)),
);
Label4.displayName = "Label4";

// Caption Component
export const Caption = memo(
	forwardRef<HTMLSpanElement, CaptionProps>(
		(
			{ className, size, color, align, as = "span", children, ...props },
			ref,
		) => {
			return (
				<Box
					as={as}
					ref={ref as any}
					className={cn(captionVariants({ size, color, align, className }))}
					{...props}
				>
					{children}
				</Box>
			);
		},
	),
);
Caption.displayName = "Caption";

// Pre-configured Caption components
export const CaptionDefault = memo(
	forwardRef<HTMLSpanElement, Omit<CaptionProps, "size">>((props, ref) => (
		<Caption ref={ref} size="default" {...props} />
	)),
);
CaptionDefault.displayName = "CaptionDefault";

export const CaptionSmall = memo(
	forwardRef<HTMLSpanElement, Omit<CaptionProps, "size">>((props, ref) => (
		<Caption ref={ref} size="small" {...props} />
	)),
);
CaptionSmall.displayName = "CaptionSmall";

// Animated versions of components
export const AnimatedHeading = withFadeAnimation(Heading as any);
export const AnimatedParagraph = withFadeAnimation(Paragraph as any);
export const AnimatedLabel = withFadeAnimation(Label);
export const AnimatedCaption = withFadeAnimation(Caption as any);

// Helper function for screen reader only text
export const ScreenReaderText = memo(
	({ children, ...props }: HTMLAttributes<HTMLSpanElement>) => (
		<Box as="span" className="sr-only" {...props}>
			{children}
		</Box>
	),
);
ScreenReaderText.displayName = "ScreenReaderText";

// RTL support helper
export const RTLText = memo(
	({ children, ...props }: HTMLAttributes<HTMLSpanElement>) => (
		<Box as="span" dir="rtl" {...props}>
			{children}
		</Box>
	),
);
RTLText.displayName = "RTLText";
export function Muted({
	children,
	className,
	...props
}: React.ComponentProps<"p">) {
	return (
		<p
			{...props}
			className={`text-sm text-muted-foreground ${className || ""}`}
		>
			{children}
		</p>
	);
}

export function H1({
	children,
	className,
	...props
}: React.ComponentProps<"h1">) {
	return (
		<h1
			{...props}
			className={`scroll-m-20 text-4xl font-extrabold tracking-tight lg:text-5xl ${className || ""}`}
		>
			{children}
		</h1>
	);
}

export function H2({
	children,
	className,
	...props
}: React.ComponentProps<"h2">) {
	return (
		<h1
			{...props}
			className={`scroll-m-20 border-b pb-2 text-3xl font-semibold tracking-tight first:mt-0 ${className || ""}`}
		>
			{children}
		</h1>
	);
}

export function H3({
	children,
	className,
	...props
}: React.ComponentProps<"h3">) {
	return (
		<h3
			{...props}
			className={`scroll-m-20 text-2xl font-semibold tracking-tight ${className || ""}`}
		>
			{children}
		</h3>
	);
}

export function H4({
	children,
	className,
	...props
}: React.ComponentProps<"h4">) {
	return (
		<h4
			{...props}
			className={`scroll-m-20 text-xl font-semibold tracking-tight ${className || ""}`}
		>
			{children}
		</h4>
	);
}

export function P({
	children,
	className,
	...props
}: React.ComponentProps<"p">) {
	return (
		<p
			{...props}
			className={`leading-7 [&:not(:first-child)]:mt-6 ${className || ""}`}
		>
			{children}
		</p>
	);
}

export function Blockquote({
	children,
	className,
	...props
}: React.ComponentProps<"blockquote">) {
	return (
		<blockquote
			{...props}
			className={`mt-6 border-l-2 pl-6 italic ${className || ""}`}
		>
			{children}
		</blockquote>
	);
}

export function Code({
	children,
	className,
	...props
}: React.ComponentProps<"code">) {
	return (
		<code
			{...props}
			className={`relative rounded bg-muted px-[0.3rem] py-[0.2rem] font-mono text-sm font-semibold ${className || ""}`}
		>
			{children}
		</code>
	);
}

export function Lead({
	children,
	className,
	...props
}: React.ComponentProps<"p">) {
	return (
		<p
			{...props}
			className={`text-xl text-muted-foreground ${className || ""}`}
		>
			{children}
		</p>
	);
}

export function Large({
	children,
	className,
	...props
}: React.ComponentProps<"p">) {
	return (
		<p {...props} className={`text-lg font-semibold ${className || ""}`}>
			{children}
		</p>
	);
}

export function Small({
	children,
	className,
	...props
}: React.ComponentProps<"small">) {
	return (
		<small
			{...props}
			className={`text-sm font-medium leading-none ${className || ""}`}
		>
			{children}
		</small>
	);
}
