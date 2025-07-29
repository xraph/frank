import { Label } from "@/components/ui/label";
import { animatedStyles, radiusStyles } from "@/lib/styles";
import { cn } from "@/lib/utils";
import { type VariantProps, cva } from "class-variance-authority";
import type * as React from "react";

export const inputContainerColorStyles = {
	primary: `
        border-primary hover:not-focus-within:primary/20 focus-within:border-blue-600
        hover:ring-blue-200 focus-within:ring focus-within:ring-blue-300
      `,
	secondary: `
        border-gray-500 hover:border-gray-600 focus-within:border-gray-600
        hover:ring-gray-200 focus-within:ring focus-within:ring-gray-300
      `,
	success: `
        border-green-500 hover:not-focus-within:border-green-600 focus-within:border-green-600
        hover:ring-green-200 focus-within:ring focus-within:ring-green-300
      `,
	warning: `
        border-yellow-500 hover:not-focus-within:border-yellow-600 focus-within:border-yellow-600
        hover:ring-yellow-200 focus-within:ring focus-within:ring-yellow-300
      `,
	error: `
        border-red-500 hover:not-focus-within:border-red-600 focus-within:border-red-600
        hover:ring-red-200 focus-within:ring focus-within:ring-red-300
      `,
	default: `
        border-border hover:not-focus-within:border-border focus-within:border-foreground
        hover:ring-gray-100 focus-within:ring focus-within:ring-gray-400
      `,
	tertiary: `
        border-gray-200 hover:not-focus-within:border-gray-300 focus-within:border-gray-300
        hover:ring-gray-100 focus-within:ring focus-within:ring-gray-200
      `,
	quaternary: `
        border-gray-700 hover:not-focus-within:border-gray-600 focus-within:border-gray-600
        hover:ring-gray-500 focus-within:ring focus-within:ring-gray-600
      `,
};

export const inputColorStyles = {
	primary: `
        text-blue-600 placeholder:text-blue-400
        border-primary hover:not-focus-within:border-primary/20 focus-within:border-blue-600
        hover:ring-blue-200 focus-within:ring focus-within:ring-blue-300
      `,
	secondary: `
        text-gray-600 placeholder:text-gray-400
        border-gray-500 hover:border-gray-600 focus-within:border-gray-600
        hover:ring-gray-200 focus-within:ring focus-within:ring-gray-300
      `,
	success: `
        text-green-600 placeholder:text-green-400
        border-green-500 hover:not-focus-within:border-green-600 focus-within:border-green-600
        hover:ring-green-200 focus-within:ring focus-within:ring-green-300
      `,
	warning: `
        text-yellow-600 placeholder:text-yellow-400
        border-yellow-500 hover:not-focus-within:border-yellow-600 focus-within:border-yellow-600
        hover:ring-yellow-200 focus-within:ring focus-within:ring-yellow-300
      `,
	error: `
        text-red-600 placeholder:text-red-400
        border-red-500 hover:not-focus-within:border-red-600 focus-within:border-red-600
        hover:ring-red-200 focus-within:ring focus-within:ring-red-300
      `,
	default: `
        text-foreground placeholder:text-muted-foreground
        border-border hover:not-focus-within:border-border focus-within:border-foreground
        focus-within:ring-0
      `,
	tertiary: `
        text-gray-700 placeholder:text-gray-500
        border-gray-200 hover:not-focus-within:border-gray-300 focus-within:border-gray-300
        hover:ring-gray-100 focus-within:ring focus-within:ring-gray-200
      `,
	quaternary: `
        text-gray-300 placeholder:text-gray-500
        border-gray-700 hover:not-focus-within:border-gray-600 focus-within:border-gray-600
        hover:ring-gray-500 focus-within:ring focus-within:ring-gray-600
      `,
};

// Other utility-based styles
export const sizeStyles = {
	xs: "h-8 px-3 py-1.5 text-xs", // Smallest size: reduced padding and height for tight spacing
	sm: "h-9 px-3 py-2 text-sm", // Small but usable for most compact UIs
	md: "h-10 px-4 py-2 text-sm", // Default: Balanced size, text-aligns well for most uses
	lg: "h-12 px-4 py-3 text-base", // Larger: Comfortable for forms or inputs with more content
	xl: "h-14 px-6 py-4 text-lg", // Extra-large: Ideal for large forms, accessibility, or spacious UIs
};

// Other utility-based styles
export const minSizeStyles = {
	xs: "min-h-8 px-3 py-1.5 text-xs", // Smallest size: reduced padding and height for tight spacing
	sm: "min-h-9 px-3 py-2 text-sm", // Small but usable for most compact UIs
	md: "min-h-10 px-4 py-2 text-sm", // Default: Balanced size, text-aligns well for most uses
	lg: "min-h-12 px-4 py-3 text-base", // Larger: Comfortable for forms or inputs with more content
	xl: "min-h-14 px-6 py-4 text-lg", // Extra-large: Ideal for large forms, accessibility, or spacious UIs
};

export const inputSizeStyles = {
	xs: "text-xs",
	sm: "text-sm",
	default: "text-md",
	md: "text-md",
	lg: "text-lg",
	xl: "text-xl",
};

const baseStyles =
	"file:text-foreground hover:!ring-0 focus-within:!ring-0 hover:!outline-none outline-none focus-within:outline-none  placeholder:text-muted-foreground selection:bg-primary selection:text-primary-foreground  aria-invalid:border-destructive/60 dark:aria-invalid:border-destructive flex w-full bg-transparent file:inline-flex file:h-7 file:border-0 file:bg-transparent file:text-sm file:font-medium disabled:pointer-events-none disabled:cursor-not-allowed disabled:opacity-50";

export const inputVariants = cva(baseStyles, {
	variants: {
		size: inputSizeStyles,
		fullWidth: {
			true: "w-full justify-center",
			false: "",
		},
		color: inputColorStyles,
		animated: animatedStyles,
	},
	defaultVariants: {
		size: "md",
		fullWidth: false,
		animated: false,
		color: "default",
	},
});

export const inputContainerVariants = cva(
	"hover:!ring-0 focus-within:!ring-0 flex items-center gap-2 transition-colors",
	{
		variants: {
			variant: {
				flat: "!shadow-none border-0 bg-muted",
				bordered: "!bg-background border-2",
				underlined:
					"!bg-transparent border-0 border-input border-b-2 shadow-none",
				faded: "border-2 border-input/25 bg-muted",
			},
			color: inputContainerColorStyles,
			size: sizeStyles,
			radius: radiusStyles,
			fullWidth: {
				true: "w-full justify-center",
				false: "",
			},
			animated: animatedStyles,
		},
		defaultVariants: {
			variant: "bordered",
			color: "default",
			size: "md",
			radius: "md",
			fullWidth: false,
			animated: false,
		},
	},
);

// Define label positions: top, left, right, bottom
export const labelPositionStyles = {
	top: "flex-col items-start",
	left: "flex-row-reverse items-center",
	right: "flex-row items-center",
	bottom: "flex-col-reverse items-start",
};

export interface InputProps
	extends Omit<React.ComponentProps<"input">, "size" | "color">,
		VariantProps<typeof inputContainerVariants> {
	isDisabled?: boolean;
	isReadOnly?: boolean;
	isRequired?: boolean;
	isError?: boolean;
	isInvalid?: boolean;
	errorMessage?: string;
	hint?: string;
	startContent?: React.ReactNode;
	endContent?: React.ReactNode;
	inputSize?: number;
	label?: string | React.ReactNode;
	labelPlacement?: keyof typeof labelPositionStyles; // top, left, right, bottom
	fullWidth?: boolean;
}

export function Input({
	className,
	inputSize,
	size,
	radius,
	animated,
	variant,
	fullWidth = true,
	label,
	labelPlacement = "top", // Default label position is "top"
	type = "text",
	isDisabled,
	isRequired,
	isError,
	errorMessage,
	hint,
	isInvalid,
	startContent,
	endContent,
	color,
	onChange, // Destructure onChange from props
	...props
}: InputProps) {
	const handleChange = (event: React.ChangeEvent<HTMLInputElement>) => {
		if (onChange) {
			if (type === "number") {
				const numericValue =
					event.target.value === ""
						? null
						: Number.parseFloat(event.target.value);
				// Create a synthetic event or pass the value directly depending on what the original onChange expects.
				// For simplicity, we'll modify the event object.
				// Note: Modifying event objects directly is generally not recommended.
				// A more robust solution might involve creating a new event or calling onChange with just the value.
				Object.defineProperty(event.target, "value", {
					writable: true,
					value: numericValue,
				});
				onChange(event);
			} else {
				onChange(event);
			}
		}
	};

	return (
		<div
			className={cn(
				"space-y-1",
				labelPositionStyles[labelPlacement],
				labelPlacement === "left" || labelPlacement === "right"
					? "flex items-center gap-4"
					: "flex flex-col",
			)}
		>
			{label && (
				<Label
					htmlFor={props.id}
					// isDisabled={isDisabled}
					isRequired={isRequired}
					className={cn(
						"font-medium text-foreground text-sm leading-tight",
						labelPlacement === "top" || labelPlacement === "bottom"
							? "mb-2"
							: "mr-2",
					)}
				>
					{label}
				</Label>
			)}
			<div
				className={cn(
					inputContainerVariants({
						variant,
						size,
						radius: variant === "underlined" ? "none" : radius,
						animated,
						fullWidth,
						color,
					}),
					(isError || isInvalid) && "border-destructive",
					className,
				)}
			>
				{startContent && (
					<div className="flex items-center">{startContent}</div>
				)}
				<input
					type={type}
					data-slot="input"
					{...props}
					onChange={handleChange} // Use the new handleChange
					className={cn(
						inputVariants({
							size,
							animated,
							fullWidth,
							color,
						}),
						isError && "border-destructive",
						className,
					)}
					size={inputSize}
					disabled={isDisabled || props.disabled}
					required={isRequired || props.required}
					readOnly={props.isReadOnly}
				/>
				{endContent && <div className="flex items-center">{endContent}</div>}
			</div>
			{errorMessage ? (
				<p className="px-1 text-destructive text-xs">{errorMessage}</p>
			) : hint ? (
				<div className="px-1 text-muted-foreground text-xs">{hint}</div>
			) : null}
		</div>
	);
}
