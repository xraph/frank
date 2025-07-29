import type * as React from "react";

import {
	inputContainerColorStyles,
	inputVariants,
	labelPositionStyles,
	minSizeStyles,
} from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { animatedStyles, radiusStyles } from "@/lib/styles";
import { cn } from "@/lib/utils";
import { type VariantProps, cva } from "class-variance-authority";

export const textAreaContainerVariants = cva(
	"hover:!ring-0 focus-within:!ring-0 flex items-center gap-2 transition-colors",
	{
		variants: {
			variant: {
				flat: "!shadow-none border-0",
				bordered: "!bg-background border-2",
				underlined:
					"!bg-transparent border-0 border-input border-b-2 shadow-none",
				faded: "border-2 border-input/40 bg-muted/10",
			},
			color: inputContainerColorStyles,
			size: minSizeStyles,
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

export interface TextareaProps
	extends Omit<
			React.ComponentProps<"textarea">,
			"size" | "color" | "required" | "disabled"
		>,
		VariantProps<typeof textAreaContainerVariants> {
	isDisabled?: boolean;
	isRequired?: boolean;
	isError?: boolean;
	error?: string;
	hint?: string;
	startContent?: React.ReactNode;
	endContent?: React.ReactNode;
	label?: string | React.ReactNode;
	labelPlacement?: keyof typeof labelPositionStyles; // top, left, right, bottom
	fullWidth?: boolean;
}

function Textarea({
	className,
	size,
	radius,
	animated,
	variant,
	fullWidth = true,
	label,
	labelPlacement = "top",
	isDisabled,
	isRequired,
	isError,
	error,
	hint,
	color,
	...props
}: TextareaProps) {
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
					textAreaContainerVariants({
						variant,
						size,
						radius: variant === "underlined" ? "none" : radius,
						animated,
						fullWidth,
						color,
					}),
					isError && "border-destructive",
					className,
				)}
			>
				<textarea
					data-slot="textarea"
					disabled={isDisabled}
					required={isRequired}
					className={cn(
						"field-sizing-content",
						inputVariants({
							size,
							animated,
							fullWidth,
							color,
						}),
						isError && "border-destructive",
						className,
					)}
					{...props}
				/>
			</div>
			{error ? (
				<p className="px-2 text-destructive text-xs">{error}</p>
			) : hint ? (
				<p className="px-2 text-muted-foreground text-xs">{hint}</p>
			) : null}
		</div>
	);
}

export { Textarea };
