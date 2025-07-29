import {
	animatedStyles,
	isIconOnlyStyles,
	radiusStyles,
	rippleStyles,
	sizeWithPaddingStyles,
	variantStyles,
} from "@/lib/styles";
import { cn } from "@/lib/utils";
import { Ripple, useRipple } from "@heroui/ripple";
import { Slot, Slottable } from "@radix-ui/react-slot";
import { type VariantProps, cva } from "class-variance-authority";
import { Loader2 } from "lucide-react";
import type * as React from "react";

const baseStyles =
	"inline-flex items-center justify-center gap-2 whitespace-nowrap text-sm font-medium transition-[color,box-shadow] disabled:pointer-events-none [&_svg]:pointer-events-none [&_svg:not([class*='size-'])]:size-4 [&_svg]:shrink-0 ring-ring/10 dark:ring-ring/20 dark:outline-ring/40 outline-ring/50 focus-visible:ring-4 focus-visible:outline-1 aria-invalid:focus-visible:ring-0";

const buttonVariants = cva(baseStyles, {
	variants: {
		variant: variantStyles,
		size: sizeWithPaddingStyles,
		radius: radiusStyles,
		fullWidth: {
			true: "w-full justify-center",
			false: "",
		},
		ripple: rippleStyles,
		isIconOnly: isIconOnlyStyles,
		animated: animatedStyles,
		isLoading: {
			true: "cursor-wait", // styles for loading state, can add spinner here
			false: "cursor-pointer",
		},
	},
	defaultVariants: {
		variant: "secondary",
		size: "sm",
		radius: "md",
		fullWidth: false,
		ripple: true,
		animated: false,
		isIconOnly: false,
		isLoading: false,
	},
});

type OnPress = (ev: React.MouseEvent<HTMLButtonElement>) => void;

export interface ButtonProps
	extends React.ComponentProps<"button">,
		VariantProps<typeof buttonVariants> {
	asChild?: boolean;
	type?: "button" | "submit" | "reset";
	ariaLabel?: string;
	isLoading?: boolean;
	isDisabled?: boolean;
	onPress?: OnPress;
	startContent?: React.ReactNode;
	endContent?: React.ReactNode;
}

function Button({
	className,
	variant,
	size,
	radius,
	fullWidth,
	isIconOnly,
	asChild = false,
	type = "button", // Default type to "button"
	ariaLabel,
	isLoading,
	isDisabled = false,
	animated = false,
	ripple = true,
	disabled,
	children,
	startContent,
	endContent,
	onClick,
	onPress,
	...props
}: ButtonProps) {
	const Comp = asChild ? Slot : "button";
	const {
		onPress: onRipplePressHandler,
		onClear: onClearRipple,
		ripples,
	} = useRipple({
		disabled: isDisabled || isLoading, // Disable ripple if button is disabled or loading
	});

	const onPressHandler = (ev: React.MouseEvent<HTMLButtonElement>) => {
		if (isDisabled || isLoading) {
			return;
		}
		if (ripple) {
			onRipplePressHandler(ev as any);
		}

		onClick?.(ev);
		onPress?.(ev);
	};

	return (
		<Comp
			data-slot="button"
			className={cn(
				buttonVariants({
					variant,
					size,
					radius,
					fullWidth,
					ripple,
					isIconOnly,
					isLoading,
					className,
					animated,
				}),
			)}
			disabled={isDisabled || isLoading}
			type={type}
			aria-label={ariaLabel}
			onClick={onPressHandler}
			{...props}
		>
			{isLoading && <Loader2 className="mr-2 h-5 w-5 animate-spin" />}
			{!isLoading && startContent && (
				<span className="start-content">{startContent}</span>
			)}
			{isLoading && isIconOnly ? null : <Slottable>{children}</Slottable>}
			{!isLoading && endContent && (
				<span className="end-content">{endContent}</span>
			)}

			{ripple && <Ripple ripples={ripples} onClear={onClearRipple} />}
		</Comp>
	);
}

export { Button, buttonVariants };
