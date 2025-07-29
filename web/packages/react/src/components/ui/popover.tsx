"use client";

import * as PopoverPrimitive from "@radix-ui/react-popover";
import type * as React from "react";

import { radiusStyles } from "@/lib/styles";
import { cn } from "@/lib/utils";
import { type VariantProps, cva } from "class-variance-authority";

function Popover({
	...props
}: React.ComponentProps<typeof PopoverPrimitive.Root>) {
	return <PopoverPrimitive.Root data-slot="popover" {...props} />;
}

function PopoverTrigger({
	...props
}: React.ComponentProps<typeof PopoverPrimitive.Trigger>) {
	return <PopoverPrimitive.Trigger data-slot="popover-trigger" {...props} />;
}

const contentVariants = cva(
	"data-[state=closed]:fade-out-0 data-[state=open]:fade-in-0 data-[state=closed]:zoom-out-95 data-[state=open]:zoom-in-95 data-[side=bottom]:slide-in-from-top-2 data-[side=left]:slide-in-from-right-2 data-[side=right]:slide-in-from-left-2 data-[side=top]:slide-in-from-bottom-2 z-50 border bg-popover p-4 text-popover-foreground shadow-md outline-hidden data-[state=closed]:animate-out data-[state=open]:animate-in",
	{
		variants: {
			radius: radiusStyles,
			fullWidth: {
				true: "w-full",
				false: "",
			},
		},
		defaultVariants: {
			radius: "md",
			fullWidth: true,
		},
	},
);

function PopoverContent({
	className,
	align = "center",
	sideOffset = 4,
	radius,
	fullWidth,
	...props
}: React.ComponentProps<typeof PopoverPrimitive.Content> &
	VariantProps<typeof contentVariants>) {
	return (
		<PopoverPrimitive.Portal>
			<PopoverPrimitive.Content
				data-slot="popover-content"
				align={align}
				sideOffset={sideOffset}
				className={cn(
					contentVariants({
						radius,
					}),
					className,
				)}
				style={
					fullWidth
						? { width: "var(--radix-popover-trigger-width)" }
						: undefined
				} // Dynamically match width
				{...props}
			/>
		</PopoverPrimitive.Portal>
	);
}

function PopoverAnchor({
	...props
}: React.ComponentProps<typeof PopoverPrimitive.Anchor>) {
	return <PopoverPrimitive.Anchor data-slot="popover-anchor" {...props} />;
}

export { Popover, PopoverTrigger, PopoverContent, PopoverAnchor };
