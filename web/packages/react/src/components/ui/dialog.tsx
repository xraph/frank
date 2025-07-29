"use client";

import * as DialogPrimitive from "@radix-ui/react-dialog";
import { XIcon } from "lucide-react";
import type * as React from "react";

import { Button } from "@/components/ui/button";
import { radiusStyles } from "@/lib/styles";
import { cn } from "@/lib/utils";
import { type VariantProps, cva } from "class-variance-authority";

// Variants for dialog content (size and backdrop)
const dialogContentVariants = cva(
	"data-[state=closed]:fade-out-0 data-[state=open]:fade-in-0 data-[state=closed]:zoom-out-95 data-[state=open]:zoom-in-95 fixed top-[50%] left-[50%] z-50 grid w-full translate-x-[-50%] translate-y-[-50%] gap-4 border border-border bg-background p-6 shadow-sm duration-200 data-[state=closed]:animate-out data-[state=open]:animate-in",
	{
		variants: {
			size: {
				xs: "max-w-xs",
				sm: "max-w-sm",
				md: "max-w-md",
				lg: "max-w-lg",
				xl: "max-w-xl",
				"2xl": "max-w-2xl",
				"3xl": "max-w-3xl",
				"4xl": "max-w-4xl",
				"5xl": "max-w-5xl",
				full: "h-full w-full",
			},
			radius: radiusStyles,
		},
		defaultVariants: {
			size: "md",
			radius: "md",
		},
	},
);

// Variants for the dialog overlay
export const dialogOverlayVariants = cva(
	"data-[state=closed]:fade-out-0 data-[state=open]:fade-in-0 fixed inset-0 z-50 data-[state=closed]:animate-out data-[state=open]:animate-in",
	{
		variants: {
			backdrop: {
				opaque: "bg-black/50",
				blur: "bg-gray-500/30 backdrop-blur-sm",
				transparent: "bg-transparent",
			},
		},
		defaultVariants: {
			backdrop: "opaque",
		},
	},
);

interface DialogContentProps
	extends React.ComponentPropsWithoutRef<typeof DialogPrimitive.Content>,
		VariantProps<typeof dialogContentVariants> {
	draggable?: boolean;
	hideCloseButton?: boolean;
	backdrop?: "opaque" | "blur" | "transparent";
}

function Dialog({
	...props
}: React.ComponentProps<typeof DialogPrimitive.Root>) {
	return <DialogPrimitive.Root data-slot="dialog" {...props} />;
}

function DialogTrigger({
	...props
}: React.ComponentProps<typeof DialogPrimitive.Trigger>) {
	return <DialogPrimitive.Trigger data-slot="dialog-trigger" {...props} />;
}

function DialogPortal({
	...props
}: React.ComponentProps<typeof DialogPrimitive.Portal>) {
	return <DialogPrimitive.Portal data-slot="dialog-portal" {...props} />;
}

function DialogClose({
	...props
}: React.ComponentProps<typeof DialogPrimitive.Close>) {
	return <DialogPrimitive.Close data-slot="dialog-close" {...props} />;
}

function DialogOverlay({
	className,
	backdrop,
	...props
}: React.ComponentProps<typeof DialogPrimitive.Overlay> &
	VariantProps<typeof dialogOverlayVariants>) {
	return (
		<DialogPrimitive.Overlay
			data-slot="dialog-overlay"
			className={cn(dialogOverlayVariants({ backdrop }), className)}
			{...props}
		/>
	);
}

function DialogContent({
	className,
	children,
	backdrop,
	size,
	radius,
	hideCloseButton,
	...props
}: DialogContentProps) {
	return (
		<DialogPortal data-slot="dialog-portal">
			<DialogOverlay backdrop={backdrop} />
			<DialogPrimitive.Content
				data-slot="dialog-content"
				className={cn(dialogContentVariants({ size, radius }), className)}
				{...props}
			>
				{children}
				{!hideCloseButton && (
					<DialogPrimitive.Close className="absolute top-2 right-2 rounded-xs opacity-70 ring-offset-background transition-opacity hover:opacity-100 focus:outline-hidden focus:ring-2 focus:ring-ring focus:ring-offset-2 disabled:pointer-events-none data-[state=open]:bg-accent data-[state=open]:text-muted-foreground [&_svg:not([class*='size-'])]:size-4 [&_svg]:pointer-events-none [&_svg]:shrink-0">
						<Button size="sm" variant="ghost" radius="full" className="!p-2">
							<XIcon />
						</Button>
						<span className="sr-only">Close</span>
					</DialogPrimitive.Close>
				)}
			</DialogPrimitive.Content>
		</DialogPortal>
	);
}

function DialogHeader({ className, ...props }: React.ComponentProps<"div">) {
	return (
		<div
			data-slot="dialog-header"
			className={cn("flex flex-col gap-2 text-center sm:text-left", className)}
			{...props}
		/>
	);
}

function DialogBody({ className, ...props }: React.ComponentProps<"div">) {
	return (
		<div
			data-slot="dialog-body"
			className={cn("flex flex-col gap-2 text-center sm:text-left", className)}
			{...props}
		/>
	);
}

function DialogFooter({ className, ...props }: React.ComponentProps<"div">) {
	return (
		<div
			data-slot="dialog-footer"
			className={cn(
				"flex flex-col-reverse gap-2 sm:flex-row sm:justify-end",
				className,
			)}
			{...props}
		/>
	);
}

function DialogTitle({
	className,
	...props
}: React.ComponentProps<typeof DialogPrimitive.Title>) {
	return (
		<DialogPrimitive.Title
			data-slot="dialog-title"
			className={cn(
				"inline-flex items-center space-x-1 font-semibold text-lg text-foreground leading-none tracking-tight",
				className,
			)}
			{...props}
		/>
	);
}

function DialogDescription({
	className,
	...props
}: React.ComponentProps<typeof DialogPrimitive.Description>) {
	return (
		<DialogPrimitive.Description
			data-slot="dialog-description"
			className={cn("text-muted-foreground text-sm", className)}
			{...props}
		/>
	);
}

export {
	Dialog,
	DialogClose,
	DialogContent,
	DialogDescription,
	DialogFooter,
	DialogHeader,
	DialogOverlay,
	DialogPortal,
	DialogTitle,
	DialogTrigger,
	DialogBody,
};
