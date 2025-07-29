"use client";

import { radiusStyles, sizeStyles } from "@/lib/styles";
import { cn } from "@/lib/utils";
import * as TabsPrimitive from "@radix-ui/react-tabs";
import { type VariantProps, cva } from "class-variance-authority";
import type * as React from "react";

export const sizeWithPaddingStyles = {
	xs: `${sizeStyles.xs} px-2 py-2 has-[>svg]:px-1.5`,
	sm: `${sizeStyles.sm} px-3 py-2`,
	default: `${sizeStyles.default} px-4 py-3 has-[>svg]:px-3`,
	md: `${sizeStyles.md} px-4 py-3 has-[>svg]:px-3`,
	lg: `${sizeStyles.lg} px-6 py-5 has-[>svg]:px-4`,
	xl: `${sizeStyles.xl} px-8 py-7 has-[>svg]:px-5`,
};

export const tabColorStyles = {
	primary: `
        data-[state=active]:border-primary data-[state=active]:text-primary
      `,
	secondary: `
        data-[state=active]:border-gray-600 data-[state=active]:text-gray-600
      `,
	success: `
        data-[state=active]:border-green-600 data-[state=active]:text-green-600
      `,
	warning: `
        data-[state=active]:border-yellow-600 data-[state=active]:text-yellow-600
      `,
	error: `
        data-[state=active]:border-red-600 data-[state=active]:text-red-600
      `,
	default: `
        data-[state=active]:border-foreground data-[state=active]:text-foreground
      `,
	tertiary: `
        data-[state=active]:border-gray-700 data-[state=active]:text-gray-700
      `,
	quaternary: `
        data-[state=active]:border-b-gray-300 data-[state=active]:text-gray-300
      `,
};

// TabsList Variants
const tabsListVariants = cva("inline-flex items-center", {
	variants: {
		variant: {
			solid: "bg-muted text-muted-foreground rounded-lg",
			underlined: "border-b-2 border-muted",
			bordered: "border border-muted rounded-lg",
			light: "text-foreground/70",
		},
		fullWidth: {
			true: "",
			false: "w-fit",
		},
		align: {
			left: "justify-start",
			center: "justify-center",
			right: "justify-end",
		},
		radius: radiusStyles,
	},
	defaultVariants: {
		variant: "solid",
		fullWidth: true,
		align: "right",
		radius: "sm",
	},
});

// TabsTrigger Variants
const tabsTriggerVariants = cva(
	"inline-flex items-center justify-center whitespace-nowrap transition-all text-sm font-medium disabled:pointer-events-none disabled:opacity-50 aria-invalid:focus-visible:ring-0",
	{
		variants: {
			variant: {
				solid:
					"px-2 py-1 rounded-md data-[state=active]:shadow-sm data-[state=active]:bg-background data-[state=active]:text-foreground focus-visible:ring-4 focus-visible:outline-1",
				underlined:
					"px-2 py-1 border-b-2 !rounded-none border-transparent data-[state=active]:border-b-primary data-[state=active]:text-foreground transition-colors",
				bordered:
					"px-3 py-1 border data-[state=active]:bg-muted data-[state=active]:shadow-sm focus-visible:ring-4 rounded-md transition-colors",
				light:
					"px-2 py-1 rounded-md data-[state=active]:text-foreground data-[state=active]:font-semibold text-foreground/70 hover:text-foreground",
			},
			size: sizeWithPaddingStyles,
			radius: radiusStyles,
			color: tabColorStyles,
		},
		defaultVariants: {
			variant: "solid",
			size: "md",
			radius: "md",
			color: "default",
		},
	},
);

// TabsContent Variants
const tabsContentVariants = cva(
	"flex-1 transition-[color,box-shadow] focus-visible:ring-4 focus-visible:outline-1",
	{
		variants: {
			variant: {
				solid: "ring-ring/10 dark:ring-ring/20",
				underlined: "",
				bordered: "",
				light: "",
			},
		},
		defaultVariants: {
			variant: "solid",
		},
	},
);

// Tabs Component
function Tabs({
	className,
	...props
}: React.ComponentProps<typeof TabsPrimitive.Root>) {
	return (
		<TabsPrimitive.Root
			data-slot="tabs"
			className={cn("flex flex-col gap-2", className)}
			{...props}
		/>
	);
}

// TabsList Component
function TabsList({
	className,
	variant,
	align,
	fullWidth,
	radius,
	...props
}: React.ComponentProps<typeof TabsPrimitive.List> &
	VariantProps<typeof tabsListVariants>) {
	return (
		<TabsPrimitive.List
			data-slot="tabs-list"
			className={cn(
				tabsListVariants({ variant, align, fullWidth, radius }),
				className,
			)}
			{...props}
		/>
	);
}

// TabsTrigger Component
type TabsTriggerProps = React.ComponentProps<typeof TabsPrimitive.Trigger> &
	VariantProps<typeof tabsTriggerVariants>;

function TabsTrigger({
	className,
	variant,
	size,
	radius,
	color,
	...props
}: TabsTriggerProps) {
	return (
		<TabsPrimitive.Trigger
			data-slot="tabs-trigger"
			className={cn(
				tabsTriggerVariants({ variant, size, radius, color }),
				className,
			)}
			{...props}
		/>
	);
}

// TabsContent Component
function TabsContent({
	className,
	variant,
	...props
}: React.ComponentProps<typeof TabsPrimitive.Content> &
	VariantProps<typeof tabsContentVariants>) {
	return (
		<TabsPrimitive.Content
			data-slot="tabs-content"
			className={cn(tabsContentVariants({ variant }), className)}
			{...props}
		/>
	);
}

export { Tabs, TabsList, TabsTrigger, TabsContent };
export type { TabsTriggerProps };
