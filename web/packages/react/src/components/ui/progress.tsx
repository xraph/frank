"use client";

import * as ProgressPrimitive from "@radix-ui/react-progress";
import type * as React from "react";

import { cn } from "@/lib/utils";

interface ProgressProps
	extends React.ComponentProps<typeof ProgressPrimitive.Root> {
	value: number;
	progressVariant?: "default" | "success" | "warning" | "danger";
}

function Progress({
	className,
	value,
	progressVariant = "default",
	...props
}: ProgressProps) {
	// Map color variants to actual color classes
	const colorClasses: any = {
		default: "bg-primary",
		success: "bg-teal-500",
		warning: "bg-yellow-500",
		danger: "bg-red-500",
	};

	// Get the appropriate color class based on variant
	const colorClass = colorClasses[progressVariant];

	return (
		<ProgressPrimitive.Root
			data-slot="progress"
			className={cn(
				"bg-primary/20 relative h-2 w-full overflow-hidden rounded-full",
				className,
			)}
			{...props}
		>
			<ProgressPrimitive.Indicator
				data-slot="progress-indicator"
				className={cn("h-full w-full flex-1 transition-all", colorClass)}
				style={{ transform: `translateX(-${100 - (value || 0)}%)` }}
			/>
		</ProgressPrimitive.Root>
	);
}

export { Progress };
