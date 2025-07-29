"use client";

import { cn } from "@/lib/utils";
import { useMemo, useState } from "react";

interface AvatarGroupProps<T = any> {
	max?: number;
	size?: "sm" | "md" | "lg" | "xl" | "xs";
	items?: T[];
	children: ((item: T) => React.ReactNode) | React.ReactNode[];
	className?: string;
	classNames?: {
		avatar?: string;
	};
}

export function AvatarGroup({
	children,
	max = 4,
	size = "lg",
	className,
	items,
	classNames,
}: AvatarGroupProps) {
	const [hoveredIndex, setHoveredIndex] = useState<number | null>(null);

	const renderedItems = useMemo(() => {
		if (typeof children != "function") {
			return children;
		}

		return items?.map(children) || [];
	}, [children]);

	const visibleUsers = renderedItems.slice(0, max);
	const remainingUsers =
		renderedItems.length > max ? renderedItems.length - max : 0;

	const sizeClasses = {
		xs: "size-6 text-xs",
		sm: "size-8 text-xs",
		md: "size-10 text-sm",
		lg: "size-11 text-base",
		xl: "size-1 text-lg",
	};

	const avatarSize = sizeClasses[size];
	const borderSize = "border-1";

	return (
		<div className={cn("flex items-center", className)}>
			<div className="flex gap-x-1 items-center">
				{visibleUsers.map((n, index) => (
					<div
						key={index}
						className={cn(
							"rounded-full border bg-background transition-transform",
							borderSize,
							hoveredIndex === index
								? "z-10 scale-110"
								: "hover:z-10 hover:scale-110",
							classNames?.avatar,
						)}
						onMouseEnter={() => setHoveredIndex(index)}
						onMouseLeave={() => setHoveredIndex(null)}
					>
						{n}
					</div>
				))}

				{remainingUsers > 0 && (
					<div
						className={cn(
							"flex items-center justify-center rounded-full border text-muted-foreground",
							avatarSize,
							borderSize,
						)}
					>
						<span>+{remainingUsers}</span>
					</div>
				)}
			</div>
		</div>
	);
}
