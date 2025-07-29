import * as React from "react";

import { cn } from "@/lib/utils";
import { ArrowUpRight } from "lucide-react";

const Tile = React.forwardRef<
	HTMLDivElement,
	React.HTMLAttributes<HTMLDivElement>
>(({ className, ...props }, ref) => (
	<div
		ref={ref}
		className={cn(
			"glass-1 hover:glass-2 group relative flex flex-col gap-6 overflow-hidden rounded-xl p-6 text-card-foreground shadow-xl transition-all",
			className,
		)}
		{...props}
	/>
));
Tile.displayName = "Tile";

const TileTitle = React.forwardRef<
	HTMLParagraphElement,
	React.HTMLAttributes<HTMLHeadingElement>
>(({ className, ...props }, ref) => (
	<h3
		ref={ref}
		className={cn(
			"text-2xl font-semibold leading-none tracking-tight",
			className,
		)}
		{...props}
	/>
));
TileTitle.displayName = "TileTitle";

const TileDescription = React.forwardRef<
	HTMLParagraphElement,
	React.HTMLAttributes<HTMLParagraphElement>
>(({ className, ...props }, ref) => (
	<div
		ref={ref}
		className={cn(
			"text-md flex flex-col gap-2 text-balance text-muted-foreground",
			className,
		)}
		{...props}
	/>
));
TileDescription.displayName = "TileDescription";

const TileContent = React.forwardRef<
	HTMLDivElement,
	React.HTMLAttributes<HTMLDivElement>
>(({ className, ...props }, ref) => (
	<div ref={ref} className={cn("flex flex-col gap-4", className)} {...props} />
));
TileContent.displayName = "TileContent";

const TileVisual = React.forwardRef<
	HTMLDivElement,
	React.HTMLAttributes<HTMLDivElement>
>(({ className, ...props }, ref) => (
	<div
		ref={ref}
		className={cn("flex grow items-end justify-center", className)}
		{...props}
	/>
));
TileVisual.displayName = "TileVisual";

const TileLink = React.forwardRef<
	HTMLAnchorElement,
	React.HTMLAttributes<HTMLAnchorElement>
>(({ className, ...props }, ref) => (
	<a
		ref={ref}
		className={cn(
			"absolute right-4 top-4 block rounded-full bg-accent/5 p-4 opacity-0 transition-opacity group-hover:opacity-100",
			className,
		)}
		{...props}
	>
		<ArrowUpRight className="h-4 w-4" />
	</a>
));
TileLink.displayName = "TileLink";

export { Tile, TileVisual, TileTitle, TileDescription, TileContent, TileLink };
