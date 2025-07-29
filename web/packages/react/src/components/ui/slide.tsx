import { cn } from "@/lib/utils";
import { ArrowUpRight, Plus } from "lucide-react";
import * as React from "react";

const Slide = React.forwardRef<
	HTMLDivElement,
	React.HTMLAttributes<HTMLDivElement> & { isExpanded?: boolean }
>(({ className, isExpanded, ...props }, ref) => (
	<div
		ref={ref}
		className={cn(
			"glass-3 group relative flex flex-col overflow-hidden rounded-xl text-card-foreground shadow-xl transition-all",
			className,
		)}
		{...props}
	/>
));
Slide.displayName = "Slide";

const SlideTitle = React.forwardRef<
	HTMLParagraphElement,
	React.HTMLAttributes<HTMLHeadingElement>
>(({ className, ...props }, ref) => (
	<h3
		ref={ref}
		className={cn("text-lg font-semibold tracking-tight", className)}
		{...props}
	/>
));
SlideTitle.displayName = "SlideTitle";

const SlideDescription = React.forwardRef<
	HTMLParagraphElement,
	React.HTMLAttributes<HTMLParagraphElement>
>(({ className, ...props }, ref) => (
	<p
		ref={ref}
		className={cn("text-balance text-sm text-muted-foreground", className)}
		{...props}
	/>
));
SlideDescription.displayName = "SlideDescription";

const SlideContent = React.forwardRef<
	HTMLDivElement,
	React.HTMLAttributes<HTMLDivElement> & { isExpanded?: boolean }
>(({ className, isExpanded, ...props }, ref) => (
	<div
		ref={ref}
		className={cn(
			"flex flex-col gap-2 p-6 transition-opacity duration-300",
			isExpanded ? "opacity-0" : "opacity-100",
			className,
		)}
		{...props}
	/>
));
SlideContent.displayName = "SlideContent";

const SlideVisual = React.forwardRef<
	HTMLDivElement,
	React.HTMLAttributes<HTMLDivElement> & { isExpanded?: boolean }
>(({ className, isExpanded, ...props }, ref) => (
	<div
		ref={ref}
		className={cn(
			"flex items-center transition-opacity duration-300",
			isExpanded ? "opacity-0" : "opacity-100",
			className,
		)}
		{...props}
	/>
));
SlideVisual.displayName = "SlideVisual";

const SlideExpandedContent = React.forwardRef<
	HTMLParagraphElement,
	React.HTMLAttributes<HTMLParagraphElement> & { isExpanded?: boolean }
>(({ className, isExpanded, ...props }, ref) => (
	<p
		ref={ref}
		className={cn(
			"absolute inset-6 text-balance text-lg text-muted-foreground transition-opacity duration-300",
			isExpanded ? "opacity-100" : "opacity-0",
			className,
		)}
		{...props}
	/>
));
SlideExpandedContent.displayName = "SlideExpandedContent";

const SlideButton = React.forwardRef<
	HTMLButtonElement,
	React.ButtonHTMLAttributes<HTMLButtonElement> & {
		isExpanded?: boolean;
		icon?: "link" | "more";
	}
>(({ className, isExpanded, icon = "more", ...props }, ref) => (
	<button
		ref={ref}
		{...props}
		className={cn(
			"pointer-events-none absolute bottom-6 right-6 z-10 block rounded-full bg-accent/5 p-4",
			className,
		)}
	>
		{icon === "link" ? (
			<ArrowUpRight className="h-4 w-4" />
		) : (
			<Plus
				className={cn(
					"h-4 w-4 transition-all",
					isExpanded ? "rotate-45" : "group-hover:rotate-90",
				)}
			/>
		)}
	</button>
));
SlideButton.displayName = "SlideButton";

export {
	Slide,
	SlideTitle,
	SlideDescription,
	SlideContent,
	SlideVisual,
	SlideButton,
	SlideExpandedContent,
};
