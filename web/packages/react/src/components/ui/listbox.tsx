"use client";
import { cn } from "@/lib/utils";
import type { ReactNode } from "react";

export interface ListItemProps {
	/** Main content of the list item */
	children: ReactNode;
	/** Content to display at the start/left of the item (icons, avatars, etc.) */
	startContent?: ReactNode;
	/** Content to display at the end/right of the item (buttons, badges, etc.) */
	endContent?: ReactNode;
	/** Description text or element to show below the main content */
	description?: ReactNode;
	/** Whether the item is disabled */
	disabled?: boolean;
	/** Whether the item is currently selected */
	selected?: boolean;
	/** Click handler for the list item */
	onClick?: () => void;
	/** Additional CSS classes */
	className?: string;
	/** Additional CSS classes for the description */
	descriptionClassName?: string;
}

export type ListVariant = "flat" | "bordered" | "separated";
export type SelectionMode = "none" | "single" | "multiple";

export interface ListProps {
	/** List items to render */
	children: ReactNode;
	/** Visual style variant of the list */
	variant?: ListVariant;
	/** Selection behavior of the list */
	selectionMode?: SelectionMode;
	/** Additional CSS classes */
	className?: string;
	[key: string]: any; // For additional props that might be passed
}

export interface ListSectionProps {
	/** Title of the section */
	title?: string;
	/** List and/or content to render within the section */
	children: ReactNode;
	/** Additional CSS classes */
	className?: string;
	/** Additional CSS classes for the title */
	titleClassName?: string;
}

// Individual List Item component
const ListItem: React.FC<ListItemProps> = ({
	children,
	startContent,
	endContent,
	description,
	disabled = false,
	selected = false,
	onClick,
	className = "",
	descriptionClassName = "",
}) => {
	return (
		<li
			className={cn(
				"flex items-center px-4 py-3 gap-3",
				disabled
					? "opacity-50 cursor-not-allowed"
					: "cursor-pointer hover:bg-gray-100",
				selected && "bg-blue-50",
				className,
			)}
			onClick={disabled ? undefined : onClick}
			role={onClick ? "button" : undefined}
			aria-disabled={disabled}
			tabIndex={disabled ? -1 : 0}
		>
			{startContent && <div className="flex-shrink-0">{startContent}</div>}
			<div className="flex-grow flex flex-col">
				<div>{children}</div>
				{description && (
					<div
						className={cn("mt-1 text-xs text-gray-500", descriptionClassName)}
					>
						{description}
					</div>
				)}
			</div>
			{endContent && <div className="flex-shrink-0 ml-auto">{endContent}</div>}
		</li>
	);
};

// Main List component
const List: React.FC<ListProps> = ({
	children,
	variant = "flat",
	selectionMode = "none",
	className = "",
	...props
}) => {
	const variantStyles = {
		flat: "",
		bordered: "border border-gray-200 rounded-lg",
		separated: "divide-y divide-gray-200 border border-gray-200 rounded-lg",
	};

	return (
		<ul
			className={cn("list-none p-0 w-full", variantStyles[variant], className)}
			role={selectionMode !== "none" ? "listbox" : "list"}
			aria-multiselectable={selectionMode === "multiple"}
			{...props}
		>
			{children}
		</ul>
	);
};

// List Section component as a wrapper div
const ListSection: React.FC<ListSectionProps> = ({
	title,
	children,
	className = "",
	titleClassName = "",
}) => {
	return (
		<div className={cn("w-full", className)}>
			{title && (
				<h3
					className={cn(
						"px-4 py-2 text-sm font-medium text-gray-500",
						titleClassName,
					)}
				>
					{title}
				</h3>
			)}
			{children}
		</div>
	);
};

export { List, ListItem, ListSection };
