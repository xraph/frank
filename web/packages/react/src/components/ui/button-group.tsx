import { cn } from "@/lib/utils";
import * as React from "react";
import { Button, type ButtonProps } from "./button"; // Adjust the import path as necessary

export interface ButtonGroupProps extends React.HTMLAttributes<HTMLDivElement> {
	orientation?: "horizontal" | "vertical";
	size?: ButtonProps["size"];
	variant?: ButtonProps["variant"];
	radius?: ButtonProps["radius"];
	isIconOnly?: ButtonProps["isIconOnly"];
	fullWidth?: boolean;
	children: React.ReactNode;
}

const ButtonGroup = ({
	className,
	orientation = "horizontal",
	size = "md",
	variant = "default",
	radius = "md",
	fullWidth = false,
	isIconOnly = false,
	children,
	...props
}: ButtonGroupProps) => {
	return (
		<div
			className={cn(
				"group inline-flex",
				orientation === "horizontal" ? "flex-row" : "flex-col",
				fullWidth && "w-full",
				className,
			)}
			{...props}
		>
			{React.Children.map(children, (child, index) => {
				// Helper function to get modified className
				const getModifiedClassName = (childClassName: string | undefined) =>
					cn(
						orientation === "horizontal" && index === 0 && "rounded-l-md", // Leftmost button
						orientation === "horizontal" &&
							index === React.Children.count(children) - 1 &&
							"rounded-r-md", // Rightmost button
						orientation === "vertical" && index === 0 && "rounded-t-md", // Topmost button
						orientation === "vertical" &&
							index === React.Children.count(children) - 1 &&
							"rounded-b-md", // Bottommost button
						orientation === "horizontal" && index > 0 && "-ml-px", // Remove left border except for the first button
						orientation === "vertical" && index > 0 && "-mt-px", // Remove top border except for the first button
						childClassName, // Retain any additional classes from the child
					);

				// Check if the child is a valid React element
				if (React.isValidElement(child)) {
					// If the child is a Button
					if (
						child.type === Button ||
						child.type.toString().includes("Button")
					) {
						return React.cloneElement(child, {
							size,
							variant,
							isIconOnly,
							radius: "none", // Remove default radius for middle buttons
							fullWidth: fullWidth && orientation === "vertical", // Make buttons full width if vertical
							className: getModifiedClassName(child.props?.className),
						});
					}

					// Check if the child uses asChild pattern (common in RadixUI trigger components)
					// and its child is a Button.
					if (
						child.props.asChild &&
						React.isValidElement(child.props.children) &&
						(child.props.children.type === Button ||
							child.props.children.type.toString().includes("Button"))
					) {
						const clonedInner = React.cloneElement(child.props.children, {
							size,
							variant,
							radius: "none",
							fullWidth: fullWidth && orientation === "vertical",
							isIconOnly,
							className: getModifiedClassName(
								child.props.children.props?.className,
							),
						});

						return React.cloneElement(child, {
							children: clonedInner,
						});
					}
				}

				// If the child isn't a button or a wrapped button, return it unmodified.
				return child;
			})}
		</div>
	);
};

export { ButtonGroup };
