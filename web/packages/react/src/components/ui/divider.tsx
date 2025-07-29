"use client";
import { cn } from "@/lib/utils";

// Define types for component props
type VariantOption = "solid" | "dashed" | "dotted";
type ThicknessOption = "thin" | "normal" | "medium" | "thick";
type LengthOption = "full" | "half" | "quarter" | "threeQuarters";
type OrientationOption = "horizontal" | "vertical";
type LabelPositionOption = "start" | "center" | "end";

// Define the props interface
interface DividerProps {
	orientation?: OrientationOption;
	bgColor?: string;
	textColor?: string;
	variant?: VariantOption;
	thickness?: ThicknessOption;
	length?: LengthOption;
	label?: string;
	labelPosition?: LabelPositionOption;
	className?: string;
}

const Divider: React.FC<DividerProps> = ({
	orientation = "horizontal",
	bgColor = "bg-gray-200",
	textColor = "text-gray-600",
	variant = "solid",
	thickness = "normal",
	length = "full",
	label = "",
	labelPosition = "center",
	className = "",
}) => {
	// Define thickness variants
	const thicknessVariants: Record<ThicknessOption, string> = {
		thin: orientation === "horizontal" ? "h-px" : "w-px",
		normal: orientation === "horizontal" ? "h-0.5" : "w-0.5",
		medium: orientation === "horizontal" ? "h-1" : "w-1",
		thick: orientation === "horizontal" ? "h-2" : "w-2",
	};

	// Define variant styles
	const variantStyles: Record<VariantOption, string> = {
		solid: "",
		dashed: "border-dashed border-2 bg-transparent",
		dotted: "border-dotted border-2 bg-transparent",
	};

	// Define length variants
	const lengthVariants: Record<LengthOption, string> = {
		full: orientation === "horizontal" ? "w-full" : "h-full",
		half: orientation === "horizontal" ? "w-1/2" : "h-1/2",
		quarter: orientation === "horizontal" ? "w-1/4" : "h-1/4",
		threeQuarters: orientation === "horizontal" ? "w-3/4" : "h-3/4",
	};

	// Define label position variants for horizontal orientation
	const labelPositionVariants: Record<LabelPositionOption, string> = {
		start: "justify-start",
		center: "justify-center",
		end: "justify-end",
	};

	// Get selected styles
	const selectedThickness =
		thicknessVariants[thickness] || thicknessVariants.normal;
	const selectedVariant = variantStyles[variant] || variantStyles.solid;
	const selectedLength = lengthVariants[length] || lengthVariants.full;
	const selectedLabelPosition =
		labelPositionVariants[labelPosition] || labelPositionVariants.center;

	// Convert to border color if using dashed or dotted variant
	const borderColor =
		variant !== "solid" ? bgColor.replace("bg-", "border-") : "";

	// If we have a label and horizontal orientation
	if (label && orientation === "horizontal") {
		return (
			<div
				className={cn("flex items-center", selectedLabelPosition, className)}
			>
				<div className={cn(selectedLength, "flex items-center")}>
					<div
						className={cn(
							"flex-grow",
							selectedVariant,
							borderColor,
							variant === "solid" ? bgColor : "",
							selectedThickness,
						)}
					></div>
					{label && <div className={cn("px-3", textColor)}>{label}</div>}
					<div
						className={cn(
							"flex-grow",
							selectedVariant,
							borderColor,
							variant === "solid" ? bgColor : "",
							selectedThickness,
						)}
					></div>
				</div>
			</div>
		);
	}

	// If we have a label and vertical orientation
	if (label && orientation === "vertical") {
		return (
			<div className={cn("flex flex-col items-center", className)}>
				<div className={cn(selectedLength, "flex flex-col items-center")}>
					<div
						className={cn(
							"flex-grow",
							selectedVariant,
							borderColor,
							variant === "solid" ? bgColor : "",
							selectedThickness,
						)}
					></div>
					<div className={cn("py-3 transform -rotate-90", textColor)}>
						{label}
					</div>
					<div
						className={cn(
							"flex-grow",
							selectedVariant,
							borderColor,
							variant === "solid" ? bgColor : "",
							selectedThickness,
						)}
					></div>
				</div>
			</div>
		);
	}

	// Basic divider with no label
	return (
		<div
			className={cn(
				orientation === "horizontal" ? "w-full" : "h-full inline-block",
				selectedLength,
				selectedVariant,
				borderColor,
				variant === "solid" ? bgColor : "",
				selectedThickness,
				className,
			)}
		/>
	);
};

export { Divider };
