"use client";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
	Command,
	CommandEmpty,
	CommandGroup,
	CommandInput,
	CommandItem,
	CommandList,
} from "@/components/ui/command";
import { inputContainerColorStyles } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import {
	Popover,
	PopoverContent,
	PopoverTrigger,
} from "@/components/ui/popover";
import {
	Select,
	SelectContent,
	SelectItem,
	SelectTrigger,
	SelectValue,
} from "@/components/ui/select";
import { radiusStyles, sizeStyles } from "@/lib/styles";
import { cn } from "@/lib/utils";
import { type VariantProps, cva } from "class-variance-authority";
import { Check, ChevronsUpDown, X } from "lucide-react";
import * as React from "react";

const selectVariants = cva("w-full justify-between", {
	variants: {
		variant: {
			default: "border shadow-sm",
			flat: "shadow-none border-0 bg-muted",
			bordered: "bg-background border-2",
			underlined:
				"bg-transparent border-0 border-input border-b-2 shadow-none rounded-none",
			faded: "border-2 border-input/25 bg-muted",
		},
		color: inputContainerColorStyles,
		// size: {
		//   xs: "h-6 text-xs",
		//   sm: "h-8 text-sm",
		//   default: "h-9 text-sm",
		//   md: "h-9 text-sm",
		//   lg: "h-10 text-base",
		//   xl: "h-11 text-lg",
		// },
		size: sizeStyles,
		radius: radiusStyles,
	},
	defaultVariants: {
		variant: "default",
		size: "default",
		radius: "md",
		color: "default",
	},
	compoundVariants: [
		{
			variant: "underlined",
			className: "rounded-none",
		},
	],
});

const contentVariants = cva("p-0", {
	variants: {
		variant: {
			default: "bg-popover border shadow-md",
			flat: "shadow-none border-0 bg-muted",
			bordered: "bg-background border-2",
			underlined: "bg-background border shadow-md",
			faded: "border-2 border-input/25 bg-muted",
		},
		radius: radiusStyles,
	},
	defaultVariants: {
		variant: "default",
		radius: "md",
	},
});

const commandInputVariants = cva("", {
	variants: {
		size: sizeStyles,
		variant: {
			default: "bg-transparent",
			flat: "bg-transparent",
			bordered: "bg-transparent",
			underlined: "bg-transparent border-b",
			faded: "bg-transparent",
		},
		radius: {
			none: "rounded-none",
			xs: "rounded-xs",
			sm: "rounded-sm",
			md: "rounded-md",
			lg: "rounded-lg",
			xl: "rounded-xl",
			full: "rounded-full",
		},
	},
	defaultVariants: {
		size: "default",
		variant: "default",
		radius: "md",
	},
});

// Define a generic type for options
export type SelectOption<T> = {
	[key: string]: any;
	disabled?: boolean;
} & T;

// Update the EnhancedSelectProps interface to include the label
interface EnhancedSelectProps<T extends string = string>
	extends Omit<
			React.ComponentPropsWithoutRef<typeof Button>,
			"color" | "variant" | "onChange"
		>,
		VariantProps<typeof selectVariants> {
	options: SelectOption<T>[];
	optionValue?: keyof SelectOption<T>;
	optionLabel?: keyof SelectOption<T>;
	optionIcon?: keyof SelectOption<T>;
	optionDescription?: keyof SelectOption<T>;
	placeholder?: string;
	value?: T | T[];
	onChange?: (value: T | T[]) => void;
	disabled?: boolean;
	loading?: boolean;
	error?: string;
	multiple?: boolean;
	searchable?: boolean;
	clearable?: boolean;
	className?: string;
	triggerClassName?: string;
	contentClassName?: string;
	itemClassName?: string;
	position?: "popper" | "item-aligned";
	maxHeight?: number;
	maxSelected?: number;
	renderOption?: (option: SelectOption<T>) => React.ReactNode;
	onBlur?: () => void;
	onFocus?: () => void;
	name?: string;
	hint?: string;
	id?: string;
	startContent?: React.ReactNode;
	renderValue?: (value: T | T[], options: SelectOption<T>[]) => React.ReactNode;
	label?: string;
	labelClassName?: string;
}

export const EnhancedSelect = React.forwardRef<
	HTMLButtonElement,
	EnhancedSelectProps
>(
	(
		{
			options,
			optionValue = "value",
			optionLabel = "label",
			optionIcon = "icon",
			optionDescription = "description",
			placeholder = "Select an option",
			value,
			onChange,
			disabled = false,
			loading = false,
			error,
			hint,
			multiple = false,
			searchable = false,
			clearable = false,
			className,
			triggerClassName,
			contentClassName,
			itemClassName,
			size = "default",
			position = "item-aligned",
			variant = "default",
			radius = "md",
			maxHeight = 300,
			maxSelected,
			renderOption,
			onBlur,
			onFocus,
			name,
			id,
			startContent,
			renderValue,
			label,
			labelClassName,
			...props
		},
		ref,
	) => {
		const [open, setOpen] = React.useState(false);
		const [search, setSearch] = React.useState("");
		const [selectedValues, setSelectedValues] = React.useState<string[]>(
			value ? (Array.isArray(value) ? value : [value]) : [],
		);

		React.useEffect(() => {
			if (multiple) {
				setSelectedValues(Array.isArray(value) ? value : value ? [value] : []);
			} else {
				setSelectedValues(value ? [value as string] : []);
			}
		}, [value, multiple]);

		const handleSelect = React.useCallback(
			(optionValue: string) => {
				let newValues: string[];

				if (multiple) {
					if (selectedValues.includes(optionValue)) {
						newValues = selectedValues.filter((v) => v !== optionValue);
					} else {
						if (maxSelected && selectedValues.length >= maxSelected) {
							return;
						}
						newValues = [...selectedValues, optionValue];
					}
				} else {
					newValues = [optionValue];
					setOpen(false);
				}

				setSelectedValues(newValues);

				if (onChange) {
					onChange(multiple ? newValues : newValues[0] || "");
				}
			},
			[multiple, onChange, selectedValues, maxSelected],
		);

		const handleClear = React.useCallback(
			(e?: React.MouseEvent) => {
				e?.stopPropagation();
				setSelectedValues([]);
				if (onChange) {
					onChange(multiple ? [] : "");
				}
			},
			[multiple, onChange],
		);

		const filteredOptions = React.useMemo(() => {
			if (!searchable || !search) return options;

			return options.filter(
				(option) =>
					String(option[optionLabel])
						.toLowerCase()
						.includes(search.toLowerCase()) ||
					String(option[optionValue])
						.toLowerCase()
						.includes(search.toLowerCase()),
			);
		}, [options, search, searchable, optionLabel, optionValue]);

		const selectedLabels = React.useMemo(() => {
			return selectedValues
				.map(
					(v) =>
						options.find((option) => option[optionValue] === v)?.[optionLabel],
				)
				.filter(Boolean) as string[];
		}, [selectedValues, options, optionValue, optionLabel]);

		const singleSelect = (
			<Select
				value={selectedValues[0]}
				onValueChange={(value) => {
					if (onChange) onChange(value);
				}}
				disabled={disabled}
				name={name}
			>
				<SelectTrigger
					id={id}
					className={cn(
						selectVariants({ radius }),
						error && "border-destructive",
						triggerClassName,
					)}
				>
					<SelectValue
						placeholder={
							<span className="placeholder:text-left placeholder:truncate placeholder:text-ellipsis">
								placeholder
							</span>
						}
					/>
				</SelectTrigger>
				<SelectContent
					className={cn(contentVariants({ radius }), contentClassName)}
					style={{
						width: "var(--radix-select-trigger-width)",
						maxHeight: "var(--radix-select-content-available-height)",
					}}
				>
					{options.map((option) => (
						<SelectItem
							key={option[optionValue]}
							value={option[optionValue]}
							disabled={option.disabled}
							className={itemClassName}
						>
							{renderOption ? (
								renderOption(option)
							) : (
								<div className="flex flex-col">
									<div className="flex items-center gap-2">
										{option[optionIcon]}
										<span>{option[optionLabel]}</span>
									</div>
									{option[optionDescription] && (
										<span className="text-xs text-muted-foreground">
											{option[optionDescription]}
										</span>
									)}
								</div>
							)}
						</SelectItem>
					))}
				</SelectContent>
			</Select>
		);

		// If using standard select for non-searchable, non-multiple select
		if (!searchable && !multiple) {
			if (label) {
				return (
					<div className="space-y-2">
						<Label
							htmlFor={id}
							className={cn("text-pyro-text-primary", labelClassName)}
						>
							{label}
						</Label>
						{singleSelect}
					</div>
				);
			}

			return singleSelect;
		}

		// Wrap the select component with a label if provided
		const selectComponent = (
			<div className={cn("relative", className)}>
				<Popover open={open} onOpenChange={setOpen}>
					<PopoverTrigger asChild>
						<div
							className={cn(
								"flex flex-1 items-center overflow-hidden",
								selectVariants({ variant, size, radius }),
								error && "border-destructive",
								triggerClassName,
							)}
						>
							{startContent}
							<Button
								ref={ref}
								{...props}
								id={id}
								variant={"light"}
								size={size}
								disabled={disabled}
								role="combobox"
								fullWidth
								aria-expanded={open}
								aria-haspopup="listbox"
								className={cn({
									"!rounded-l-none pl-1": !!startContent,
								})}
								onClick={() => {
									onFocus?.();
									setOpen(!open);
								}}
								onBlur={onBlur}
								onFocus={onFocus}
							>
								<div className="flex flex-1 items-center gap-1 overflow-hidden">
									{renderValue ? (
										renderValue(selectedValues, options)
									) : multiple ? (
										selectedValues.length > 0 ? (
											<div className="flex flex-wrap gap-1">
												{selectedValues.length <= 2 ? (
													selectedLabels.map((label, i) => (
														<Badge
															key={i}
															variant="secondary"
															className={cn(
																"max-w-[150px] truncate",
																radius === "full" && "rounded-full",
																radius === "xl" && "rounded-xl",
																radius === "lg" && "rounded-lg",
																radius === "md" && "rounded-md",
																radius === "sm" && "rounded-sm",
																radius === "xs" && "rounded-xs",
																radius === "none" && "rounded-none",
															)}
														>
															{label}
															{clearable && (
																<Button
																	variant="ghost"
																	size="sm"
																	className="ml-1 h-4 w-4 p-0"
																	onClick={(e) => {
																		e.stopPropagation();
																		handleSelect(selectedValues[i]);
																	}}
																>
																	<X className="h-3 w-3" />
																	<span className="sr-only">Remove</span>
																</Button>
															)}
														</Badge>
													))
												) : (
													<Badge
														variant="secondary"
														className={cn(
															radius === "full" && "rounded-full",
															radius === "xl" && "rounded-xl",
															radius === "lg" && "rounded-lg",
															radius === "md" && "rounded-md",
															radius === "sm" && "rounded-sm",
															radius === "xs" && "rounded-xs",
															radius === "none" && "rounded-none",
														)}
													>
														{selectedValues.length} selected
													</Badge>
												)}
											</div>
										) : (
											<span className="text-muted-foreground">
												{placeholder}
											</span>
										)
									) : selectedValues.length > 0 ? (
										<span className="truncate">
											{
												options.find(
													(option) => option[optionValue] === selectedValues[0],
												)?.[optionLabel]
											}
										</span>
									) : (
										<span className="text-muted-foreground">{placeholder}</span>
									)}
								</div>
								<div className="flex items-center gap-1">
									{clearable && selectedValues.length > 0 && (
										<Button
											variant="ghost"
											size="sm"
											className={cn(
												"h-4 w-4 p-0",
												radius === "full" && "rounded-full",
												radius === "xl" && "rounded-xl",
												radius === "lg" && "rounded-lg",
												radius === "md" && "rounded-md",
												radius === "sm" && "rounded-sm",
												radius === "xs" && "rounded-xs",
												radius === "none" && "rounded-none",
											)}
											onClick={handleClear}
										>
											<X className="h-3 w-3" />
											<span className="sr-only">Clear</span>
										</Button>
									)}
									<ChevronsUpDown className="h-4 w-4 opacity-50" />
								</div>
							</Button>
						</div>
					</PopoverTrigger>
					<PopoverContent
						className={cn(
							contentVariants({ variant, radius }),
							contentClassName,
						)}
						style={{ width: "var(--radix-popover-trigger-width)" }}
					>
						<Command shouldFilter={false}>
							{searchable && (
								<CommandInput
									placeholder="Search..."
									value={search}
									onValueChange={setSearch}
									className={cn(
										commandInputVariants({ size, variant, radius }),
									)}
								/>
							)}
							<CommandList
								className={cn("max-h-[300px]")}
								style={{
									maxHeight: maxHeight ? `${maxHeight}px` : "300px",
								}}
							>
								<CommandEmpty>No results found.</CommandEmpty>
								<CommandGroup>
									{filteredOptions.map((option) => {
										const isSelected = selectedValues.includes(
											option[optionValue],
										);
										return (
											<CommandItem
												key={option[optionValue]}
												value={option[optionValue]}
												disabled={option.disabled}
												onSelect={() => handleSelect(option[optionValue])}
												className={cn(
													"flex items-center gap-2",
													isSelected && "bg-accent",
													option.disabled && "opacity-50 cursor-not-allowed",
													itemClassName,
												)}
											>
												{multiple && (
													<div
														className={cn(
															"flex h-4 w-4 items-center justify-center border border-primary",
															radius === "full" && "rounded-full",
															radius === "xl" && "rounded-xl",
															radius === "lg" && "rounded-lg",
															radius === "md" && "rounded-md",
															radius === "sm" && "rounded-sm",
															radius === "xs" && "rounded-xs",
															radius === "none" && "rounded-none",
															isSelected
																? "bg-primary text-primary-foreground"
																: "opacity-50",
														)}
													>
														{isSelected && <Check className="h-3 w-3" />}
													</div>
												)}
												{renderOption ? (
													renderOption(option)
												) : (
													<div className="flex flex-col">
														<div className="flex items-center gap-2">
															{option[optionIcon]}
															<span>{option[optionLabel]}</span>
														</div>
														{option[optionDescription] && (
															<span className="text-xs text-muted-foreground">
																{option[optionDescription]}
															</span>
														)}
													</div>
												)}
												{!multiple && isSelected && (
													<Check className="ml-auto h-4 w-4" />
												)}
											</CommandItem>
										);
									})}
								</CommandGroup>
							</CommandList>
						</Command>
					</PopoverContent>
				</Popover>
				{error && <p className="p-1 text-sm text-destructive">{error}</p>}
				{hint && !error && <p className="p-1 text-xs">{hint}</p>}
				{name && (
					<input
						type="hidden"
						name={name}
						value={
							multiple ? selectedValues.join(",") : selectedValues[0] || ""
						}
					/>
				)}
			</div>
		);

		// If a label is provided, wrap the select component with a label
		if (label) {
			return (
				<div className="space-y-2">
					<Label
						htmlFor={id}
						className={cn("text-pyro-text-primary", labelClassName)}
					>
						{label}
					</Label>
					{selectComponent}
				</div>
			);
		}

		return selectComponent;
	},
);

EnhancedSelect.displayName = "EnhancedSelect";
