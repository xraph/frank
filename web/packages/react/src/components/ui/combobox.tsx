"use client";

import { radiusStyles, sizeStyles, variantStyles } from "@/lib/styles";
import { cn } from "@/lib/utils";
import { type VariantProps, cva } from "class-variance-authority";
import { Check, ChevronsUpDown } from "lucide-react";
import * as React from "react";
import { Button } from "./button";
import {
	Command,
	CommandEmpty,
	CommandGroup,
	CommandInput,
	CommandItem,
	CommandList,
} from "./command";
import { Popover, PopoverContent, PopoverTrigger } from "./popover";

// Define ComboBox variants using cva
const comboBoxVariants = cva("w-full justify-between", {
	variants: {
		size: sizeStyles,
		radius: radiusStyles,
		variant: variantStyles,
		fullWidth: {
			true: "w-full justify-center",
			false: "",
		},
	},
	defaultVariants: {
		size: "default",
		variant: "default",
		size: "md",
		fullWidth: false,
	},
});

export interface ComboBoxItemProps<T> {
	item: T;
	isSelected: boolean;
	onSelect: () => void;
}

interface ComboBoxProps<T> extends VariantProps<typeof comboBoxVariants> {
	items: T[];
	value?: T;
	onValueChange?: (value: T | undefined) => void;
	placeholder?: string;
	searchPlaceholder?: string;
	emptyMessage?: string;
	className?: string;
	disabled?: boolean;
	/** Function to get the display value for the selected item */
	getDisplayValue: (item: T) => string;
	/** Function to get the search value for the item */
	getSearchValue: (item: T) => string;
	/** Function to get a unique key for the item */
	getItemKey: (item: T) => string | number;
	/** Custom render function for each item */
	children: (props: ComboBoxItemProps<T>) => React.ReactNode;
}

export function ComboBox<T>({
	items,
	value,
	onValueChange,
	placeholder = "Select an option...",
	searchPlaceholder = "Search...",
	emptyMessage = "No items found.",
	size,
	variant,
	className,
	disabled = false,
	getDisplayValue,
	getSearchValue,
	getItemKey,
	children,
}: ComboBoxProps<T>) {
	const [open, setOpen] = React.useState(false);
	const [selectedItem, setSelectedItem] = React.useState<T | undefined>(value);
	const [searchQuery, setSearchQuery] = React.useState("");

	React.useEffect(() => {
		if (value !== undefined) {
			setSelectedItem(value);
		}
	}, [value]);

	const handleSelect = React.useCallback(
		(item: T) => {
			const newValue = selectedItem === item ? undefined : item;
			setSelectedItem(newValue);
			onValueChange?.(newValue);
			setOpen(false);
		},
		[selectedItem, onValueChange],
	);

	const filteredItems = React.useMemo(() => {
		if (!searchQuery) return items;
		return items.filter((item) =>
			getSearchValue(item).toLowerCase().includes(searchQuery.toLowerCase()),
		);
	}, [items, searchQuery, getSearchValue]);

	return (
		<Popover open={open} onOpenChange={setOpen}>
			<PopoverTrigger asChild>
				<Button
					variant="outline"
					role="combobox"
					aria-expanded={open}
					disabled={disabled}
					className={cn(comboBoxVariants({ size, variant }), className)}
				>
					{selectedItem ? getDisplayValue(selectedItem) : placeholder}
					<ChevronsUpDown className="ml-2 h-4 w-4 shrink-0 opacity-50" />
				</Button>
			</PopoverTrigger>
			<PopoverContent className={cn("p-0", comboBoxVariants({ size }))}>
				<Command>
					<CommandInput
						placeholder={searchPlaceholder}
						className="h-9"
						value={searchQuery}
						onValueChange={setSearchQuery}
					/>
					<CommandList>
						<CommandEmpty>{emptyMessage}</CommandEmpty>
						<CommandGroup>
							{filteredItems.map((item) => (
								<CommandItem
									key={getItemKey(item)}
									value={getSearchValue(item)}
									onSelect={() => handleSelect(item)}
								>
									{children({
										item,
										isSelected: selectedItem === item,
										onSelect: () => handleSelect(item),
									})}
								</CommandItem>
							))}
						</CommandGroup>
					</CommandList>
				</Command>
			</PopoverContent>
		</Popover>
	);
}
