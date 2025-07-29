import { useDebounce } from "@/hooks/use-debounce";
import { Check, ChevronsUpDown, Loader2 } from "lucide-react";
import { useCallback, useEffect, useState } from "react";

import { Button } from "@/components/ui/button";
import {
	Command,
	CommandEmpty,
	CommandGroup,
	CommandInput,
	CommandItem,
	CommandList,
} from "@/components/ui/command";
import {
	Popover,
	PopoverContent,
	PopoverTrigger,
} from "@/components/ui/popover";
import { cn } from "@/lib/utils";

export interface Option {
	value: string;
	label: string;
	disabled?: boolean;
	description?: string;
	icon?: React.ReactNode;
}

export interface AsyncSelectProps<T> {
	/** Async function to fetch options */
	fetcher: (query?: string) => Promise<T[]>;
	/** Preload all data ahead of time */
	preload?: boolean;
	/** Function to filter options */
	filterFn?: (option: T, query: string) => boolean;
	/** Function to render each option */
	renderOption: (option: T) => React.ReactNode;
	/** Function to get the value from an option */
	getOptionValue: (option: T) => string;
	/** Function to get the display value for the selected option */
	getDisplayValue: (option: T) => React.ReactNode;
	/** Custom not found message */
	notFound?: React.ReactNode;
	/** Custom loading skeleton */
	loadingSkeleton?: React.ReactNode;
	/** Currently selected value */
	value: string;
	/** Callback when selection changes */
	onChange: (value: string) => void;
	/** Label for the select field */
	label: string;
	/** Placeholder text when no selection */
	placeholder?: string;
	/** Disable the entire select */
	disabled?: boolean;
	/** Custom width for the popover */
	width?: string | number;
	/** Custom class names */
	className?: string;
	/** Custom trigger button class names */
	triggerClassName?: string;
	/** Custom no results message */
	noResultsMessage?: string;
	/** Allow clearing the selection */
	clearable?: boolean;
}

export function AsyncSelect<T>({
	fetcher,
	preload,
	filterFn,
	renderOption,
	getOptionValue,
	getDisplayValue,
	notFound,
	loadingSkeleton,
	label,
	placeholder = "Select...",
	value,
	onChange,
	disabled = false,
	width = "200px",
	className,
	triggerClassName,
	noResultsMessage,
	clearable = true,
}: AsyncSelectProps<T>) {
	const [mounted, setMounted] = useState(false);
	const [open, setOpen] = useState(false);
	const [options, setOptions] = useState<T[]>([]);
	const [loading, setLoading] = useState(false);
	const [error, setError] = useState<string | null>(null);
	const [selectedValue, setSelectedValue] = useState(value);
	const [selectedOption, setSelectedOption] = useState<T | null>(null);
	const [searchTerm, setSearchTerm] = useState("");
	const debouncedSearchTerm = useDebounce(searchTerm, preload ? 0 : 300);
	const [originalOptions, setOriginalOptions] = useState<T[]>([]);

	useEffect(() => {
		setMounted(true);
		setSelectedValue(value);
	}, [value]);

	// Initialize selectedOption when options are loaded and value exists
	useEffect(() => {
		if (value && options.length > 0) {
			const option = options.find((opt) => getOptionValue(opt) === value);
			if (option) {
				setSelectedOption(option);
			}
		}
	}, [value, options, getOptionValue]);

	// Effect for initial fetch
	useEffect(() => {
		const initializeOptions = async () => {
			try {
				setLoading(true);
				setError(null);
				// If we have a value, use it for the initial search
				const data = await fetcher(value);
				setOriginalOptions(data);
				setOptions(data);
			} catch (err) {
				setError(
					err instanceof Error ? err.message : "Failed to fetch options",
				);
			} finally {
				setLoading(false);
			}
		};

		if (!mounted) {
			initializeOptions();
		}
	}, [mounted, fetcher, value]);

	// biome-ignore lint/correctness/useExhaustiveDependencies: ignore
	useEffect(() => {
		const fetchOptions = async () => {
			try {
				setLoading(true);
				setError(null);
				const data = await fetcher(debouncedSearchTerm);
				setOriginalOptions(data);
				setOptions(data);
			} catch (err) {
				setError(
					err instanceof Error ? err.message : "Failed to fetch options",
				);
			} finally {
				setLoading(false);
			}
		};

		if (!mounted) {
			fetchOptions();
		} else if (!preload) {
			fetchOptions();
		} else if (preload) {
			if (debouncedSearchTerm) {
				setOptions(
					originalOptions.filter((option) =>
						filterFn ? filterFn(option, debouncedSearchTerm) : true,
					),
				);
			} else {
				setOptions(originalOptions);
			}
		}
	}, [fetcher, debouncedSearchTerm, mounted, preload, filterFn]);

	const handleSelect = useCallback(
		(currentValue: string) => {
			const newValue =
				clearable && currentValue === selectedValue ? "" : currentValue;
			setSelectedValue(newValue);
			setSelectedOption(
				options.find((option) => getOptionValue(option) === newValue) || null,
			);
			onChange(newValue);
			setOpen(false);
		},
		[selectedValue, onChange, clearable, options, getOptionValue],
	);

	return (
		<Popover open={open} onOpenChange={setOpen}>
			<PopoverTrigger asChild>
				<Button
					variant="outline"
					// biome-ignore lint/a11y/useSemanticElements: ignore
					role="combobox"
					aria-expanded={open}
					className={cn(
						"justify-between",
						disabled && "cursor-not-allowed opacity-50",
						triggerClassName,
					)}
					style={{ width: width }}
					isDisabled={disabled}
				>
					{selectedOption ? getDisplayValue(selectedOption) : placeholder}
					<ChevronsUpDown className="opacity-50" size={10} />
				</Button>
			</PopoverTrigger>
			<PopoverContent style={{ width: width }} className={cn("p-0", className)}>
				<Command shouldFilter={false}>
					<div className="relative w-full border-b">
						<CommandInput
							placeholder={`Search ${label.toLowerCase()}...`}
							value={searchTerm}
							onValueChange={(value) => {
								setSearchTerm(value);
							}}
						/>
						{loading && options.length > 0 && (
							<div className="-translate-y-1/2 absolute top-1/2 right-2 flex transform items-center">
								<Loader2 className="h-4 w-4 animate-spin" />
							</div>
						)}
					</div>
					<CommandList>
						{error && (
							<div className="p-4 text-center text-destructive">{error}</div>
						)}
						{loading &&
							options.length === 0 &&
							(loadingSkeleton || <DefaultLoadingSkeleton />)}
						{!loading &&
							!error &&
							options.length === 0 &&
							(notFound || (
								<CommandEmpty>
									{noResultsMessage ?? `No ${label.toLowerCase()} found.`}
								</CommandEmpty>
							))}
						<CommandGroup>
							{options.map((option) => (
								<CommandItem
									key={getOptionValue(option)}
									value={getOptionValue(option)}
									onSelect={handleSelect}
								>
									{renderOption(option)}
									<Check
										className={cn(
											"ml-auto h-3 w-3",
											selectedValue === getOptionValue(option)
												? "opacity-100"
												: "opacity-0",
										)}
									/>
								</CommandItem>
							))}
						</CommandGroup>
					</CommandList>
				</Command>
			</PopoverContent>
		</Popover>
	);
}

function DefaultLoadingSkeleton() {
	return (
		<CommandGroup>
			{[1, 2, 3].map((i) => (
				<CommandItem key={i} disabled>
					<div className="flex w-full items-center gap-2">
						<div className="h-6 w-6 animate-pulse rounded-full bg-muted" />
						<div className="flex flex-1 flex-col gap-1">
							<div className="h-4 w-24 animate-pulse rounded bg-muted" />
							<div className="h-3 w-16 animate-pulse rounded bg-muted" />
						</div>
					</div>
				</CommandItem>
			))}
		</CommandGroup>
	);
}
