import { Label } from "@/components/ui/label";
import { cn } from "@/lib/utils";
import type { VariantProps } from "class-variance-authority";
import type React from "react";
import { useEffect, useMemo, useRef, useState } from "react";
import { inputContainerVariants, inputVariants } from "./input";

export interface MentionItem {
	id: string | number;
	display: string;
	type?: string; // Added type field to differentiate between mentions and tags
	[key: string]: any; // Allow additional properties
}

export interface MentionTrigger {
	char: string;
	type: string;
	displayFormat?: (mention: MentionItem) => string;
}

export interface MentionMeta {
	mentionId: string | number;
	trigger: string;
	triggerType: string;
	startPosition: number;
	endPosition: number;
	display: string;
	originalMention: MentionItem;
}

export interface AutoSuggestInputProps
	extends Omit<
			React.ComponentProps<"input">,
			"size" | "color" | "required" | "disabled"
		>,
		VariantProps<typeof inputContainerVariants> {
	suggestions?: string[];
	mentions?: MentionItem[];
	mentionTriggers?: MentionTrigger[]; // Changed to array of triggers with their types
	onMentionSelect?: (
		mention: MentionItem,
		inputWithMention: string,
		triggerType: string,
	) => void;
	onMentionRemove?: (mention: MentionMeta) => void;
	onSuggestionSelect?: (suggestion: string) => void;
	getSuggestions?: (value: string) => string[] | Promise<string[]>;
	getMentions?: (
		search: string,
		triggerType: string,
	) => MentionItem[] | Promise<MentionItem[]>;
	isDisabled?: boolean;
	isRequired?: boolean;
	isReadOnly?: boolean;
	isError?: boolean;
	errorMessage?: string;
	hint?: string;
	startContent?: React.ReactNode;
	endContent?: React.ReactNode;
	inputSize?: number;
	label?: string | React.ReactNode;
	labelPlacement?: "top" | "left" | "right" | "bottom";
	fullWidth?: boolean;
	maxMentionSuggestions?: number;
	renderMention?: (
		mention: MentionItem,
		isSelected: boolean,
		triggerType: string,
	) => React.ReactNode;
	renderMentionInInput?: (mention: MentionMeta) => React.ReactNode;
	mentionListClassName?: string;
	mentionItemClassName?: string;
	mentionSelectedItemClassName?: string;
	formatMentionText?: (mention: MentionItem, triggerType: string) => string;
	onMentionClick?: (mention: MentionMeta) => void;
}

// Define label positions: top, left, right, bottom
const labelPositionStyles = {
	top: "flex-col items-start",
	left: "flex-row-reverse items-center",
	right: "flex-row items-center",
	bottom: "flex-col-reverse items-start",
};

export function AutoSuggestInput({
	className,
	inputSize,
	size = "md",
	radius,
	animated,
	variant,
	fullWidth = true,
	label,
	labelPlacement = "top",
	type = "text",
	isDisabled,
	isRequired,
	isError,
	errorMessage,
	hint,
	isReadOnly,
	startContent,
	endContent,
	color,
	suggestions = [],
	mentions = [],
	mentionTriggers = [{ char: "@", type: "user" }], // Default to @ mentions for backward compatibility
	getSuggestions,
	getMentions,
	onSuggestionSelect,
	onMentionSelect,
	onMentionRemove,
	onMentionClick,
	onChange,
	value: propValue,
	maxMentionSuggestions = 5,
	renderMention,
	renderMentionInInput,
	mentionListClassName,
	mentionItemClassName,
	mentionSelectedItemClassName,
	formatMentionText,
	...props
}: AutoSuggestInputProps) {
	const [inputValue, setInputValue] = useState<string>(
		(propValue as string) || "",
	);
	const [suggestion, setSuggestion] = useState<string>("");
	const [dynamicSuggestions, setDynamicSuggestions] =
		useState<string[]>(suggestions);
	const [mentionSearch, setMentionSearch] = useState<string | null>(null);
	const [mentionSearchPosition, setMentionSearchPosition] =
		useState<number>(-1);
	const [activeTrigger, setActiveTrigger] = useState<MentionTrigger | null>(
		null,
	);
	const [filteredMentions, setFilteredMentions] = useState<MentionItem[]>([]);
	const [showMentions, setShowMentions] = useState<boolean>(false);
	const [selectedMentionIndex, setSelectedMentionIndex] = useState<number>(0);
	const [mentionListRect, setMentionListRect] = useState<{
		top: number;
		left: number;
	}>({ top: 0, left: 0 });
	const [activeMentions, setActiveMentions] = useState<MentionMeta[]>([]);

	const inputRef = useRef<HTMLInputElement>(null);
	const startContentRef = useRef<HTMLDivElement>(null);
	const endContentRef = useRef<HTMLDivElement>(null);
	const inputContainerRef = useRef<HTMLDivElement>(null);
	const mentionsListRef = useRef<HTMLDivElement>(null);
	const mentionDisplayRef = useRef<HTMLDivElement>(null);

	// Update local state when prop value changes
	useEffect(() => {
		if (propValue !== undefined) {
			setFullContent(propValue as string);
			// Clear the visible input if we have mentions
			if (activeMentions.length > 0) {
				setInputValue("");
			} else {
				setInputValue(propValue as string);
			}
		}
	}, [propValue, activeMentions.length]);

	// Update suggestions dynamically if function is provided
	useEffect(() => {
		const updateSuggestions = async () => {
			if (getSuggestions && inputValue && !showMentions) {
				const newSuggestions = await getSuggestions(inputValue);
				setDynamicSuggestions(newSuggestions);
			}
		};

		updateSuggestions();
	}, [inputValue, getSuggestions, showMentions]);

	// Find matching suggestion
	useEffect(() => {
		if (!inputValue || showMentions) {
			setSuggestion("");
			return;
		}

		const activeSuggestions = getSuggestions ? dynamicSuggestions : suggestions;

		const matchingSuggestion = activeSuggestions.find(
			(item) =>
				item.toLowerCase().startsWith(inputValue.toLowerCase()) &&
				item.toLowerCase() !== inputValue.toLowerCase(),
		);

		setSuggestion(matchingSuggestion || "");
	}, [
		inputValue,
		suggestions,
		dynamicSuggestions,
		getSuggestions,
		showMentions,
	]);

	// Handle mention searching
	useEffect(() => {
		const handleMentionSearch = async () => {
			if (mentionSearch !== null && activeTrigger) {
				let mentionsToFilter = mentions;

				if (getMentions) {
					try {
						mentionsToFilter = await getMentions(
							mentionSearch,
							activeTrigger.type,
						);
					} catch (error) {
						console.error("Error fetching mentions:", error);
					}
				}

				// Filter mentions based on search term and current trigger type
				const filtered = mentionsToFilter
					.filter((mention) => {
						// If mention has a type, match by type, otherwise don't filter by type
						const typeMatches = mention.type
							? mention.type === activeTrigger.type
							: true;
						return (
							typeMatches &&
							mention.display
								.toLowerCase()
								.includes(mentionSearch.toLowerCase())
						);
					})
					.slice(0, maxMentionSuggestions);

				setFilteredMentions(filtered);
				setShowMentions(filtered.length > 0);
				setSelectedMentionIndex(0);

				// Calculate position for mentions dropdown
				if (
					inputRef.current &&
					inputContainerRef.current &&
					filtered.length > 0
				) {
					const inputRect = inputRef.current.getBoundingClientRect();
					const containerRect =
						inputContainerRef.current.getBoundingClientRect();

					// Get text width up to caret position for horizontal positioning
					const selectionStart = inputRef.current.selectionStart || 0;
					const textBeforeCaret = inputValue.substring(0, selectionStart);

					// Create temporary element to measure text width
					const temp = document.createElement("div");
					temp.style.position = "absolute";
					temp.style.visibility = "hidden";
					temp.style.whiteSpace = "pre";
					temp.style.fontFamily = window.getComputedStyle(
						inputRef.current,
					).fontFamily;
					temp.style.fontSize = window.getComputedStyle(
						inputRef.current,
					).fontSize;
					temp.style.fontWeight = window.getComputedStyle(
						inputRef.current,
					).fontWeight;
					temp.style.letterSpacing = window.getComputedStyle(
						inputRef.current,
					).letterSpacing;
					temp.innerText = textBeforeCaret;
					document.body.appendChild(temp);

					// Calculate left position based on text width and any startContent
					let leftPosition = temp.clientWidth;

					// Add padding-left of input
					const inputPaddingLeft = Number.parseInt(
						window.getComputedStyle(inputRef.current).paddingLeft,
						10,
					);
					leftPosition += inputPaddingLeft;

					// Add position of startContent if it exists
					if (startContentRef.current) {
						const startContentWidth =
							startContentRef.current.getBoundingClientRect().width;
						leftPosition += startContentWidth;
					}

					// Make sure dropdown doesn't go off the right edge
					const maxLeft = containerRect.width - 200; // assuming dropdown min-width is 200px
					leftPosition = Math.min(leftPosition, maxLeft);

					document.body.removeChild(temp);

					setMentionListRect({
						top: inputRect.height,
						left: leftPosition,
					});
				}
			} else {
				setShowMentions(false);
			}
		};

		handleMentionSearch();
	}, [
		mentionSearch,
		mentions,
		getMentions,
		maxMentionSuggestions,
		activeTrigger,
	]);

	// Track mentions in the input text
	useEffect(() => {
		if (inputRef.current) {
			// Need to recalculate positions of all mentions when text changes
			adjustMentionPositions();
		}
	}, [inputValue]);

	// Add this after your other useEffect hooks
	useEffect(() => {
		// Only add the listener when the mentions dropdown is showing
		if (!showMentions) return;

		const handleClickOutside = (event: MouseEvent) => {
			// If the click is outside both the input and the mentions dropdown
			if (
				inputRef.current &&
				!inputRef.current.contains(event.target as Node) &&
				mentionsListRef.current &&
				!mentionsListRef.current.contains(event.target as Node)
			) {
				// Close the dropdown
				setShowMentions(false);
				setMentionSearch(null);
				setActiveTrigger(null);
			}
		};

		// Add the event listener
		document.addEventListener("mousedown", handleClickOutside);

		// Remove the event listener on cleanup
		return () => {
			document.removeEventListener("mousedown", handleClickOutside);
		};
	}, [showMentions]);

	// Adjust positions of mentions as text changes
	const adjustMentionPositions = () => {
		// First check if any mentions were deleted
		updateActiveMentions();

		// Now adjust positions of remaining mentions
		// This is a more complex implementation that would need to track
		// text changes and update mention positions accordingly
	};

	// Handle removing mentions when backspacing
	const updateActiveMentions = () => {
		// Create a copy of the current mentions
		let updatedMentions = [...activeMentions];

		// Check if any mentions were deleted
		const deletedMentions = updatedMentions.filter((mention) => {
			const mentionFullText = inputValue.substring(
				mention.startPosition,
				mention.endPosition,
			);
			const expectedText = formatMentionText
				? formatMentionText(mention.originalMention, mention.triggerType)
				: `${mention.trigger}${mention.display}`;

			return mentionFullText !== expectedText;
		});

		// Remove deleted mentions
		if (deletedMentions.length > 0) {
			updatedMentions = updatedMentions.filter(
				(mention) =>
					!deletedMentions.some(
						(deleted) => deleted.mentionId === mention.mentionId,
					),
			);

			// Notify about removed mentions
			if (onMentionRemove) {
				deletedMentions.forEach((mention) => {
					onMentionRemove(mention);
				});
			}

			setActiveMentions(updatedMentions);
		}
	};

	const handleChange = (e: React.ChangeEvent<HTMLInputElement>) => {
		const newValue = e.target.value;
		const cursorPosition = e.target.selectionStart || 0;
		setInputValue(newValue);

		// Update the full content (keeping mentions)
		if (activeMentions.length > 0) {
			const updatedFullContent = fullContent + newValue;
			setFullContent(updatedFullContent);

			// Create synthetic event with full content
			const syntheticEvent = {
				...e,
				target: {
					...e.target,
					value: updatedFullContent,
				},
			} as React.ChangeEvent<HTMLInputElement>;

			if (onChange) {
				onChange(syntheticEvent);
			}
		} else {
			// When no mentions, input value is the full content
			setFullContent(newValue);

			if (onChange) {
				onChange(e);
			}
		}

		// Check for mention triggers
		let foundTrigger = false;

		for (const trigger of mentionTriggers) {
			const triggerChar = trigger.char;
			const triggerIndex = newValue.lastIndexOf(
				triggerChar,
				cursorPosition - 1,
			);

			if (
				triggerIndex !== -1 &&
				(triggerIndex === 0 || newValue[triggerIndex - 1] === " ")
			) {
				const searchText = newValue.substring(
					triggerIndex + triggerChar.length,
					cursorPosition,
				);

				// Only trigger mention search if there's no space after the trigger
				if (!searchText.includes(" ")) {
					setMentionSearch(searchText);
					setMentionSearchPosition(triggerIndex);
					setActiveTrigger(trigger);
					foundTrigger = true;
					break;
				}
			}
		}

		if (!foundTrigger) {
			setMentionSearch(null);
			setActiveTrigger(null);
			setShowMentions(false);
		}
	};

	const handleKeyDown = (e: React.KeyboardEvent<HTMLInputElement>) => {
		// Handle mention selection with keyboard
		if (showMentions) {
			switch (e.key) {
				case "ArrowDown":
					e.preventDefault();
					setSelectedMentionIndex((prev) =>
						prev < filteredMentions.length - 1 ? prev + 1 : prev,
					);
					break;

				case "ArrowUp":
					e.preventDefault();
					setSelectedMentionIndex((prev) => (prev > 0 ? prev - 1 : 0));
					break;

				case "Tab":
				case "Enter":
					e.preventDefault();
					if (filteredMentions.length > 0) {
						selectMention(filteredMentions[selectedMentionIndex]);
					}
					break;

				case "Escape":
					e.preventDefault();
					setShowMentions(false);
					setMentionSearch(null);
					setActiveTrigger(null);
					break;

				default:
					break;
			}
			return;
		}

		// Handle regular suggestion completion with Tab
		if (e.key === "Tab" && suggestion && !showMentions) {
			e.preventDefault();
			const newValue = suggestion;
			setInputValue(newValue);

			// Create a synthetic event to pass to onChange
			const syntheticEvent = {
				...e,
				target: {
					...e.target,
					value: newValue,
				},
			} as unknown as React.ChangeEvent<HTMLInputElement>;

			if (onChange) {
				onChange(syntheticEvent);
			}

			if (onSuggestionSelect) {
				onSuggestionSelect(newValue);
			}
		}
	};

	// Store the complete content (mentions + input text)
	const [fullContent, setFullContent] = useState<string>("");

	// Handle mention selection
	const selectMention = (mention: MentionItem) => {
		if (mentionSearchPosition >= 0 && inputRef.current && activeTrigger) {
			const cursorPosition = inputRef.current.selectionStart || 0;
			const beforeMention = inputValue.substring(0, mentionSearchPosition);
			const afterMention = inputValue.substring(cursorPosition);

			// Format the mention text based on the prop or use default format
			const mentionText = formatMentionText
				? formatMentionText(mention, activeTrigger.type)
				: `${activeTrigger.char}${mention.display}`;

			// Store the mention in our full content but clear the visible input
			const newFullContent = `${beforeMention}${mentionText} ${afterMention}`;
			setFullContent(newFullContent);

			// Clear the input field since we'll show the mention separately
			setInputValue("");

			// Add to active mentions list
			const newMention: MentionMeta = {
				mentionId: mention.id,
				trigger: activeTrigger.char,
				triggerType: activeTrigger.type,
				startPosition: mentionSearchPosition,
				endPosition: mentionSearchPosition + mentionText.length,
				display: mention.display,
				originalMention: mention,
			};

			setActiveMentions((prevMentions) => [...prevMentions, newMention]);

			// Create a synthetic event to pass to onChange with the full content
			const syntheticEvent = {
				target: {
					value: newFullContent,
				},
			} as React.ChangeEvent<HTMLInputElement>;

			if (onChange) {
				onChange(syntheticEvent as any);
			}

			if (onMentionSelect) {
				onMentionSelect(mention, newFullContent, activeTrigger.type);
			}

			// Reset mention state
			setShowMentions(false);
			setMentionSearch(null);
			setActiveTrigger(null);

			// Focus the input for continued typing
			setTimeout(() => {
				if (inputRef.current) {
					inputRef.current.focus();
				}
			}, 0);
		}
	};

	// Get size styles based on the current size prop
	const getSizeClasses = (size: string) => {
		switch (size) {
			case "xs":
				return "text-xs px-3";
			case "sm":
				return "text-sm px-3";
			case "md":
				return "text-sm px-4";
			case "lg":
				return "text-base px-4";
			case "xl":
				return "text-lg px-6";
			default:
				return "text-sm px-4";
		}
	};

	// Function to calculate computed styles of the input
	const getComputedPadding = () => {
		if (!inputRef.current) return { left: 0, right: 0 };

		const computedStyle = window.getComputedStyle(inputRef.current);
		return {
			left: Number.parseInt(computedStyle.paddingLeft, 10),
			right: Number.parseInt(computedStyle.paddingRight, 10),
		};
	};

	const getComputedPaddingStart = () => {
		if (!startContentRef.current) return { width: 0 };

		const computedStyle = window.getComputedStyle(startContentRef.current);
		return {
			width: Number.parseInt(computedStyle.width, 10) + 8,
		};
	};

	const getComputedPaddingEnd = () => {
		if (!endContentRef.current) return { width: 0 };

		const computedStyle = window.getComputedStyle(endContentRef.current);
		return {
			width: Number.parseInt(computedStyle.width, 10),
		};
	};

	const dynShared = useMemo(() => {
		return {
			paddingLeft: startContent ? getComputedPaddingStart().width : undefined,
			paddingRight: endContent ? getComputedPaddingEnd().width : undefined,
		};
	}, [startContent, endContent]);

	return (
		<div
			className={cn(
				"space-y-1",
				labelPositionStyles[labelPlacement],
				labelPlacement === "left" || labelPlacement === "right"
					? "flex items-center gap-4"
					: "flex flex-col",
			)}
		>
			{label && (
				<Label
					htmlFor={props.id}
					isRequired={isRequired}
					className={cn(
						"font-medium text-foreground text-sm leading-tight",
						labelPlacement === "top" || labelPlacement === "bottom"
							? "mb-2"
							: "mr-2",
					)}
				>
					{label}
				</Label>
			)}
			<div
				ref={inputContainerRef}
				className={cn(
					inputContainerVariants({
						variant,
						size,
						radius: variant === "underlined" ? "none" : radius,
						animated,
						fullWidth,
						color,
					}),
					"relative",
					isError && "border-destructive",
					className,
				)}
			>
				{startContent && (
					<div ref={startContentRef} className="flex items-center z-20">
						{startContent}
					</div>
				)}

				{/* Suggestion overlay - only show when not displaying mentions */}
				{!showMentions && (
					<div
						className={cn(
							"absolute inset-0 flex items-center pointer-events-none overflow-hidden",
							startContent ? "pl-8" : getSizeClasses(size),
							getSizeClasses(size),
						)}
						style={{ zIndex: 5 }}
					>
						{/* This is the invisible text that matches what user has typed */}
						<div className="flex-grow whitespace-pre" style={dynShared}>
							<span className="invisible">{inputValue}</span>

							{/* This is the visible suggestion text */}
							{suggestion && (
								<span className="text-gray-400 ml-0">
									{suggestion.substring(inputValue.length)}
								</span>
							)}
						</div>
					</div>
				)}

				{/* Mentions container */}
				{renderMentionInInput && activeMentions.length > 0 && (
					<div
						ref={mentionDisplayRef}
						className="absolute inset-y-0 left-0 z-15 flex flex-wrap gap-1 items-center pointer-events-none pl-3"
						style={{
							maxWidth: "70%",
							overflowX: "hidden",
							overflowY: "auto",
						}}
					>
						{activeMentions
							.sort((a, b) => a.startPosition - b.startPosition)
							.map((mention, index) => {
								const mentionElement = renderMentionInInput(mention);

								return (
									<div
										key={`${mention.mentionId}-${index}`}
										className="pointer-events-auto"
										onClick={(e) => {
											e.stopPropagation();
											if (onMentionClick) {
												onMentionClick(mention);
											}
										}}
									>
										{mentionElement}
									</div>
								);
							})}
					</div>
				)}

				{/* Actual input */}
				<input
					ref={inputRef}
					type={type}
					data-slot="input"
					size={inputSize}
					readOnly={isReadOnly}
					disabled={isDisabled}
					required={isRequired}
					className={cn(
						inputVariants({
							size,
							animated,
							fullWidth,
							color,
						}),
						"relative bg-transparent",
						isError && "border-destructive",
						renderMentionInInput && activeMentions.length > 0 && "pl-4",
						className,
					)}
					value={activeMentions.length > 0 ? "" : inputValue} // Show empty input when there are mentions
					onChange={handleChange}
					onKeyDown={handleKeyDown}
					style={{
						zIndex: 10,
						marginLeft: activeMentions.length > 0 ? "30%" : "0",
					}}
					placeholder={
						activeMentions.length > 0 ? "Continue typing..." : props.placeholder
					}
					{...props}
				/>

				{endContent && (
					<div ref={endContentRef} className="flex items-center z-20">
						{endContent}
					</div>
				)}

				{/* Mentions dropdown */}
				{showMentions && (
					<div
						ref={mentionsListRef}
						className={cn(
							"absolute z-50 bg-white dark:bg-gray-800 shadow-lg rounded-md overflow-hidden",
							"border border-gray-200 dark:border-gray-700 w-auto min-w-[200px] max-w-[300px]",
							mentionListClassName,
						)}
						style={{
							top: `${mentionListRect.top}px`,
							left: `${mentionListRect.left}px`,
							maxHeight: "200px",
							overflow: "auto",
						}}
					>
						<div className="max-h-[200px] overflow-y-auto py-1">
							{filteredMentions.length > 0 ? (
								filteredMentions.map((mention, index) => {
									const isSelected = index === selectedMentionIndex;
									const triggerType = activeTrigger
										? activeTrigger.type
										: "user";

									// Use custom renderer if provided
									if (renderMention) {
										return (
											<div
												key={mention.id}
												onClick={() => selectMention(mention)}
												className={cn(
													"cursor-pointer hover:bg-gray-100 dark:hover:bg-gray-700",
													isSelected &&
														(mentionSelectedItemClassName ||
															"bg-blue-50 dark:bg-blue-900"),
													mentionItemClassName,
												)}
											>
												{renderMention(mention, isSelected, triggerType)}
											</div>
										);
									}

									// Default rendering
									return (
										<div
											key={mention.id}
											className={cn(
												"px-3 py-2 cursor-pointer hover:bg-gray-100 dark:hover:bg-gray-700",
												isSelected &&
													(mentionSelectedItemClassName ||
														"bg-blue-50 dark:bg-blue-900"),
												mentionItemClassName,
											)}
											onClick={() => selectMention(mention)}
										>
											<div className="flex items-center">
												{mention.avatar && (
													<div className="w-6 h-6 rounded-full overflow-hidden mr-2">
														<img
															src={mention.avatar}
															alt={mention.display}
															className="w-full h-full object-cover"
														/>
													</div>
												)}
												<div>
													<div className="font-medium">
														{mention.display}
														{mention.type && mention.type !== "user" && (
															<span className="ml-2 text-xs bg-gray-200 dark:bg-gray-700 text-gray-700 dark:text-gray-300 px-2 py-0.5 rounded">
																{mention.type}
															</span>
														)}
													</div>
													{mention.description && (
														<div className="text-xs text-gray-500 dark:text-gray-400">
															{mention.description}
														</div>
													)}
												</div>
											</div>
										</div>
									);
								})
							) : (
								<div className="px-3 py-2 text-gray-500 dark:text-gray-400 text-sm">
									No results found
								</div>
							)}
						</div>
					</div>
				)}
			</div>
			{errorMessage ? (
				<p className="px-2 text-destructive text-xs">{errorMessage}</p>
			) : hint ? (
				<p className="px-2 text-muted-foreground text-xs">{hint}</p>
			) : null}
		</div>
	);
}
