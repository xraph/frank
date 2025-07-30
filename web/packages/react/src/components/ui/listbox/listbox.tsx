import { useTheme } from "@/theme/context";
import { type StyledProps, getColorVariant } from "@/theme/styled";
import { css } from "@emotion/react";
import styled from "@emotion/styled";
import React, {
	useState,
	useRef,
	useEffect,
	useCallback,
	useMemo,
} from "react";

export interface ListboxItem {
	/** Unique identifier */
	key: string | number;
	/** Display label */
	label: string;
	/** Value for the item */
	value?: any;
	/** Description text */
	description?: string;
	/** Start content (icon, avatar) */
	startContent?: React.ReactNode;
	/** End content (icon, badge) */
	endContent?: React.ReactNode;
	/** Disabled state */
	isDisabled?: boolean;
	/** Custom class name */
	className?: string;
	/** Text value for search */
	textValue?: string;
}

export interface ListboxProps
	extends Omit<React.HTMLAttributes<HTMLDivElement>, "onSelect"> {
	/** Listbox items */
	items?: ListboxItem[];
	/** Selected keys */
	selectedKeys?: Set<string | number> | "all";
	/** Default selected keys */
	defaultSelectedKeys?: Set<string | number> | "all";
	/** Disabled keys */
	disabledKeys?: Set<string | number>;
	/** Selection mode */
	selectionMode?: "none" | "single" | "multiple";
	/** Selection behavior */
	selectionBehavior?: "toggle" | "replace";
	/** Empty content */
	emptyContent?: React.ReactNode;
	/** Loading state */
	isLoading?: boolean;
	/** Loading content */
	loadingContent?: React.ReactNode;
	/** Listbox variant */
	variant?: "flat" | "bordered" | "light" | "solid";
	/** Listbox color */
	color?: "primary" | "secondary" | "success" | "warning" | "danger";
	/** Item height */
	itemHeight?: "sm" | "md" | "lg";
	/** Max height */
	maxHeight?: string | number;
	/** Hide selected icon */
	hideSelectedIcon?: boolean;
	/** Show dividers */
	showDividers?: boolean;
	/** Keyboard navigation */
	shouldFocusWrap?: boolean;
	/** Auto focus */
	autoFocus?: boolean;
	/** Custom class name */
	className?: string;
	/** Custom styles */
	css?: any;
	/** Selection change handler */
	onSelectionChange?: (keys: Set<string | number> | "all") => void;
	/** Item action handler */
	onAction?: (key: string | number) => void;
}

export interface ListboxItemProps extends React.HTMLAttributes<HTMLDivElement> {
	/** Item data */
	item: ListboxItem;
	/** Selected state */
	isSelected?: boolean;
	/** Focused state */
	isFocused?: boolean;
	/** Disabled state */
	isDisabled?: boolean;
	/** Selection mode */
	selectionMode?: "none" | "single" | "multiple";
	/** Hide selected icon */
	hideSelectedIcon?: boolean;
	/** Item height */
	itemHeight?: "sm" | "md" | "lg";
	/** Color theme */
	color?: "primary" | "secondary" | "success" | "warning" | "danger";
	/** Custom class name */
	className?: string;
	/** Custom styles */
	css?: any;
	/** Click handler */
	onPress?: () => void;
}

type StyledListboxProps = StyledProps<ListboxProps>;
type StyledListboxItemProps = StyledProps<ListboxItemProps>;

const getListboxVariantStyles = (props: StyledListboxProps) => {
	const { theme, variant = "flat", color = "primary" } = props;
	const baseColor = getColorVariant(theme, color, 500);

	switch (variant) {
		case "flat":
			return css`
        background-color: ${theme.colors.background.secondary};
        border: 1px solid transparent;
      `;
		case "bordered":
			return css`
        background-color: ${theme.colors.background.primary};
        border: 1px solid ${theme.colors.border.primary};
      `;
		case "light":
			return css`
        background-color: ${getColorVariant(theme, color, 50)};
        border: 1px solid transparent;
      `;
		case "solid":
			return css`
        background-color: ${baseColor};
        border: 1px solid ${baseColor};
        color: ${theme.colors.text.inverse};
      `;
		default:
			return css``;
	}
};

const getListboxItemHeightStyles = (props: StyledListboxItemProps) => {
	const { theme, itemHeight = "md" } = props;

	switch (itemHeight) {
		case "sm":
			return css`
        min-height: ${theme.spacing[8]};
        padding: ${theme.spacing[2]} ${theme.spacing[3]};
        font-size: ${theme.fontSizes.sm};
      `;
		case "md":
			return css`
        min-height: ${theme.spacing[10]};
        padding: ${theme.spacing[3]} ${theme.spacing[4]};
        font-size: ${theme.fontSizes.base};
      `;
		case "lg":
			return css`
        min-height: ${theme.spacing[12]};
        padding: ${theme.spacing[4]} ${theme.spacing[6]};
        font-size: ${theme.fontSizes.lg};
      `;
		default:
			return css``;
	}
};

const getListboxItemStateStyles = (props: StyledListboxItemProps) => {
	const { theme, isSelected, isFocused, isDisabled, color = "primary" } = props;
	const baseColor = getColorVariant(theme, color, 500);
	const lightColor = getColorVariant(theme, color, 50);

	if (isDisabled) {
		return css`
      opacity: 0.5;
      cursor: not-allowed;
      pointer-events: none;
    `;
	}

	let styles = css`
    cursor: pointer;
    transition: all ${theme.transitions.fast};
    
    &:hover {
      background-color: ${theme.colors.background.tertiary};
    }
  `;

	if (isSelected) {
		styles = css`
      ${styles}
      background-color: ${lightColor};
      color: ${getColorVariant(theme, color, 700)};
      
      &:hover {
        background-color: ${getColorVariant(theme, color, 100)};
      }
    `;
	}

	if (isFocused) {
		styles = css`
      ${styles}
      outline: 2px solid ${baseColor};
      outline-offset: -2px;
    `;
	}

	return styles;
};

const StyledListbox = styled.div<StyledListboxProps>`
  position: relative;
  border-radius: ${(props) => props.theme.borderRadius.lg};
  overflow: hidden;
  outline: none;
  
  ${getListboxVariantStyles}

  ${(props) =>
		props.maxHeight &&
		css`
    max-height: ${typeof props.maxHeight === "number" ? `${props.maxHeight}px` : props.maxHeight};
    overflow-y: auto;
  `}

  /* Custom scrollbar */
  &::-webkit-scrollbar {
    width: 6px;
  }

  &::-webkit-scrollbar-track {
    background: ${(props) => props.theme.colors.neutral[100]};
  }

  &::-webkit-scrollbar-thumb {
    background: ${(props) => props.theme.colors.neutral[300]};
    border-radius: 3px;
  }

  &::-webkit-scrollbar-thumb:hover {
    background: ${(props) => props.theme.colors.neutral[400]};
  }

  /* Custom CSS prop */
  ${(props) => props.css}
`;

const StyledListboxItem = styled.div<StyledListboxItemProps>`
  display: flex;
  align-items: center;
  gap: ${(props) => props.theme.spacing[3]};
  position: relative;
  user-select: none;

  ${getListboxItemHeightStyles}
  ${getListboxItemStateStyles}

  ${(props) => props.css}
`;

const ItemContent = styled.div<StyledProps>`
  display: flex;
  flex-direction: column;
  flex: 1;
  min-width: 0;
  gap: ${(props) => props.theme.spacing[1]};
`;

const ItemLabel = styled.div<StyledProps>`
  font-weight: ${(props) => props.theme.fontWeights.medium};
  color: inherit;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
`;

const ItemDescription = styled.div<StyledProps>`
  font-size: ${(props) => props.theme.fontSizes.sm};
  color: ${(props) => props.theme.colors.text.secondary};
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
`;

const EmptyContent = styled.div<StyledProps>`
  display: flex;
  align-items: center;
  justify-content: center;
  padding: ${(props) => props.theme.spacing[8]} ${(props) => props.theme.spacing[4]};
  color: ${(props) => props.theme.colors.text.secondary};
  font-size: ${(props) => props.theme.fontSizes.sm};
  text-align: center;
`;

const LoadingContent = styled.div<StyledProps>`
  display: flex;
  align-items: center;
  justify-content: center;
  padding: ${(props) => props.theme.spacing[6]} ${(props) => props.theme.spacing[4]};
  gap: ${(props) => props.theme.spacing[2]};
  color: ${(props) => props.theme.colors.text.secondary};
  font-size: ${(props) => props.theme.fontSizes.sm};
`;

const Divider = styled.div<StyledProps>`
  height: 1px;
  background-color: ${(props) => props.theme.colors.border.primary};
  margin: ${(props) => props.theme.spacing[1]} 0;
`;

const SelectedIcon = () => (
	// biome-ignore lint/a11y/noSvgWithoutTitle: <explanation>
	<svg
		width="16"
		height="16"
		viewBox="0 0 24 24"
		fill="none"
		stroke="currentColor"
		strokeWidth="2"
		strokeLinecap="round"
		strokeLinejoin="round"
	>
		<polyline points="20,6 9,17 4,12" />
	</svg>
);

const LoadingSpinner = () => (
	// biome-ignore lint/a11y/noSvgWithoutTitle: <explanation>
	<svg
		width="16"
		height="16"
		viewBox="0 0 24 24"
		fill="none"
		stroke="currentColor"
		strokeWidth="2"
		style={{ animation: "spin 1s linear infinite" }}
	>
		<path d="M21 12a9 9 0 11-6.219-8.56" />
	</svg>
);

export const ListboxItem: React.FC<ListboxItemProps> = ({
	item,
	isSelected = false,
	isFocused = false,
	isDisabled = false,
	selectionMode = "single",
	hideSelectedIcon = false,
	itemHeight = "md",
	color = "primary",
	className,
	css,
	onPress,
	...props
}) => {
	const { theme } = useTheme();

	const itemProps = {
		item,
		isSelected,
		isFocused,
		isDisabled: isDisabled || item.isDisabled,
		selectionMode,
		hideSelectedIcon,
		itemHeight,
		color,
		className,
		theme: theme,
		css,
	};

	const handleClick = () => {
		if (!itemProps.isDisabled) {
			onPress?.();
		}
	};

	const handleKeyDown = (e: React.KeyboardEvent) => {
		if ((e.key === "Enter" || e.key === " ") && !itemProps.isDisabled) {
			e.preventDefault();
			onPress?.();
		}
	};

	return (
		<StyledListboxItem
			{...itemProps}
			{...props}
			onClick={handleClick}
			onKeyDown={handleKeyDown}
			tabIndex={isFocused ? 0 : -1}
			role="option"
			aria-selected={isSelected}
			aria-disabled={itemProps.isDisabled}
		>
			{item.startContent}
			<ItemContent theme={theme}>
				<ItemLabel theme={theme}>{item.label}</ItemLabel>
				{item.description && (
					<ItemDescription theme={theme}>{item.description}</ItemDescription>
				)}
			</ItemContent>
			{item.endContent}
			{!hideSelectedIcon && selectionMode !== "none" && isSelected && (
				<SelectedIcon />
			)}
		</StyledListboxItem>
	);
};

export const Listbox = React.forwardRef<HTMLDivElement, ListboxProps>(
	(
		{
			items = [],
			selectedKeys: controlledSelectedKeys,
			defaultSelectedKeys,
			disabledKeys = new Set(),
			selectionMode = "single",
			selectionBehavior = "toggle",
			emptyContent = "No items found",
			isLoading = false,
			loadingContent,
			variant = "flat",
			color = "primary",
			itemHeight = "md",
			maxHeight,
			hideSelectedIcon = false,
			showDividers = false,
			shouldFocusWrap = true,
			autoFocus = false,
			className,
			css,
			onSelectionChange,
			onAction,
			...props
		},
		ref,
	) => {
		const { theme } = useTheme();
		const [internalSelectedKeys, setInternalSelectedKeys] = useState<
			Set<string | number> | "all"
		>(defaultSelectedKeys || new Set());
		const [focusedKey, setFocusedKey] = useState<string | number | null>(null);
		const listboxRef = useRef<HTMLDivElement>(null);

		const isControlled = controlledSelectedKeys !== undefined;
		const selectedKeys = isControlled
			? controlledSelectedKeys
			: internalSelectedKeys;

		// Auto focus first item
		useEffect(() => {
			if (autoFocus && items.length > 0) {
				const firstEnabledItem = items.find(
					(item) => !item.isDisabled && !disabledKeys.has(item.key),
				);
				if (firstEnabledItem) {
					setFocusedKey(firstEnabledItem.key);
				}
			}
		}, [autoFocus, items, disabledKeys]);

		// Get enabled items
		const enabledItems = useMemo(
			() =>
				items.filter((item) => !item.isDisabled && !disabledKeys.has(item.key)),
			[items, disabledKeys],
		);

		const handleSelectionChange = useCallback(
			(keys: Set<string | number> | "all") => {
				if (!isControlled) {
					setInternalSelectedKeys(keys);
				}
				onSelectionChange?.(keys);
			},
			[isControlled, onSelectionChange],
		);

		const handleItemPress = useCallback(
			(key: string | number) => {
				if (selectionMode === "none") {
					onAction?.(key);
					return;
				}

				let newSelectedKeys: Set<string | number> | "all";

				if (selectionMode === "single") {
					if (
						selectionBehavior === "toggle" &&
						selectedKeys !== "all" &&
						selectedKeys.has(key)
					) {
						newSelectedKeys = new Set();
					} else {
						newSelectedKeys = new Set([key]);
					}
				} else {
					// Multiple selection
					if (selectedKeys === "all") {
						newSelectedKeys = new Set(
							items.map((item) => item.key).filter((k) => k !== key),
						);
					} else {
						newSelectedKeys = new Set(selectedKeys);
						if (newSelectedKeys.has(key)) {
							if (selectionBehavior === "toggle") {
								newSelectedKeys.delete(key);
							}
						} else {
							newSelectedKeys.add(key);
						}
					}
				}

				handleSelectionChange(newSelectedKeys);
				onAction?.(key);
			},
			[
				selectionMode,
				selectionBehavior,
				selectedKeys,
				items,
				handleSelectionChange,
				onAction,
			],
		);

		const handleKeyDown = useCallback(
			(e: React.KeyboardEvent) => {
				if (enabledItems.length === 0) return;

				const currentIndex = focusedKey
					? enabledItems.findIndex((item) => item.key === focusedKey)
					: -1;
				let newIndex = currentIndex;

				switch (e.key) {
					case "ArrowDown":
						e.preventDefault();
						newIndex = currentIndex + 1;
						if (newIndex >= enabledItems.length) {
							newIndex = shouldFocusWrap ? 0 : enabledItems.length - 1;
						}
						break;
					case "ArrowUp":
						e.preventDefault();
						newIndex = currentIndex - 1;
						if (newIndex < 0) {
							newIndex = shouldFocusWrap ? enabledItems.length - 1 : 0;
						}
						break;
					case "Home":
						e.preventDefault();
						newIndex = 0;
						break;
					case "End":
						e.preventDefault();
						newIndex = enabledItems.length - 1;
						break;
					case "Enter":
					case " ":
						e.preventDefault();
						if (focusedKey !== null) {
							handleItemPress(focusedKey);
						}
						return;
					case "a":
						if (e.ctrlKey || e.metaKey) {
							e.preventDefault();
							if (selectionMode === "multiple") {
								handleSelectionChange("all");
							}
						}
						return;
					default:
						return;
				}

				if (newIndex !== currentIndex && enabledItems[newIndex]) {
					setFocusedKey(enabledItems[newIndex].key);
				}
			},
			[
				enabledItems,
				focusedKey,
				shouldFocusWrap,
				handleItemPress,
				selectionMode,
				handleSelectionChange,
			],
		);

		const listboxProps = {
			variant,
			color,
			maxHeight,
			className,
			css,
		};

		const isItemSelected = (key: string | number) => {
			if (selectedKeys === "all") return true;
			return selectedKeys.has(key);
		};

		const renderContent = () => {
			if (isLoading) {
				return (
					<LoadingContent theme={theme}>
						<LoadingSpinner />
						{loadingContent || "Loading..."}
						<style>
							{/* biome-ignore lint/style/noUnusedTemplateLiteral: <explanation> */}
							{`@keyframes spin { to { transform: rotate(360deg); } }`}
						</style>
					</LoadingContent>
				);
			}

			if (items.length === 0) {
				return <EmptyContent theme={theme}>{emptyContent}</EmptyContent>;
			}

			return items.map((item, index) => (
				<React.Fragment key={item.key}>
					{showDividers && index > 0 && <Divider theme={theme} />}
					<ListboxItem
						item={item}
						isSelected={isItemSelected(item.key)}
						isFocused={focusedKey === item.key}
						isDisabled={item.isDisabled || disabledKeys.has(item.key)}
						selectionMode={selectionMode}
						hideSelectedIcon={hideSelectedIcon}
						itemHeight={itemHeight}
						color={color}
						onPress={() => handleItemPress(item.key)}
					/>
				</React.Fragment>
			));
		};

		return (
			<StyledListbox
				ref={ref || listboxRef}
				theme={theme}
				{...listboxProps}
				{...props}
				role="listbox"
				aria-multiselectable={selectionMode === "multiple"}
				tabIndex={0}
				onKeyDown={handleKeyDown}
			>
				{renderContent()}
			</StyledListbox>
		);
	},
);

Listbox.displayName = "Listbox";
ListboxItem.displayName = "ListboxItem";
