import { useTheme } from "@/theme/context";
import { type StyledProps, getColorVariant } from "@/theme/styled";
import type { Theme } from "@/theme/theme";
import { css } from "@emotion/react";
import styled from "@emotion/styled";
import React, { useState, useRef, useEffect, useImperativeHandle } from "react";

export interface SelectOption {
	value: string | number;
	label: string;
	isDisabled?: boolean;
	startContent?: React.ReactNode;
	endContent?: React.ReactNode;
	description?: string;
}

export interface SelectProps
	extends Omit<
		React.SelectHTMLAttributes<HTMLSelectElement>,
		"size" | "children"
	> {
	/** Select variant */
	variant?: "flat" | "bordered" | "underlined" | "faded";
	/** Select color theme */
	color?: "primary" | "secondary" | "success" | "warning" | "danger";
	/** Select size */
	size?: "sm" | "md" | "lg";
	/** Select radius */
	radius?: "none" | "sm" | "md" | "lg" | "full";
	/** Label text */
	label?: string;
	/** Placeholder text */
	placeholder?: string;
	/** Description text */
	description?: string;
	/** Error message */
	errorMessage?: string;
	/** Invalid state */
	isInvalid?: boolean;
	/** Disabled state */
	isDisabled?: boolean;
	/** Required field */
	isRequired?: boolean;
	/** Full width select */
	fullWidth?: boolean;
	/** Multiple selection */
	isMultiple?: boolean;
	/** Options array */
	options?: SelectOption[];
	/** Selected value(s) */
	selectedKeys?: Set<string | number> | string | number;
	/** Default selected value(s) */
	defaultSelectedKeys?: Set<string | number> | string | number;
	/** Selection change handler */
	onSelectionChange?: (keys: Set<string | number>) => void;
	/** Start content (icon) */
	startContent?: React.ReactNode;
	/** End content (icon) */
	endContent?: React.ReactNode;
	/** Custom class name */
	className?: string;
	/** Custom styles */
	css?: any;
	/** Label placement */
	labelPlacement?: "inside" | "outside" | "outside-left";
}

type StyledSelectProps = StyledProps<SelectProps>;

const getSelectVariantStyles = (
	props: StyledSelectProps & { isFocused: boolean; isOpen: boolean },
) => {
	const {
		theme,
		variant = "flat",
		color = "primary",
		isInvalid,
		isFocused,
		isDisabled,
		isOpen,
	} = props;
	const baseColor = getColorVariant(theme, color, 500);
	const errorColor = theme.colors.danger[500];

	const focusColor = isInvalid ? errorColor : baseColor;

	switch (variant) {
		case "flat":
			return css`
        background-color: ${theme.colors.background.secondary};
        border: 2px solid transparent;

        &:hover:not(:disabled) {
          background-color: ${theme.colors.background.tertiary};
        }

        ${
					(isFocused || isOpen) &&
					css`
          background-color: ${theme.colors.background.primary};
          border-color: ${focusColor};
        `
				}

        ${
					isInvalid &&
					css`
          border-color: ${errorColor};
        `
				}

        ${
					isDisabled &&
					css`
          opacity: 0.5;
          cursor: not-allowed;
        `
				}
      `;

		case "bordered":
			return css`
        background-color: ${theme.colors.background.primary};
        border: 2px solid ${theme.colors.border.primary};

        &:hover:not(:disabled) {
          border-color: ${theme.colors.border.secondary};
        }

        ${
					(isFocused || isOpen) &&
					css`
          border-color: ${focusColor};
        `
				}

        ${
					isInvalid &&
					css`
          border-color: ${errorColor};
        `
				}

        ${
					isDisabled &&
					css`
          opacity: 0.5;
          cursor: not-allowed;
          background-color: ${theme.colors.background.secondary};
        `
				}
      `;

		case "underlined":
			return css`
        background-color: transparent;
        border: none;
        border-bottom: 2px solid ${theme.colors.border.primary};
        border-radius: 0;

        &:hover:not(:disabled) {
          border-bottom-color: ${theme.colors.border.secondary};
        }

        ${
					(isFocused || isOpen) &&
					css`
          border-bottom-color: ${focusColor};
        `
				}

        ${
					isInvalid &&
					css`
          border-bottom-color: ${errorColor};
        `
				}

        ${
					isDisabled &&
					css`
          opacity: 0.5;
          cursor: not-allowed;
        `
				}
      `;

		case "faded":
			return css`
        background-color: ${theme.colors.neutral[100]};
        border: 2px solid ${theme.colors.neutral[200]};

        &:hover:not(:disabled) {
          background-color: ${theme.colors.neutral[50]};
          border-color: ${theme.colors.neutral[300]};
        }

        ${
					(isFocused || isOpen) &&
					css`
          background-color: ${theme.colors.background.primary};
          border-color: ${focusColor};
        `
				}

        ${
					isInvalid &&
					css`
          border-color: ${errorColor};
        `
				}

        ${
					isDisabled &&
					css`
          opacity: 0.5;
          cursor: not-allowed;
        `
				}
      `;

		default:
			return css``;
	}
};

const getSelectSizeStyles = (props: StyledSelectProps) => {
	const { theme, size = "md" } = props;

	switch (size) {
		case "sm":
			return css`
        height: ${theme.spacing[8]};
        padding: 0 ${theme.spacing[3]};
        font-size: ${theme.fontSizes.sm};
      `;
		case "md":
			return css`
        height: ${theme.spacing[10]};
        padding: 0 ${theme.spacing[4]};
        font-size: ${theme.fontSizes.base};
      `;
		case "lg":
			return css`
        height: ${theme.spacing[12]};
        padding: 0 ${theme.spacing[6]};
        font-size: ${theme.fontSizes.lg};
      `;
		default:
			return css``;
	}
};

const getSelectRadiusStyles = (props: StyledSelectProps) => {
	const { theme, radius = "md", variant } = props;

	if (variant === "underlined") return css``;

	switch (radius) {
		case "none":
			return css`border-radius: ${theme.borderRadius.none};`;
		case "sm":
			return css`border-radius: ${theme.borderRadius.sm};`;
		case "md":
			return css`border-radius: ${theme.borderRadius.md};`;
		case "lg":
			return css`border-radius: ${theme.borderRadius.lg};`;
		case "full":
			return css`border-radius: ${theme.borderRadius.full};`;
		default:
			return css`border-radius: ${theme.borderRadius.md};`;
	}
};

const SelectContainer = styled.div<StyledSelectProps & { fullWidth?: boolean }>`
  display: flex;
  flex-direction: column;
  gap: ${(props) => props.theme.spacing[2]};
  width: ${(props) => (props.fullWidth ? "100%" : "auto")};
  position: relative;
`;

const SelectWrapper = styled.div<
	StyledSelectProps & { isFocused: boolean; isOpen: boolean }
>`
  position: relative;
  display: flex;
  align-items: center;
  transition: all ${(props) => props.theme.transitions.normal};
  width: ${(props) => (props.fullWidth ? "100%" : "auto")};
  cursor: ${(props) => (props.isDisabled ? "not-allowed" : "pointer")};

  ${getSelectVariantStyles}
  ${getSelectSizeStyles}
  ${getSelectRadiusStyles}

  ${(props) => props.css}
`;

const HiddenSelect = styled.select`
  position: absolute;
  opacity: 0;
  pointer-events: none;
  width: 100%;
  height: 100%;
`;

const SelectTrigger = styled.div<StyledSelectProps>`
  display: flex;
  align-items: center;
  justify-content: space-between;
  width: 100%;
  color: ${(props) => props.theme.colors.text.primary};
  cursor: inherit;
`;

const SelectValue = styled.div<StyledSelectProps & { hasPlaceholder: boolean }>`
  flex: 1;
  text-align: left;
  color: ${(props) =>
		props.hasPlaceholder
			? props.theme.colors.text.tertiary
			: props.theme.colors.text.primary};
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
`;

const ChevronIcon = styled.div<StyledSelectProps & { isOpen: boolean }>`
  display: flex;
  align-items: center;
  margin-left: ${(props) => props.theme.spacing[2]};
  transform: ${(props) => (props.isOpen ? "rotate(180deg)" : "rotate(0deg)")};
  transition: transform ${(props) => props.theme.transitions.fast};
  color: ${(props) => props.theme.colors.text.secondary};
`;

const Dropdown = styled.div<
	StyledSelectProps & { isOpen: boolean; size?: "sm" | "md" | "lg" }
>`
  position: absolute;
  top: 100%;
  left: 0;
  right: 0;
  z-index: ${(props) => props.theme.zIndex.dropdown};
  background-color: ${(props) => props.theme.colors.background.primary};
  border: 1px solid ${(props) => props.theme.colors.border.primary};
  border-radius: ${(props) => props.theme.borderRadius.md};
  box-shadow: ${(props) => props.theme.shadows.lg};
  max-height: 200px;
  overflow-y: auto;
  margin-top: ${(props) => props.theme.spacing[1]};
  display: ${(props) => (props.isOpen ? "block" : "none")};
`;

const Option = styled.div<
	StyledSelectProps & {
		isSelected: boolean;
		isDisabled?: boolean;
		size?: "sm" | "md" | "lg";
	}
>`
  display: flex;
  align-items: center;
  gap: ${(props) => props.theme.spacing[2]};
  padding: ${(props) => {
		switch (props.size) {
			case "sm":
				return `${props.theme.spacing[2]} ${props.theme.spacing[3]}`;
			case "lg":
				return `${props.theme.spacing[4]} ${props.theme.spacing[6]}`;
			default:
				return `${props.theme.spacing[3]} ${props.theme.spacing[4]}`;
		}
	}};
  cursor: ${(props) => (props.isDisabled ? "not-allowed" : "pointer")};
  transition: background-color ${(props) => props.theme.transitions.fast};
  font-size: ${(props) => {
		switch (props.size) {
			case "sm":
				return props.theme.fontSizes.sm;
			case "lg":
				return props.theme.fontSizes.lg;
			default:
				return props.theme.fontSizes.base;
		}
	}};

  ${(props) =>
		props.isSelected &&
		css`
    background-color: ${props.theme.colors.primary[50]};
    color: ${props.theme.colors.primary[700]};
  `}

  ${(props) =>
		props.isDisabled &&
		css`
    opacity: 0.5;
    pointer-events: none;
  `}

  &:hover:not(:disabled) {
    background-color: ${(props) =>
			props.isSelected
				? props.theme.colors.primary[100]
				: props.theme.colors.background.secondary};
  }
`;

const OptionContent = styled.div`
  display: flex;
  flex-direction: column;
  flex: 1;
  min-width: 0;
`;

const OptionLabel = styled.div<StyledSelectProps>`
  font-weight: ${(props) => props.theme.fontWeights.medium};
`;

const OptionDescription = styled.div<StyledSelectProps>`
  font-size: ${(props) => props.theme.fontSizes.sm};
  color: ${(props) => props.theme.colors.text.secondary};
  margin-top: ${(props) => props.theme.spacing[1]};
`;

const Label = styled.label<
	StyledSelectProps & {
		isRequired?: boolean;
		size?: "sm" | "md" | "lg";
	}
>`
  color: ${(props) => props.theme.colors.text.primary};
  font-size: ${(props) => {
		switch (props.size) {
			case "sm":
				return props.theme.fontSizes.sm;
			case "lg":
				return props.theme.fontSizes.lg;
			default:
				return props.theme.fontSizes.base;
		}
	}};
  font-weight: ${(props) => props.theme.fontWeights.medium};

  ${(props) =>
		props.isRequired &&
		css`
    &::after {
      content: ' *';
      color: ${props.theme.colors.danger[500]};
    }
  `}
`;

const HelperText = styled.div<StyledSelectProps & { isError?: boolean }>`
  font-size: ${(props) => props.theme.fontSizes.sm};
  color: ${(props) =>
		props.isError
			? props.theme.colors.danger[500]
			: props.theme.colors.text.secondary};
`;

const ContentWrapper = styled.div<{ position: "start" | "end"; theme: Theme }>`
  display: flex;
  align-items: center;
  color: ${(props) => props.theme.colors.text.tertiary};
  ${(props) =>
		props.position === "start"
			? css`margin-right: ${props.theme.spacing[2]};`
			: css`margin-left: ${props.theme.spacing[2]};`}
`;

const ChevronDownIcon = () => (
	// biome-ignore lint/a11y/noSvgWithoutTitle: <explanation>
	<svg
		width="16"
		height="16"
		viewBox="0 0 24 24"
		fill="none"
		stroke="currentColor"
		strokeWidth="2"
	>
		<polyline points="6,9 12,15 18,9" />
	</svg>
);

export const Select = React.forwardRef<HTMLSelectElement, SelectProps>(
	(
		{
			variant = "flat",
			color = "primary",
			size = "md",
			radius = "md",
			label,
			placeholder = "Select an option",
			description,
			errorMessage,
			isInvalid = false,
			isDisabled = false,
			isRequired = false,
			fullWidth = false,
			isMultiple = false,
			options = [],
			selectedKeys,
			defaultSelectedKeys,
			onSelectionChange,
			startContent,
			endContent,
			className,
			css,
			labelPlacement = "outside",
			onChange,
			onFocus,
			onBlur,
			...props
		},
		ref,
	) => {
		const { theme } = useTheme();
		const [isFocused, setIsFocused] = useState(false);
		const [isOpen, setIsOpen] = useState(false);
		const [internalSelected, setInternalSelected] = useState<
			Set<string | number>
		>(
			new Set(
				defaultSelectedKeys
					? typeof defaultSelectedKeys === "string" ||
						typeof defaultSelectedKeys === "number"
						? [defaultSelectedKeys]
						: Array.from(defaultSelectedKeys)
					: [],
			),
		);

		const selectRef = useRef<HTMLSelectElement>(null);
		const dropdownRef = useRef<HTMLDivElement>(null);

		useImperativeHandle(ref, () => selectRef.current!);

		const currentSelected =
			selectedKeys !== undefined
				? typeof selectedKeys === "string" || typeof selectedKeys === "number"
					? new Set([selectedKeys])
					: selectedKeys
				: internalSelected;

		const handleToggle = () => {
			if (!isDisabled) {
				setIsOpen(!isOpen);
			}
		};

		const handleOptionClick = (optionValue: string | number) => {
			let newSelected: Set<string | number>;

			if (isMultiple) {
				newSelected = new Set(currentSelected);
				if (newSelected.has(optionValue)) {
					newSelected.delete(optionValue);
				} else {
					newSelected.add(optionValue);
				}
			} else {
				newSelected = new Set([optionValue]);
				setIsOpen(false);
			}

			if (selectedKeys === undefined) {
				setInternalSelected(newSelected);
			}

			onSelectionChange?.(newSelected);
		};

		const handleFocus = (e: React.FocusEvent<HTMLSelectElement>) => {
			setIsFocused(true);
			onFocus?.(e);
		};

		const handleBlur = (e: React.FocusEvent<HTMLSelectElement>) => {
			setIsFocused(false);
			onBlur?.(e);
		};

		// Close dropdown when clicking outside
		useEffect(() => {
			const handleClickOutside = (event: MouseEvent) => {
				if (
					dropdownRef.current &&
					!dropdownRef.current.contains(event.target as Node)
				) {
					setIsOpen(false);
				}
			};

			document.addEventListener("mousedown", handleClickOutside);
			return () =>
				document.removeEventListener("mousedown", handleClickOutside);
		}, []);

		const selectProps = {
			variant,
			color,
			size,
			radius,
			isInvalid: isInvalid || !!errorMessage,
			isDisabled,
			fullWidth,
			isFocused,
			isOpen,
			className,
			css,
		};

		const selectedOption = options.find((opt) =>
			currentSelected.has(opt.value),
		);
		const selectedText =
			isMultiple && currentSelected.size > 1
				? `${currentSelected.size} items selected`
				: selectedOption?.label || "";

		const selectElement = (
			<SelectWrapper theme={theme} {...selectProps} ref={dropdownRef}>
				{startContent && (
					<ContentWrapper theme={theme} position="start">
						{startContent}
					</ContentWrapper>
				)}

				<SelectTrigger theme={theme} onClick={handleToggle}>
					<SelectValue theme={theme} hasPlaceholder={!selectedText}>
						{selectedText || placeholder}
					</SelectValue>

					<ChevronIcon theme={theme} isOpen={isOpen}>
						{endContent || <ChevronDownIcon />}
					</ChevronIcon>
				</SelectTrigger>

				<Dropdown theme={theme} isOpen={isOpen} size={size}>
					{options.map((option) => (
						<Option
							theme={theme}
							key={option.value}
							isSelected={currentSelected.has(option.value)}
							isDisabled={option.isDisabled}
							size={size}
							onClick={() =>
								!option.isDisabled && handleOptionClick(option.value)
							}
						>
							{option.startContent}
							<OptionContent>
								<OptionLabel theme={theme}>{option.label}</OptionLabel>
								{option.description && (
									<OptionDescription theme={theme}>
										{option.description}
									</OptionDescription>
								)}
							</OptionContent>
							{option.endContent}
						</Option>
					))}
				</Dropdown>

				<HiddenSelect
					ref={selectRef}
					multiple={isMultiple}
					disabled={isDisabled}
					value={Array.from(currentSelected)}
					onChange={onChange}
					onFocus={handleFocus}
					onBlur={handleBlur}
					{...props}
				>
					{options.map((option) => (
						<option
							key={option.value}
							value={option.value}
							disabled={option.isDisabled}
						>
							{option.label}
						</option>
					))}
				</HiddenSelect>
			</SelectWrapper>
		);

		if (!label && !description && !errorMessage) {
			return selectElement;
		}

		return (
			<SelectContainer theme={theme} fullWidth={fullWidth}>
				{label && labelPlacement === "outside" && (
					<Label theme={theme} isRequired={isRequired} size={size}>
						{label}
					</Label>
				)}
				{selectElement}
				{(description || errorMessage) && (
					<HelperText theme={theme} isError={!!errorMessage}>
						{errorMessage || description}
					</HelperText>
				)}
			</SelectContainer>
		);
	},
);

Select.displayName = "Select";
