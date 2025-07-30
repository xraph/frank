import { useTheme } from "@/theme/context";
import type { StyledProps } from "@/theme/styled";
import { css, keyframes } from "@emotion/react";
import styled from "@emotion/styled";
import React, { useState, useRef, useEffect, useCallback } from "react";
import { createPortal } from "react-dom";

export interface PopoverProps extends React.HTMLAttributes<HTMLDivElement> {
	/** Popover open state */
	isOpen?: boolean;
	/** Default open state */
	defaultOpen?: boolean;
	/** Open state change handler */
	onOpenChange?: (open: boolean) => void;
	/** Popover placement */
	placement?:
		| "top"
		| "top-start"
		| "top-end"
		| "bottom"
		| "bottom-start"
		| "bottom-end"
		| "left"
		| "left-start"
		| "left-end"
		| "right"
		| "right-start"
		| "right-end";
	/** Popover trigger */
	trigger?: "click" | "hover" | "focus" | "manual";
	/** Show arrow */
	showArrow?: boolean;
	/** Offset from trigger */
	offset?: number;
	/** Cross axis offset */
	crossOffset?: number;
	/** Close on blur */
	shouldCloseOnBlur?: boolean;
	/** Close on interaction outside */
	shouldCloseOnInteractOutside?: boolean;
	/** Backdrop type */
	backdrop?: "transparent" | "opaque" | "blur";
	/** Custom class name */
	className?: string;
	/** Custom styles */
	css?: any;
	/** Portal container */
	portalContainer?: Element;
	/** Trigger element */
	children?: React.ReactNode;
}

export interface PopoverTriggerProps
	extends React.HTMLAttributes<HTMLDivElement> {
	children: React.ReactNode;
	className?: string;
	css?: any;
}

export interface PopoverContentProps
	extends React.HTMLAttributes<HTMLDivElement> {
	children: React.ReactNode;
	className?: string;
	css?: any;
}

type StyledPopoverProps = StyledProps<PopoverProps>;

// Animation keyframes
const fadeIn = keyframes`
  from {
    opacity: 0;
    transform: scale(0.95);
  }
  to {
    opacity: 1;
    transform: scale(1);
  }
`;

const fadeOut = keyframes`
  from {
    opacity: 1;
    transform: scale(1);
  }
  to {
    opacity: 0;
    transform: scale(0.95);
  }
`;

const getPopoverPlacementStyles = (
	placement: PopoverProps["placement"],
	triggerRect: DOMRect | null,
	offset: number,
	crossOffset: number,
) => {
	if (!triggerRect) return {};

	const styles: React.CSSProperties = {
		position: "absolute",
		zIndex: 1500,
	};

	switch (placement) {
		case "top":
			styles.bottom = `${window.innerHeight - triggerRect.top + offset}px`;
			styles.left = `${triggerRect.left + triggerRect.width / 2}px`;
			styles.transform = `translateX(-50%) translateX(${crossOffset}px)`;
			break;
		case "top-start":
			styles.bottom = `${window.innerHeight - triggerRect.top + offset}px`;
			styles.left = `${triggerRect.left + crossOffset}px`;
			break;
		case "top-end":
			styles.bottom = `${window.innerHeight - triggerRect.top + offset}px`;
			styles.right = `${window.innerWidth - triggerRect.right - crossOffset}px`;
			break;
		case "bottom":
			styles.top = `${triggerRect.bottom + offset}px`;
			styles.left = `${triggerRect.left + triggerRect.width / 2}px`;
			styles.transform = `translateX(-50%) translateX(${crossOffset}px)`;
			break;
		case "bottom-start":
			styles.top = `${triggerRect.bottom + offset}px`;
			styles.left = `${triggerRect.left + crossOffset}px`;
			break;
		case "bottom-end":
			styles.top = `${triggerRect.bottom + offset}px`;
			styles.right = `${window.innerWidth - triggerRect.right - crossOffset}px`;
			break;
		case "left":
			styles.right = `${window.innerWidth - triggerRect.left + offset}px`;
			styles.top = `${triggerRect.top + triggerRect.height / 2}px`;
			styles.transform = `translateY(-50%) translateY(${crossOffset}px)`;
			break;
		case "left-start":
			styles.right = `${window.innerWidth - triggerRect.left + offset}px`;
			styles.top = `${triggerRect.top + crossOffset}px`;
			break;
		case "left-end":
			styles.right = `${window.innerWidth - triggerRect.left + offset}px`;
			styles.bottom = `${window.innerHeight - triggerRect.bottom - crossOffset}px`;
			break;
		case "right":
			styles.left = `${triggerRect.right + offset}px`;
			styles.top = `${triggerRect.top + triggerRect.height / 2}px`;
			styles.transform = `translateY(-50%) translateY(${crossOffset}px)`;
			break;
		case "right-start":
			styles.left = `${triggerRect.right + offset}px`;
			styles.top = `${triggerRect.top + crossOffset}px`;
			break;
		case "right-end":
			styles.left = `${triggerRect.right + offset}px`;
			styles.bottom = `${window.innerHeight - triggerRect.bottom - crossOffset}px`;
			break;
		default:
			// Default to bottom
			styles.top = `${triggerRect.bottom + offset}px`;
			styles.left = `${triggerRect.left + triggerRect.width / 2}px`;
			styles.transform = `translateX(-50%) translateX(${crossOffset}px)`;
	}

	return styles;
};

const getArrowStyles = (placement: PopoverProps["placement"]) => {
	const arrowSize = 8;

	switch (placement) {
		case "top":
		case "top-start":
		case "top-end":
			return css`
        &::after {
          content: '';
          position: absolute;
          top: 100%;
          left: ${placement === "top" ? "50%" : placement === "top-start" ? "16px" : "auto"};
          right: ${placement === "top-end" ? "16px" : "auto"};
          transform: ${placement === "top" ? "translateX(-50%)" : "none"};
          width: 0;
          height: 0;
          border-left: ${arrowSize}px solid transparent;
          border-right: ${arrowSize}px solid transparent;
          border-top: ${arrowSize}px solid currentColor;
        }
      `;
		case "bottom":
		case "bottom-start":
		case "bottom-end":
			return css`
        &::after {
          content: '';
          position: absolute;
          bottom: 100%;
          left: ${placement === "bottom" ? "50%" : placement === "bottom-start" ? "16px" : "auto"};
          right: ${placement === "bottom-end" ? "16px" : "auto"};
          transform: ${placement === "bottom" ? "translateX(-50%)" : "none"};
          width: 0;
          height: 0;
          border-left: ${arrowSize}px solid transparent;
          border-right: ${arrowSize}px solid transparent;
          border-bottom: ${arrowSize}px solid currentColor;
        }
      `;
		case "left":
		case "left-start":
		case "left-end":
			return css`
        &::after {
          content: '';
          position: absolute;
          left: 100%;
          top: ${placement === "left" ? "50%" : placement === "left-start" ? "16px" : "auto"};
          bottom: ${placement === "left-end" ? "16px" : "auto"};
          transform: ${placement === "left" ? "translateY(-50%)" : "none"};
          width: 0;
          height: 0;
          border-top: ${arrowSize}px solid transparent;
          border-bottom: ${arrowSize}px solid transparent;
          border-left: ${arrowSize}px solid currentColor;
        }
      `;
		case "right":
		case "right-start":
		case "right-end":
			return css`
        &::after {
          content: '';
          position: absolute;
          right: 100%;
          top: ${placement === "right" ? "50%" : placement === "right-start" ? "16px" : "auto"};
          bottom: ${placement === "right-end" ? "16px" : "auto"};
          transform: ${placement === "right" ? "translateY(-50%)" : "none"};
          width: 0;
          height: 0;
          border-top: ${arrowSize}px solid transparent;
          border-bottom: ${arrowSize}px solid transparent;
          border-right: ${arrowSize}px solid currentColor;
        }
      `;
		default:
			return css``;
	}
};

const getBackdropStyles = (props: StyledPopoverProps) => {
	const { theme, backdrop = "transparent" } = props;

	switch (backdrop) {
		case "transparent":
			return css`
        background-color: transparent;
      `;
		case "opaque":
			return css`
        background-color: rgba(0, 0, 0, 0.1);
      `;
		case "blur":
			return css`
        background-color: rgba(0, 0, 0, 0.05);
        backdrop-filter: blur(2px);
      `;
		default:
			return css`
        background-color: transparent;
      `;
	}
};

const PopoverBackdrop = styled.div<StyledPopoverProps>`
  position: fixed;
  top: 0;
  left: 0;
  right: 0;
  bottom: 0;
  z-index: ${(props) => props.theme.zIndex.overlay};

  ${getBackdropStyles}
`;

const PopoverContent = styled.div<
	StyledPopoverProps & {
		isClosing?: boolean;
		placement?: PopoverProps["placement"];
		showArrow?: boolean;
	}
>`
  background-color: ${(props) => props.theme.colors.background.primary};
  border: 1px solid ${(props) => props.theme.colors.border.primary};
  border-radius: ${(props) => props.theme.borderRadius.lg};
  box-shadow: ${(props) => props.theme.shadows.lg};
  padding: ${(props) => props.theme.spacing[4]};
  max-width: 320px;
  animation: ${(props) => (props.isClosing ? fadeOut : fadeIn)} 
    ${(props) => props.theme.transitions.fast};
  color: ${(props) => props.theme.colors.background.primary};

  ${(props) => props.showArrow && getArrowStyles(props.placement)}

  /* Custom CSS prop */
  ${(props) => props.css}
`;

const PopoverTrigger = styled.div<StyledProps<PopoverTriggerProps>>`
  display: inline-block;
  cursor: pointer;

  /* Custom CSS prop */
  ${(props) => props.css}
`;

// Context for popover state
const PopoverContext = React.createContext<{
	isOpen: boolean;
	onOpenChange: (open: boolean) => void;
	triggerRef: React.RefObject<HTMLDivElement>;
	placement: PopoverProps["placement"];
	trigger: PopoverProps["trigger"];
	showArrow: boolean;
	offset: number;
	crossOffset: number;
} | null>(null);

export const Popover: React.FC<PopoverProps> & {
	Trigger: React.FC<PopoverTriggerProps>;
	Content: React.FC<PopoverContentProps>;
} = ({
	children,
	isOpen: controlledOpen,
	defaultOpen = false,
	onOpenChange,
	placement = "bottom",
	trigger = "click",
	showArrow = true,
	offset = 8,
	crossOffset = 0,
	shouldCloseOnBlur = true,
	shouldCloseOnInteractOutside = true,
	backdrop = "transparent",
	className,
	css,
	portalContainer,
	...props
}) => {
	const [internalOpen, setInternalOpen] = useState(defaultOpen);
	const triggerRef = useRef<HTMLDivElement>(null);
	const isControlled = controlledOpen !== undefined;
	const isOpen = isControlled ? controlledOpen : internalOpen;

	const handleOpenChange = useCallback(
		(open: boolean) => {
			if (!isControlled) {
				setInternalOpen(open);
			}
			onOpenChange?.(open);
		},
		[isControlled, onOpenChange],
	);

	// Close on click outside
	useEffect(() => {
		if (!isOpen || !shouldCloseOnInteractOutside) return;

		const handleClickOutside = (event: MouseEvent) => {
			if (
				triggerRef.current &&
				!triggerRef.current.contains(event.target as Node)
			) {
				const popoverContent = document.querySelector("[data-popover-content]");
				if (popoverContent && !popoverContent.contains(event.target as Node)) {
					handleOpenChange(false);
				}
			}
		};

		document.addEventListener("mousedown", handleClickOutside);
		return () => document.removeEventListener("mousedown", handleClickOutside);
	}, [isOpen, shouldCloseOnInteractOutside, handleOpenChange]);

	// Close on escape
	useEffect(() => {
		if (!isOpen) return;

		const handleEscape = (event: KeyboardEvent) => {
			if (event.key === "Escape") {
				handleOpenChange(false);
			}
		};

		document.addEventListener("keydown", handleEscape);
		return () => document.removeEventListener("keydown", handleEscape);
	}, [isOpen, handleOpenChange]);

	const contextValue = {
		isOpen,
		onOpenChange: handleOpenChange,
		triggerRef,
		placement,
		trigger,
		showArrow,
		offset,
		crossOffset,
	};

	return (
		<PopoverContext.Provider value={contextValue}>
			<div className={className} {...props}>
				{children}
			</div>
		</PopoverContext.Provider>
	);
};

const PopoverTriggerComponent: React.FC<PopoverTriggerProps> = ({
	children,
	className,
	css,
	...props
}) => {
	const { theme } = useTheme();
	const context = React.useContext(PopoverContext);
	if (!context) {
		throw new Error("PopoverTrigger must be used within a Popover");
	}

	const { isOpen, onOpenChange, triggerRef, trigger } = context;

	const handleClick = () => {
		if (trigger === "click") {
			onOpenChange(!isOpen);
		}
	};

	const handleMouseEnter = () => {
		if (trigger === "hover") {
			onOpenChange(true);
		}
	};

	const handleMouseLeave = () => {
		if (trigger === "hover") {
			onOpenChange(false);
		}
	};

	const handleFocus = () => {
		if (trigger === "focus") {
			onOpenChange(true);
		}
	};

	const handleBlur = () => {
		if (trigger === "focus") {
			onOpenChange(false);
		}
	};

	return (
		<PopoverTrigger
			ref={triggerRef}
			theme={theme}
			className={className}
			css={css}
			onClick={handleClick}
			onMouseEnter={handleMouseEnter}
			onMouseLeave={handleMouseLeave}
			onFocus={handleFocus}
			onBlur={handleBlur}
			{...props}
		>
			{children}
		</PopoverTrigger>
	);
};

const PopoverContentComponent: React.FC<PopoverContentProps> = ({
	children,
	className,
	css,
	...props
}) => {
	const { theme } = useTheme();
	const context = React.useContext(PopoverContext);
	if (!context) {
		throw new Error("PopoverContent must be used within a Popover");
	}

	const { isOpen, triggerRef, placement, showArrow, offset, crossOffset } =
		context;

	const [triggerRect, setTriggerRect] = useState<DOMRect | null>(null);

	useEffect(() => {
		if (isOpen && triggerRef.current) {
			setTriggerRect(triggerRef.current.getBoundingClientRect());
		}
	}, [isOpen, triggerRef]);

	if (!isOpen) return null;

	const positionStyles = getPopoverPlacementStyles(
		placement,
		triggerRect,
		offset,
		crossOffset,
	);

	const container = document.body;

	const content = (
		<>
			{context && <PopoverBackdrop theme={theme} />}
			<PopoverContent
				theme={theme}
				data-popover-content
				className={className}
				css={css}
				placement={placement}
				showArrow={showArrow}
				style={positionStyles}
				{...props}
			>
				{children}
			</PopoverContent>
		</>
	);

	return createPortal(content, container);
};

Popover.Trigger = PopoverTriggerComponent;
Popover.Content = PopoverContentComponent;

Popover.displayName = "Popover";
PopoverTriggerComponent.displayName = "PopoverTrigger";
PopoverContentComponent.displayName = "PopoverContent";
