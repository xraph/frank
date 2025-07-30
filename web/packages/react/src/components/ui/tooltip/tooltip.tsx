import { useTheme } from "@/theme/context";
import type { StyledProps } from "@/theme/styled";
import { css, keyframes } from "@emotion/react";
import styled from "@emotion/styled";
import React, { useState, useRef, useEffect, useCallback } from "react";
import { createPortal } from "react-dom";

export interface TooltipProps extends React.HTMLAttributes<HTMLDivElement> {
	/** Tooltip open state */
	isOpen?: boolean;
	/** Default open state */
	defaultOpen?: boolean;
	/** Open state change handler */
	onOpenChange?: (open: boolean) => void;
	/** Tooltip placement */
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
	/** Show delay in milliseconds */
	delay?: number;
	/** Hide delay in milliseconds */
	closeDelay?: number;
	/** Show arrow */
	showArrow?: boolean;
	/** Offset from trigger */
	offset?: number;
	/** Cross axis offset */
	crossOffset?: number;
	/** Disable tooltip */
	isDisabled?: boolean;
	/** Custom class name */
	className?: string;
	/** Custom styles */
	css?: any;
	/** Portal container */
	portalContainer?: Element;
	/** Trigger element */
	children?: React.ReactNode;
}

export interface TooltipTriggerProps
	extends React.HTMLAttributes<HTMLDivElement> {
	children: React.ReactNode;
	className?: string;
	css?: any;
	/** Accessibility label for the trigger */
	"aria-label"?: string;
}

export interface TooltipContentProps
	extends React.HTMLAttributes<HTMLDivElement> {
	children: React.ReactNode;
	className?: string;
	css?: any;
}

type StyledTooltipProps = StyledProps<TooltipProps>;

// Validation arrays for prop values
const VALID_PLACEMENTS = [
	"top",
	"top-start",
	"top-end",
	"bottom",
	"bottom-start",
	"bottom-end",
	"left",
	"left-start",
	"left-end",
	"right",
	"right-start",
	"right-end",
] as const;

// Helper function to validate placement
const validatePlacement = (placement: any): TooltipProps["placement"] => {
	return VALID_PLACEMENTS.includes(placement) ? placement : "top";
};

// Animation keyframes
const tooltipFadeIn = keyframes`
  from {
    opacity: 0;
    transform: scale(0.9);
  }
  to {
    opacity: 1;
    transform: scale(1);
  }
`;

const tooltipFadeOut = keyframes`
  from {
    opacity: 1;
    transform: scale(1);
  }
  to {
    opacity: 0;
    transform: scale(0.9);
  }
`;

const getTooltipPlacementStyles = (
	placement: TooltipProps["placement"],
	triggerRect: DOMRect | null,
	offset: number,
	crossOffset: number,
) => {
	if (!triggerRect) return {};

	const validatedPlacement = validatePlacement(placement);
	const styles: React.CSSProperties = {
		position: "absolute",
		zIndex: 1600, // Higher than popover
	};

	// Add viewport boundary checking
	const viewportPadding = 8;
	const maxWidth = Math.min(320, window.innerWidth - viewportPadding * 2);

	switch (validatedPlacement) {
		case "top":
			styles.bottom = `${window.innerHeight - triggerRect.top + offset}px`;
			styles.left = `${triggerRect.left + triggerRect.width / 2}px`;
			styles.transform = `translateX(-50%) translateX(${crossOffset}px)`;
			styles.maxWidth = `${maxWidth}px`;
			break;
		case "top-start":
			styles.bottom = `${window.innerHeight - triggerRect.top + offset}px`;
			styles.left = `${Math.max(viewportPadding, triggerRect.left + crossOffset)}px`;
			styles.maxWidth = `${maxWidth}px`;
			break;
		case "top-end":
			styles.bottom = `${window.innerHeight - triggerRect.top + offset}px`;
			styles.right = `${Math.max(viewportPadding, window.innerWidth - triggerRect.right - crossOffset)}px`;
			styles.maxWidth = `${maxWidth}px`;
			break;
		case "bottom":
			styles.top = `${triggerRect.bottom + offset}px`;
			styles.left = `${triggerRect.left + triggerRect.width / 2}px`;
			styles.transform = `translateX(-50%) translateX(${crossOffset}px)`;
			styles.maxWidth = `${maxWidth}px`;
			break;
		case "bottom-start":
			styles.top = `${triggerRect.bottom + offset}px`;
			styles.left = `${Math.max(viewportPadding, triggerRect.left + crossOffset)}px`;
			styles.maxWidth = `${maxWidth}px`;
			break;
		case "bottom-end":
			styles.top = `${triggerRect.bottom + offset}px`;
			styles.right = `${Math.max(viewportPadding, window.innerWidth - triggerRect.right - crossOffset)}px`;
			styles.maxWidth = `${maxWidth}px`;
			break;
		case "left":
			styles.right = `${window.innerWidth - triggerRect.left + offset}px`;
			styles.top = `${triggerRect.top + triggerRect.height / 2}px`;
			styles.transform = `translateY(-50%) translateY(${crossOffset}px)`;
			styles.maxWidth = `${maxWidth}px`;
			break;
		case "left-start":
			styles.right = `${window.innerWidth - triggerRect.left + offset}px`;
			styles.top = `${Math.max(viewportPadding, triggerRect.top + crossOffset)}px`;
			styles.maxWidth = `${maxWidth}px`;
			break;
		case "left-end":
			styles.right = `${window.innerWidth - triggerRect.left + offset}px`;
			styles.bottom = `${Math.max(viewportPadding, window.innerHeight - triggerRect.bottom - crossOffset)}px`;
			styles.maxWidth = `${maxWidth}px`;
			break;
		case "right":
			styles.left = `${triggerRect.right + offset}px`;
			styles.top = `${triggerRect.top + triggerRect.height / 2}px`;
			styles.transform = `translateY(-50%) translateY(${crossOffset}px)`;
			styles.maxWidth = `${maxWidth}px`;
			break;
		case "right-start":
			styles.left = `${triggerRect.right + offset}px`;
			styles.top = `${Math.max(viewportPadding, triggerRect.top + crossOffset)}px`;
			styles.maxWidth = `${maxWidth}px`;
			break;
		case "right-end":
			styles.left = `${triggerRect.right + offset}px`;
			styles.bottom = `${Math.max(viewportPadding, window.innerHeight - triggerRect.bottom - crossOffset)}px`;
			styles.maxWidth = `${maxWidth}px`;
			break;
		default:
			// Default to top
			styles.bottom = `${window.innerHeight - triggerRect.top + offset}px`;
			styles.left = `${triggerRect.left + triggerRect.width / 2}px`;
			styles.transform = `translateX(-50%) translateX(${crossOffset}px)`;
			styles.maxWidth = `${maxWidth}px`;
	}

	return styles;
};

const getTooltipArrowStyles = (placement: TooltipProps["placement"]) => {
	const validatedPlacement = validatePlacement(placement);
	const arrowSize = 6;

	switch (validatedPlacement) {
		case "top":
		case "top-start":
		case "top-end":
			return css`
        &::after {
          content: '';
          position: absolute;
          top: 100%;
          left: ${validatedPlacement === "top" ? "50%" : validatedPlacement === "top-start" ? "12px" : "auto"};
          right: ${validatedPlacement === "top-end" ? "12px" : "auto"};
          transform: ${validatedPlacement === "top" ? "translateX(-50%)" : "none"};
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
          left: ${validatedPlacement === "bottom" ? "50%" : validatedPlacement === "bottom-start" ? "12px" : "auto"};
          right: ${validatedPlacement === "bottom-end" ? "12px" : "auto"};
          transform: ${validatedPlacement === "bottom" ? "translateX(-50%)" : "none"};
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
          top: ${validatedPlacement === "left" ? "50%" : validatedPlacement === "left-start" ? "12px" : "auto"};
          bottom: ${validatedPlacement === "left-end" ? "12px" : "auto"};
          transform: ${validatedPlacement === "left" ? "translateY(-50%)" : "none"};
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
          top: ${validatedPlacement === "right" ? "50%" : validatedPlacement === "right-start" ? "12px" : "auto"};
          bottom: ${validatedPlacement === "right-end" ? "12px" : "auto"};
          transform: ${validatedPlacement === "right" ? "translateY(-50%)" : "none"};
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

const TooltipContent = styled.div<
	StyledTooltipProps & {
		isClosing?: boolean;
		placement?: TooltipProps["placement"];
		showArrow?: boolean;
	}
>`
  background-color: ${(props) => props.theme.colors.neutral[800]};
  color: ${(props) => props.theme.colors.neutral[50]};
  border-radius: ${(props) => props.theme.borderRadius.md};
  padding: ${(props) => props.theme.spacing[2]} ${(props) => props.theme.spacing[3]};
  font-size: ${(props) => props.theme.fontSizes.sm};
  line-height: ${(props) => props.theme.lineHeights.tight};
  max-width: 320px;
  word-wrap: break-word;
  box-shadow: ${(props) => props.theme.shadows.md};
  animation: ${(props) => (props.isClosing ? tooltipFadeOut : tooltipFadeIn)} 
    ${(props) => props.theme.transitions.fast};

  /* Arrow styles */
  ${(props) => props.showArrow && getTooltipArrowStyles(props.placement)}

  /* Ensure arrow uses the same color as background */
  &::after {
    color: ${(props) => props.theme.colors.neutral[800]};
  }

  /* Custom CSS prop */
  ${(props) => props.css}
`;

const TooltipTrigger = styled.div<StyledProps<TooltipTriggerProps>>`
  display: inline-block;

  /* Custom CSS prop */
  ${(props) => props.css}
`;

// Context for tooltip state
const TooltipContext = React.createContext<{
	isOpen: boolean;
	onOpenChange: (open: boolean) => void;
	triggerRef: React.RefObject<HTMLDivElement>;
	placement: TooltipProps["placement"];
	showArrow: boolean;
	offset: number;
	crossOffset: number;
	delay: number;
	closeDelay: number;
	isDisabled: boolean;
} | null>(null);

export const Tooltip: React.FC<TooltipProps> & {
	Trigger: React.FC<TooltipTriggerProps>;
	Content: React.FC<TooltipContentProps>;
} = ({
	children,
	isOpen: controlledOpen,
	defaultOpen = false,
	onOpenChange,
	placement = "top",
	delay = 700,
	closeDelay = 300,
	showArrow = true,
	offset = 8,
	crossOffset = 0,
	isDisabled = false,
	className,
	css,
	portalContainer,
	...props
}) => {
	const [internalOpen, setInternalOpen] = useState(defaultOpen);
	const triggerRef = useRef<HTMLDivElement>(null);
	const isControlled = controlledOpen !== undefined;
	const isOpen = isControlled ? controlledOpen : internalOpen;

	const validatedPlacement = validatePlacement(placement);
	const validatedDelay = typeof delay === "number" && delay >= 0 ? delay : 700;
	const validatedCloseDelay =
		typeof closeDelay === "number" && closeDelay >= 0 ? closeDelay : 300;

	const handleOpenChange = useCallback(
		(open: boolean) => {
			if (isDisabled) return;

			if (!isControlled) {
				setInternalOpen(open);
			}
			onOpenChange?.(open);
		},
		[isControlled, onOpenChange, isDisabled],
	);

	// Close on escape
	useEffect(() => {
		if (!isOpen || isDisabled) return;

		const handleEscape = (event: KeyboardEvent) => {
			if (event.key === "Escape") {
				handleOpenChange(false);
			}
		};

		document.addEventListener("keydown", handleEscape);
		return () => document.removeEventListener("keydown", handleEscape);
	}, [isOpen, handleOpenChange, isDisabled]);

	const contextValue = {
		isOpen,
		onOpenChange: handleOpenChange,
		triggerRef,
		placement: validatedPlacement,
		showArrow,
		offset,
		crossOffset,
		delay: validatedDelay,
		closeDelay: validatedCloseDelay,
		isDisabled,
	};

	return (
		<TooltipContext.Provider value={contextValue}>
			<div className={className} {...props}>
				{children}
			</div>
		</TooltipContext.Provider>
	);
};

const TooltipTriggerComponent: React.FC<TooltipTriggerProps> = ({
	children,
	className,
	css,
	"aria-label": ariaLabel,
	...props
}) => {
	const { theme } = useTheme();
	const context = React.useContext(TooltipContext);
	if (!context) {
		throw new Error("TooltipTrigger must be used within a Tooltip");
	}

	const { isOpen, onOpenChange, triggerRef, delay, closeDelay, isDisabled } =
		context;
	const showTimeoutRef = useRef<NodeJS.Timeout>();
	const hideTimeoutRef = useRef<NodeJS.Timeout>();

	const clearTimeouts = () => {
		if (showTimeoutRef.current) {
			clearTimeout(showTimeoutRef.current);
		}
		if (hideTimeoutRef.current) {
			clearTimeout(hideTimeoutRef.current);
		}
	};

	const handleMouseEnter = () => {
		if (isDisabled) return;

		clearTimeouts();
		showTimeoutRef.current = setTimeout(() => {
			onOpenChange(true);
		}, delay);
	};

	const handleMouseLeave = () => {
		if (isDisabled) return;

		clearTimeouts();
		hideTimeoutRef.current = setTimeout(() => {
			onOpenChange(false);
		}, closeDelay);
	};

	const handleFocus = () => {
		if (isDisabled) return;

		clearTimeouts();
		onOpenChange(true);
	};

	const handleBlur = () => {
		if (isDisabled) return;

		clearTimeouts();
		onOpenChange(false);
	};

	// Cleanup timeouts on unmount
	useEffect(() => {
		return () => clearTimeouts();
	}, []);

	return (
		<TooltipTrigger
			ref={triggerRef}
			theme={theme}
			className={className}
			css={css}
			onMouseEnter={handleMouseEnter}
			onMouseLeave={handleMouseLeave}
			onFocus={handleFocus}
			onBlur={handleBlur}
			aria-describedby={isOpen ? "tooltip-content" : undefined}
			aria-label={ariaLabel}
			{...props}
		>
			{children}
		</TooltipTrigger>
	);
};

const TooltipContentComponent: React.FC<TooltipContentProps> = ({
	children,
	className,
	css,
	...props
}) => {
	const { theme } = useTheme();
	const context = React.useContext(TooltipContext);
	if (!context) {
		throw new Error("TooltipContent must be used within a Tooltip");
	}

	const {
		isOpen,
		triggerRef,
		placement,
		showArrow,
		offset,
		crossOffset,
		isDisabled,
	} = context;
	const [triggerRect, setTriggerRect] = useState<DOMRect | null>(null);
	const [isClosing, setIsClosing] = useState(false);

	// Update trigger rect when tooltip opens
	useEffect(() => {
		if (isOpen && triggerRef.current && !isDisabled) {
			const updateRect = () => {
				setTriggerRect(triggerRef.current!.getBoundingClientRect());
			};

			updateRect();

			// Update on scroll/resize
			window.addEventListener("scroll", updateRect, true);
			window.addEventListener("resize", updateRect);

			return () => {
				window.removeEventListener("scroll", updateRect, true);
				window.removeEventListener("resize", updateRect);
			};
		}
	}, [isOpen, triggerRef, isDisabled]);

	// Handle closing animation
	useEffect(() => {
		if (!isOpen && triggerRect) {
			setIsClosing(true);
			const timer = setTimeout(() => {
				setIsClosing(false);
				setTriggerRect(null);
			}, 150); // Match animation duration
			return () => clearTimeout(timer);
		}
	}, [isOpen, triggerRect]);

	if ((!isOpen && !isClosing) || isDisabled) return null;

	const positionStyles = getTooltipPlacementStyles(
		placement,
		triggerRect,
		offset,
		crossOffset,
	);

	const container = document.body;

	const content = (
		<TooltipContent
			id="tooltip-content"
			theme={theme}
			data-tooltip-content
			className={className}
			css={css}
			placement={placement}
			showArrow={showArrow}
			isClosing={isClosing}
			style={positionStyles}
			role="tooltip"
			{...props}
		>
			{children}
		</TooltipContent>
	);

	return createPortal(content, container);
};

Tooltip.Trigger = TooltipTriggerComponent;
Tooltip.Content = TooltipContentComponent;

Tooltip.displayName = "Tooltip";
TooltipTriggerComponent.displayName = "TooltipTrigger";
TooltipContentComponent.displayName = "TooltipContent";
