import { useTheme } from "@/theme/context";
import type { StyledProps } from "@/theme/styled";
import type { Theme } from "@/theme/theme";
import { css, keyframes } from "@emotion/react";
import styled from "@emotion/styled";
import React, { useEffect, useRef, useCallback } from "react";
import { createPortal } from "react-dom";

export interface ModalProps extends React.HTMLAttributes<HTMLDivElement> {
	/** Modal open state */
	isOpen?: boolean;
	/** Close modal callback */
	onClose?: () => void;
	/** Modal size */
	size?:
		| "xs"
		| "sm"
		| "md"
		| "lg"
		| "xl"
		| "2xl"
		| "3xl"
		| "4xl"
		| "5xl"
		| "full";
	/** Modal radius */
	radius?: "none" | "sm" | "md" | "lg" | "xl";
	/** Modal placement */
	placement?:
		| "auto"
		| "top"
		| "top-center"
		| "center"
		| "bottom"
		| "bottom-center";
	/** Hide close button */
	hideCloseButton?: boolean;
	/** Close on backdrop click */
	isDismissable?: boolean;
	/** Close on escape key */
	isKeyboardDismissDisabled?: boolean;
	/** Disable scroll lock */
	scrollBehavior?: "inside" | "outside" | "normal";
	/** Modal backdrop blur */
	backdrop?: "transparent" | "opaque" | "blur";
	/** Custom class name */
	className?: string;
	/** Custom styles */
	css?: any;
	/** Portal container */
	portalContainer?: Element;
}

type StyledModalProps = StyledProps<ModalProps>;

// Animation keyframes
const fadeIn = keyframes`
  from {
    opacity: 0;
  }
  to {
    opacity: 1;
  }
`;

const fadeOut = keyframes`
  from {
    opacity: 1;
  }
  to {
    opacity: 0;
  }
`;

const scaleIn = keyframes`
  from {
    opacity: 0;
    transform: scale(0.95);
  }
  to {
    opacity: 1;
    transform: scale(1);
  }
`;

const scaleOut = keyframes`
  from {
    opacity: 1;
    transform: scale(1);
  }
  to {
    opacity: 0;
    transform: scale(0.95);
  }
`;

const getModalSizeStyles = (props: StyledModalProps) => {
	const { theme, size = "md" } = props;

	switch (size) {
		case "xs":
			return css`
        max-width: 320px;
        width: 90vw;
      `;
		case "sm":
			return css`
        max-width: 400px;
        width: 90vw;
      `;
		case "md":
			return css`
        max-width: 512px;
        width: 90vw;
      `;
		case "lg":
			return css`
        max-width: 640px;
        width: 90vw;
      `;
		case "xl":
			return css`
        max-width: 768px;
        width: 90vw;
      `;
		case "2xl":
			return css`
        max-width: 896px;
        width: 90vw;
      `;
		case "3xl":
			return css`
        max-width: 1024px;
        width: 90vw;
      `;
		case "4xl":
			return css`
        max-width: 1152px;
        width: 90vw;
      `;
		case "5xl":
			return css`
        max-width: 1280px;
        width: 90vw;
      `;
		case "full":
			return css`
        width: 100vw;
        height: 100vh;
        max-width: none;
        max-height: none;
        border-radius: 0;
        margin: 0;
      `;
		default:
			return css`
        max-width: 512px;
        width: 90vw;
      `;
	}
};

const getModalRadiusStyles = (props: StyledModalProps) => {
	const { theme, radius = "lg", size } = props;

	if (size === "full") return css``;

	switch (radius) {
		case "none":
			return css`border-radius: ${theme.borderRadius.none};`;
		case "sm":
			return css`border-radius: ${theme.borderRadius.sm};`;
		case "md":
			return css`border-radius: ${theme.borderRadius.md};`;
		case "lg":
			return css`border-radius: ${theme.borderRadius.lg};`;
		case "xl":
			return css`border-radius: ${theme.borderRadius.xl};`;
		default:
			return css`border-radius: ${theme.borderRadius.lg};`;
	}
};

const getModalPlacementStyles = (props: StyledModalProps) => {
	const { placement = "center", size } = props;

	if (size === "full") {
		return css`
      justify-content: center;
      align-items: center;
    `;
	}

	switch (placement) {
		case "top":
			return css`
        justify-content: flex-start;
        align-items: flex-start;
        padding-top: 3rem;
      `;
		case "top-center":
			return css`
        justify-content: center;
        align-items: flex-start;
        padding-top: 3rem;
      `;
		case "center":
			return css`
        justify-content: center;
        align-items: center;
      `;
		case "bottom":
			return css`
        justify-content: flex-start;
        align-items: flex-end;
        padding-bottom: 3rem;
      `;
		case "bottom-center":
			return css`
        justify-content: center;
        align-items: flex-end;
        padding-bottom: 3rem;
      `;
		default:
			return css`
        justify-content: center;
        align-items: center;
        
        @media (max-height: 640px) {
          align-items: flex-start;
          padding-top: 2rem;
          padding-bottom: 2rem;
        }
      `;
	}
};

const getBackdropStyles = (props: StyledModalProps) => {
	const { theme, backdrop = "opaque" } = props;

	switch (backdrop) {
		case "transparent":
			return css`
        background-color: transparent;
      `;
		case "opaque":
			return css`
        background-color: rgba(0, 0, 0, 0.5);
      `;
		case "blur":
			return css`
        background-color: rgba(0, 0, 0, 0.3);
        backdrop-filter: blur(4px);
      `;
		default:
			return css`
        background-color: rgba(0, 0, 0, 0.5);
      `;
	}
};

const ModalOverlay = styled.div<StyledModalProps & { isClosing?: boolean }>`
  position: fixed;
  top: 0;
  left: 0;
  right: 0;
  bottom: 0;
  z-index: ${(props) => props.theme.zIndex.modal};
  display: flex;
  padding: ${(props) => props.theme.spacing[4]};
  animation: ${(props) => (props.isClosing ? fadeOut : fadeIn)} 
    ${(props) => props.theme.transitions.normal};

  ${getBackdropStyles}
  ${getModalPlacementStyles}

  /* Custom CSS prop */
  ${(props) => props.css}
`;

const ModalContent = styled.div<
	StyledModalProps & {
		isClosing?: boolean;
		scrollBehavior?: "inside" | "outside" | "normal";
	}
>`
  position: relative;
  background-color: ${(props) => props.theme.colors.background.primary};
  box-shadow: ${(props) => props.theme.shadows.xl};
  display: flex;
  flex-direction: column;
  outline: none;
  animation: ${(props) => (props.isClosing ? scaleOut : scaleIn)} 
    ${(props) => props.theme.transitions.normal};
  
  ${getModalSizeStyles}
  ${getModalRadiusStyles}

  ${(props) =>
		props.scrollBehavior === "inside" &&
		css`
    max-height: calc(100vh - 2 * ${props.theme.spacing[4]});
    overflow: hidden;
  `}

  ${(props) =>
		props.scrollBehavior === "outside" &&
		css`
    max-height: none;
    overflow: visible;
  `}
`;

const CloseButton = styled.button<{ theme: Theme }>`
  position: absolute;
  top: ${(props) => props.theme.spacing[4]};
  right: ${(props) => props.theme.spacing[4]};
  background: none;
  border: none;
  cursor: pointer;
  padding: ${(props) => props.theme.spacing[2]};
  border-radius: ${(props) => props.theme.borderRadius.sm};
  color: ${(props) => props.theme.colors.text.secondary};
  transition: all ${(props) => props.theme.transitions.fast};
  z-index: 10;
  width: 32px;
  height: 32px;
  display: flex;
  align-items: center;
  justify-content: center;

  &:hover {
    background-color: ${(props) => props.theme.colors.neutral[100]};
    color: ${(props) => props.theme.colors.text.primary};
  }

  &:focus {
    outline: 2px solid ${(props) => props.theme.colors.border.focus};
    outline-offset: 2px;
  }
`;

const CloseIcon = () => (
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
		<line x1="18" y1="6" x2="6" y2="18" />
		<line x1="6" y1="6" x2="18" y2="18" />
	</svg>
);

export const Modal = React.forwardRef<HTMLDivElement, ModalProps>(
	(
		{
			children,
			isOpen = false,
			onClose,
			size = "md",
			radius = "lg",
			placement = "auto",
			hideCloseButton = false,
			isDismissable = true,
			isKeyboardDismissDisabled = false,
			scrollBehavior = "normal",
			backdrop = "opaque",
			className,
			css,
			portalContainer,
			...props
		},
		ref,
	) => {
		const { theme } = useTheme();
		const modalRef = useRef<HTMLDivElement>(null);
		const overlayRef = useRef<HTMLDivElement>(null);

		// Handle escape key
		const handleKeyDown = useCallback(
			(event: KeyboardEvent) => {
				if (!isKeyboardDismissDisabled && event.key === "Escape" && isOpen) {
					onClose?.();
				}
			},
			[isOpen, onClose, isKeyboardDismissDisabled],
		);

		// Handle backdrop click
		const handleOverlayClick = useCallback(
			(event: React.MouseEvent) => {
				if (isDismissable && event.target === overlayRef.current) {
					onClose?.();
				}
			},
			[isDismissable, onClose],
		);

		// Focus management
		useEffect(() => {
			if (isOpen && modalRef.current) {
				modalRef.current.focus();
			}
		}, [isOpen]);

		// Scroll lock
		useEffect(() => {
			if (isOpen && scrollBehavior !== "normal") {
				const originalStyle = window.getComputedStyle(document.body).overflow;
				document.body.style.overflow = "hidden";

				return () => {
					document.body.style.overflow = originalStyle;
				};
			}
		}, [isOpen, scrollBehavior]);

		// Keyboard event listener
		useEffect(() => {
			if (isOpen) {
				document.addEventListener("keydown", handleKeyDown);
				return () => document.removeEventListener("keydown", handleKeyDown);
			}
		}, [isOpen, handleKeyDown]);

		const modalProps = {
			...props,
			size,
			radius,
			placement,
			backdrop,
			scrollBehavior,
			className,
			theme,
			css,
		};

		if (!isOpen) {
			return null;
		}

		const modalContent = (
			<ModalOverlay
				ref={overlayRef}
				onClick={handleOverlayClick}
				{...modalProps}
			>
				<ModalContent
					ref={modalRef}
					tabIndex={-1}
					role="dialog"
					aria-modal="true"
					{...modalProps}
				>
					{!hideCloseButton && (
						<CloseButton
							theme={theme}
							onClick={onClose}
							aria-label="Close modal"
						>
							<CloseIcon />
						</CloseButton>
					)}
					{children}
				</ModalContent>
			</ModalOverlay>
		);

		// Use portal if container provided, otherwise render directly
		const container = portalContainer || document.body;
		return createPortal(modalContent, container);
	},
);

Modal.displayName = "Modal";

// Modal subcomponents
export interface ModalHeaderProps extends React.HTMLAttributes<HTMLDivElement> {
	className?: string;
	css?: any;
}

export const ModalHeader = styled.div<StyledProps<ModalHeaderProps>>`
  display: flex;
  flex-direction: column;
  gap: ${(props) => props.theme.spacing[2]};
  padding: ${(props) => props.theme.spacing[6]} ${(props) => props.theme.spacing[6]} 0;
  padding-right: ${(props) => props.theme.spacing[12]}; /* Space for close button */

  ${(props) => props.css}
`;

export interface ModalBodyProps extends React.HTMLAttributes<HTMLDivElement> {
	className?: string;
	css?: any;
}

export const ModalBody = styled.div<
	StyledProps<ModalBodyProps> & {
		scrollBehavior?: "inside" | "outside" | "normal";
	}
>`
  display: flex;
  flex-direction: column;
  gap: ${(props) => props.theme.spacing[4]};
  padding: ${(props) => props.theme.spacing[6]};
  flex: 1;
  
  ${(props) =>
		props.scrollBehavior === "inside" &&
		css`
    overflow-y: auto;
    max-height: none;
  `}

  ${(props) => props.css}
`;

export interface ModalFooterProps extends React.HTMLAttributes<HTMLDivElement> {
	className?: string;
	css?: any;
}

export const ModalFooter = styled.div<StyledProps<ModalFooterProps>>`
  display: flex;
  flex-direction: row;
  justify-content: flex-end;
  align-items: center;
  gap: ${(props) => props.theme.spacing[3]};
  padding: 0 ${(props) => props.theme.spacing[6]} ${(props) => props.theme.spacing[6]};

  ${(props) => props.css}
`;
