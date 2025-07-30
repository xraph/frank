import { useTheme } from "@/theme/context";
import { type StyledProps, getColorVariant } from "@/theme/styled";
import { css } from "@emotion/react";
import styled from "@emotion/styled";
import React from "react";

export interface LinkProps
	extends React.AnchorHTMLAttributes<HTMLAnchorElement> {
	/** Link color theme */
	color?:
		| "primary"
		| "secondary"
		| "success"
		| "warning"
		| "danger"
		| "foreground";
	/** Link size */
	size?: "sm" | "md" | "lg";
	/** Link underline behavior */
	underline?: "none" | "hover" | "always" | "active" | "focus";
	/** Link variant */
	variant?: "solid" | "underlined" | "light";
	/** External link indicator */
	isExternal?: boolean;
	/** Disabled state */
	isDisabled?: boolean;
	/** Block level link */
	isBlock?: boolean;
	/** Custom class name */
	className?: string;
	/** Custom styles */
	css?: any;
}

type StyledLinkProps = StyledProps<LinkProps>;

const getLinkColorStyles = (props: StyledLinkProps) => {
	const { theme, color = "primary", variant = "solid", isDisabled } = props;

	if (isDisabled) {
		return css`
      color: ${theme.colors.text.tertiary};
      cursor: not-allowed;
      pointer-events: none;
      opacity: 0.5;
    `;
	}

	if (color === "foreground") {
		return css`
      color: ${theme.colors.text.primary};

      &:hover {
        opacity: 0.8;
      }

      &:active {
        opacity: 0.6;
      }
    `;
	}

	const baseColor = getColorVariant(theme, color, 500);
	const hoverColor = getColorVariant(theme, color, 600);
	const activeColor = getColorVariant(theme, color, 700);
	const lightColor = getColorVariant(theme, color, 50);

	switch (variant) {
		case "solid":
			return css`
        color: ${baseColor};

        &:hover {
          color: ${hoverColor};
        }

        &:active {
          color: ${activeColor};
        }
      `;

		case "underlined":
			return css`
        color: ${baseColor};
        text-decoration: underline;
        text-underline-offset: 2px;

        &:hover {
          color: ${hoverColor};
        }

        &:active {
          color: ${activeColor};
        }
      `;

		case "light":
			return css`
        color: ${baseColor};
        background-color: transparent;
        padding: ${theme.spacing[1]} ${theme.spacing[2]};
        border-radius: ${theme.borderRadius.sm};

        &:hover {
          background-color: ${lightColor};
        }

        &:active {
          background-color: ${getColorVariant(theme, color, 100)};
        }
      `;

		default:
			return css``;
	}
};

const getLinkSizeStyles = (props: StyledLinkProps) => {
	const { theme, size = "md" } = props;

	switch (size) {
		case "sm":
			return css`
        font-size: ${theme.fontSizes.sm};
      `;
		case "md":
			return css`
        font-size: ${theme.fontSizes.base};
      `;
		case "lg":
			return css`
        font-size: ${theme.fontSizes.lg};
      `;
		default:
			return css`
        font-size: ${theme.fontSizes.base};
      `;
	}
};

const getLinkUnderlineStyles = (props: StyledLinkProps) => {
	const { underline = "hover" } = props;

	switch (underline) {
		case "none":
			return css`
        text-decoration: none;

        &:hover {
          text-decoration: none;
        }
      `;

		case "hover":
			return css`
        text-decoration: none;

        &:hover {
          text-decoration: underline;
          text-underline-offset: 2px;
        }
      `;

		case "always":
			return css`
        text-decoration: underline;
        text-underline-offset: 2px;
      `;

		case "active":
			return css`
        text-decoration: none;

        &:active {
          text-decoration: underline;
          text-underline-offset: 2px;
        }
      `;

		case "focus":
			return css`
        text-decoration: none;

        &:focus {
          text-decoration: underline;
          text-underline-offset: 2px;
        }
      `;

		default:
			return css``;
	}
};

const StyledLink = styled.a<StyledLinkProps>`
  display: ${(props) => (props.isBlock ? "block" : "inline-flex")};
  align-items: center;
  gap: ${(props) => props.theme.spacing[1]};
  font-family: inherit;
  font-weight: ${(props) => props.theme.fontWeights.medium};
  line-height: ${(props) => props.theme.lineHeights.normal};
  cursor: pointer;
  transition: all ${(props) => props.theme.transitions.fast};
  position: relative;
  outline: none;

  &:focus-visible {
    outline: 2px solid ${(props) => props.theme.colors.border.focus};
    outline-offset: 2px;
    border-radius: ${(props) => props.theme.borderRadius.sm};
  }

  ${getLinkColorStyles}
  ${getLinkSizeStyles}
  ${getLinkUnderlineStyles}

  /* Custom CSS prop */
  ${(props) => props.css}
`;

const ExternalIcon = styled.svg<{ size?: "sm" | "md" | "lg" }>`
  width: ${(props) => {
		switch (props.size) {
			case "sm":
				return "12px";
			case "lg":
				return "18px";
			default:
				return "14px";
		}
	}};
  height: ${(props) => {
		switch (props.size) {
			case "sm":
				return "12px";
			case "lg":
				return "18px";
			default:
				return "14px";
		}
	}};
  opacity: 0.7;
`;

export const Link = React.forwardRef<HTMLAnchorElement, LinkProps>(
	(
		{
			children,
			color = "primary",
			size = "md",
			underline = "hover",
			variant = "solid",
			isExternal = false,
			isDisabled = false,
			isBlock = false,
			className,
			css,
			href,
			target,
			rel,
			...props
		},
		ref,
	) => {
		const { theme } = useTheme();

		// Auto-detect external links
		const isExternalLink =
			isExternal ||
			(href &&
				(href.startsWith("http") ||
					href.startsWith("mailto:") ||
					href.startsWith("tel:")));

		const linkProps = {
			...props,
			color,
			size,
			underline,
			variant,
			isDisabled,
			isBlock,
			className,
			css,
			href: isDisabled ? undefined : href,
			target: isExternalLink ? "_blank" : target,
			rel: isExternalLink ? "noopener noreferrer" : rel,
		};

		return (
			<StyledLink theme={theme} ref={ref} {...linkProps}>
				{children}
				{isExternalLink && !isDisabled && (
					<ExternalIcon
						size={size}
						viewBox="0 0 24 24"
						fill="none"
						stroke="currentColor"
						strokeWidth="2"
						strokeLinecap="round"
						strokeLinejoin="round"
					>
						<path d="M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6" />
						<polyline points="15,3 21,3 21,9" />
						<line x1="10" y1="14" x2="21" y2="3" />
					</ExternalIcon>
				)}
			</StyledLink>
		);
	},
);

Link.displayName = "Link";
