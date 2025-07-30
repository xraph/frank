import { useTheme } from "@/theme/context";
import { type StyledProps, getColorVariant } from "@/theme/styled";
import { css } from "@emotion/react";
import styled from "@emotion/styled";
import React from "react";

export interface BadgeProps extends React.HTMLAttributes<HTMLSpanElement> {
  /** Badge variant */
  variant?: "solid" | "flat" | "bordered" | "shadow" | "dot";
  /** Badge color theme */
  color?: "primary" | "secondary" | "success" | "warning" | "danger";
  /** Badge size */
  size?: "sm" | "md" | "lg";
  /** Badge content */
  content?: React.ReactNode | number | string;
  /** Maximum count to display (shows count+ when exceeded) */
  max?: number;
  /** Show badge as dot without content */
  isDot?: boolean;
  /** Hide badge when content is 0 or empty */
  showZero?: boolean;
  /** Badge placement relative to children */
  placement?: "top-right" | "top-left" | "bottom-right" | "bottom-left";
  /** Disable badge */
  isDisabled?: boolean;
  /** Badge shape */
  shape?: "rectangle" | "circle";
  /** Custom class name */
  className?: string;
  /** Custom styles */
  css?: any;
  /** Children to wrap with badge */
  children?: React.ReactNode;
}

type StyledBadgeProps = StyledProps<BadgeProps>;

const getBadgeVariantStyles = (props: StyledBadgeProps) => {
  const { theme, variant = "solid", color = "primary", isDisabled } = props;
  const baseColor = getColorVariant(theme, color, 500);
  const lightColor = getColorVariant(theme, color, 50);
  const darkColor = getColorVariant(theme, color, 700);

  if (isDisabled) {
    return css`
      opacity: 0.5;
      cursor: not-allowed;
    `;
  }

  switch (variant) {
    case "solid":
      return css`
        background-color: ${baseColor};
        color: ${theme.colors.text.inverse};
        border: 1px solid transparent;
      `;

    case "flat":
      return css`
        background-color: ${getColorVariant(theme, color, 100)};
        color: ${baseColor};
        border: 1px solid transparent;
      `;

    case "bordered":
      return css`
        background-color: ${theme.colors.background.primary};
        color: ${baseColor};
        border: 1px solid ${baseColor};
      `;

    case "shadow":
      return css`
        background-color: ${baseColor};
        color: ${theme.colors.text.inverse};
        border: 1px solid transparent;
        box-shadow: ${theme.shadows.sm};
      `;

    case "dot":
      return css`
        background-color: ${baseColor};
        border: 2px solid ${theme.colors.background.primary};
        width: 8px;
        height: 8px;
        padding: 0;
        min-width: 8px;
      `;

    default:
      return css``;
  }
};

const getBadgeSizeStyles = (props: StyledBadgeProps) => {
  const { theme, size = "md", variant, shape = "rectangle" } = props;

  if (variant === "dot") {
    switch (size) {
      case "sm":
        return css`
          width: 6px;
          height: 6px;
          min-width: 6px;
        `;
      case "md":
        return css`
          width: 8px;
          height: 8px;
          min-width: 8px;
        `;
      case "lg":
        return css`
          width: 10px;
          height: 10px;
          min-width: 10px;
        `;
    }
  }

  const isCircle = shape === "circle";

  switch (size) {
    case "sm":
      return css`
        min-width: ${isCircle ? theme.spacing[4] : theme.spacing[4]};
        height: ${theme.spacing[4]};
        padding: ${isCircle ? "0" : `0 ${theme.spacing[1]}`};
        font-size: ${theme.fontSizes.xs};
      `;
    case "md":
      return css`
        min-width: ${isCircle ? theme.spacing[5] : theme.spacing[5]};
        height: ${theme.spacing[5]};
        padding: ${isCircle ? "0" : `0 ${theme.spacing[2]}`};
        font-size: ${theme.fontSizes.xs};
      `;
    case "lg":
      return css`
        min-width: ${isCircle ? theme.spacing[6] : theme.spacing[6]};
        height: ${theme.spacing[6]};
        padding: ${isCircle ? "0" : `0 ${theme.spacing[2]}`};
        font-size: ${theme.fontSizes.sm};
      `;
    default:
      return css``;
  }
};

const getBadgeShapeStyles = (props: StyledBadgeProps) => {
  const { theme, shape = "rectangle", variant } = props;

  if (variant === "dot") {
    return css`border-radius: ${theme.borderRadius.full};`;
  }

  switch (shape) {
    case "circle":
      return css`border-radius: ${theme.borderRadius.full};`;
    case "rectangle":
      return css`border-radius: ${theme.borderRadius.sm};`;
    default:
      return css`border-radius: ${theme.borderRadius.sm};`;
  }
};

const StyledBadge = styled.span<StyledBadgeProps>`
  display: inline-flex;
  align-items: center;
  justify-content: center;
  font-family: inherit;
  font-weight: ${(props) => props.theme.fontWeights.medium};
  line-height: ${(props) => props.theme.lineHeights.tight};
  white-space: nowrap;
  user-select: none;
  transition: all ${(props) => props.theme.transitions.normal};
  box-sizing: border-box;

  ${getBadgeVariantStyles}
  ${getBadgeSizeStyles}
  ${getBadgeShapeStyles}

    /* Custom CSS prop */
  ${(props) => props.css}
`;

const BadgeWrapper = styled.span<{ placement: string }>`
  position: relative;
  display: inline-flex;

  ${StyledBadge} {
    position: absolute;
    z-index: ${(props) => props.theme.zIndex.docked};

    ${(props) => {
      switch (props.placement) {
        case "top-right":
          return css`
            top: 0;
            right: 0;
            transform: translate(50%, -50%);
          `;
        case "top-left":
          return css`
            top: 0;
            left: 0;
            transform: translate(-50%, -50%);
          `;
        case "bottom-right":
          return css`
            bottom: 0;
            right: 0;
            transform: translate(50%, 50%);
          `;
        case "bottom-left":
          return css`
            bottom: 0;
            left: 0;
            transform: translate(-50%, 50%);
          `;
        default:
          return css`
            top: 0;
            right: 0;
            transform: translate(50%, -50%);
          `;
      }
    }}
  }
`;

export const Badge = React.forwardRef<HTMLSpanElement, BadgeProps>(
  (
    {
      children,
      content,
      variant = "solid",
      color = "primary",
      size = "md",
      max = 99,
      isDot = false,
      showZero = false,
      placement = "top-right",
      isDisabled = false,
      shape = "rectangle",
      className,
      css,
      ...props
    },
    ref,
  ) => {
    const { theme } = useTheme();

    // Determine if badge should be shown
    const shouldShowBadge = () => {
      if (isDot) return true;
      if (content === 0 || content === "0") return showZero;
      return content !== undefined && content !== null && content !== "";
    };

    // Format badge content
    const getBadgeContent = () => {
      if (isDot || variant === "dot") return null;

      if (typeof content === "number") {
        return content > max ? `${max}+` : content.toString();
      }

      return content;
    };

    const badgeProps = {
      ...props,
      variant: isDot ? "dot" : variant,
      color,
      size,
      shape: isDot ? "circle" : shape,
      isDisabled,
      className,
      css,
    };

    const badgeElement = shouldShowBadge() ? (
      <StyledBadge theme={theme} ref={ref} {...badgeProps}>
        {getBadgeContent()}
      </StyledBadge>
    ) : null;

    // If no children, return just the badge
    if (!children) {
      return badgeElement;
    }

    // If children exist, wrap them with positioned badge
    return (
      <BadgeWrapper theme={theme} placement={placement}>
        {children}
        {badgeElement}
      </BadgeWrapper>
    );
  },
);

Badge.displayName = "Badge";