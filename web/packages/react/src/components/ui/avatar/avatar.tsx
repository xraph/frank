import { useTheme } from "@/theme/context";
import { type StyledProps, getColorVariant } from "@/theme/styled";
import { css } from "@emotion/react";
import styled from "@emotion/styled";
import React, { useState, useEffect } from "react";

export interface AvatarProps extends React.HTMLAttributes<HTMLDivElement> {
	/** Avatar source - image URL */
	src?: string;
	/** Alt text for image */
	alt?: string;
	/** Name to generate initials from */
	name?: string;
	/** Avatar size */
	size?: "xs" | "sm" | "md" | "lg" | "xl";
	/** Avatar color theme (for initials background) */
	color?: "primary" | "secondary" | "success" | "warning" | "danger";
	/** Avatar radius */
	radius?: "none" | "sm" | "md" | "lg" | "full";
	/** Show border */
	isBordered?: boolean;
	/** Disabled state */
	isDisabled?: boolean;
	/** Fallback icon when no image or name */
	fallback?: React.ReactNode;
	/** Status indicator */
	showStatus?: boolean;
	/** Status color */
	statusColor?: "primary" | "secondary" | "success" | "warning" | "danger";
	/** Status placement */
	statusPlacement?: "top-right" | "top-left" | "bottom-right" | "bottom-left";
	/** Custom class name */
	className?: string;
	/** Custom styles */
	css?: any;
	/** Image loading error callback */
	onError?: () => void;
}

type StyledAvatarProps = StyledProps<AvatarProps>;

const getAvatarSizeStyles = (props: StyledAvatarProps) => {
	const { theme, size = "md" } = props;

	switch (size) {
		case "xs":
			return css`
        width: ${theme.spacing[6]};
        height: ${theme.spacing[6]};
        font-size: ${theme.fontSizes.xs};
      `;
		case "sm":
			return css`
        width: ${theme.spacing[8]};
        height: ${theme.spacing[8]};
        font-size: ${theme.fontSizes.sm};
      `;
		case "md":
			return css`
        width: ${theme.spacing[10]};
        height: ${theme.spacing[10]};
        font-size: ${theme.fontSizes.base};
      `;
		case "lg":
			return css`
        width: ${theme.spacing[12]};
        height: ${theme.spacing[12]};
        font-size: ${theme.fontSizes.lg};
      `;
		case "xl":
			return css`
        width: ${theme.spacing[16]};
        height: ${theme.spacing[16]};
        font-size: ${theme.fontSizes.xl};
      `;
		default:
			return css``;
	}
};

const getAvatarRadiusStyles = (props: StyledAvatarProps) => {
	const { theme, radius = "full" } = props;

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
			return css`border-radius: ${theme.borderRadius.full};`;
	}
};

const getAvatarColorStyles = (props: StyledAvatarProps) => {
	const { theme, color = "primary", isDisabled } = props;
	const baseColor = getColorVariant(theme, color, 500);
	const lightColor = getColorVariant(theme, color, 100);
	const darkColor = getColorVariant(theme, color, 700);

	if (isDisabled) {
		return css`
      opacity: 0.5;
      cursor: not-allowed;
    `;
	}

	return css`
    background-color: ${lightColor};
    color: ${darkColor};
  `;
};

const StyledAvatar = styled.div<StyledAvatarProps>`
  position: relative;
  display: inline-flex;
  align-items: center;
  justify-content: center;
  font-family: inherit;
  font-weight: ${(props) => props.theme.fontWeights.medium};
  line-height: ${(props) => props.theme.lineHeights.tight};
  user-select: none;
  overflow: hidden;
  flex-shrink: 0;
  transition: all ${(props) => props.theme.transitions.normal};

  ${getAvatarSizeStyles}
  ${getAvatarRadiusStyles}
  ${getAvatarColorStyles}

  ${(props) =>
		props.isBordered &&
		css`
      border: 2px solid ${props.theme.colors.border.primary};
    `}

  /* Custom CSS prop */
  ${(props) => props.css}
`;

const AvatarImage = styled.img<StyledAvatarProps>`
  width: 100%;
  height: 100%;
  object-fit: cover;
  ${getAvatarRadiusStyles}
`;

const AvatarInitials = styled.span`
  font-weight: ${(props) => props.theme.fontWeights.semibold};
  text-transform: uppercase;
`;

const AvatarFallback = styled.div`
  display: flex;
  align-items: center;
  justify-content: center;
  width: 100%;
  height: 100%;
  color: ${(props) => props.theme.colors.text.tertiary};
`;

const StatusIndicator = styled.div<
	StyledAvatarProps & {
		statusColor: string;
		statusPlacement: string;
		size: string;
	}
>`
  position: absolute;
  border: 2px solid ${(props) => props.theme.colors.background.primary};
  border-radius: ${(props) => props.theme.borderRadius.full};
  background-color: ${(props) => {
		const color = props.statusColor || "success";
		return getColorVariant(props.theme, color as any, 500);
	}};

  ${(props) => {
		const sizeMap = {
			xs: "8px",
			sm: "10px",
			md: "12px",
			lg: "14px",
			xl: "16px",
		};
		const size = sizeMap[props.size as keyof typeof sizeMap] || "12px";

		return css`
      width: ${size};
      height: ${size};
    `;
	}}

  ${(props) => {
		switch (props.statusPlacement) {
			case "top-right":
				return css`
          top: 0;
          right: 0;
          transform: translate(25%, -25%);
        `;
			case "top-left":
				return css`
          top: 0;
          left: 0;
          transform: translate(-25%, -25%);
        `;
			case "bottom-right":
				return css`
          bottom: 0;
          right: 0;
          transform: translate(25%, 25%);
        `;
			case "bottom-left":
				return css`
          bottom: 0;
          left: 0;
          transform: translate(-25%, 25%);
        `;
			default:
				return css`
          bottom: 0;
          right: 0;
          transform: translate(25%, 25%);
        `;
		}
	}}
`;

// Default fallback icon
const DefaultFallbackIcon = () => (
	<svg width="60%" height="60%" viewBox="0 0 24 24" fill="currentColor">
		<path d="M12 12c2.21 0 4-1.79 4-4s-1.79-4-4-4-4 1.79-4 4 1.79 4 4 4zm0 2c-2.67 0-8 1.34-8 4v2h16v-2c0-2.66-5.33-4-8-4z" />
	</svg>
);

// Function to generate initials from name
const getInitials = (name: string): string => {
	return name
		.split(" ")
		.map((word) => word.charAt(0))
		.join("")
		.slice(0, 2)
		.toUpperCase();
};

export const Avatar = React.forwardRef<HTMLDivElement, AvatarProps>(
	(
		{
			src,
			alt,
			name,
			size = "md",
			color = "primary",
			radius = "full",
			isBordered = false,
			isDisabled = false,
			fallback,
			showStatus = false,
			statusColor = "success",
			statusPlacement = "bottom-right",
			className,
			css,
			onError,
			...props
		},
		ref,
	) => {
		const { theme } = useTheme();
		const [imageError, setImageError] = useState(false);
		const [imageLoaded, setImageLoaded] = useState(false);

		// Reset image error state when src changes
		useEffect(() => {
			setImageError(false);
			setImageLoaded(false);
		}, [src]);

		const handleImageError = () => {
			setImageError(true);
			onError?.();
		};

		const handleImageLoad = () => {
			setImageLoaded(true);
		};

		const avatarProps = {
			...props,
			size,
			color,
			radius,
			isBordered,
			isDisabled,
			className,
			css,
		};

		const renderContent = () => {
			// Show image if src exists and no error
			if (src && !imageError) {
				return (
					<AvatarImage
						theme={theme}
						src={src}
						alt={alt || name}
						radius={radius}
						onError={handleImageError}
						onLoad={handleImageLoad}
						style={{
							opacity: imageLoaded ? 1 : 0,
							transition: theme.transitions.normal,
						}}
					/>
				);
			}

			// Show initials if name exists
			if (name) {
				return (
					<AvatarInitials theme={theme}>{getInitials(name)}</AvatarInitials>
				);
			}

			// Show custom fallback or default icon
			return (
				<AvatarFallback theme={theme}>
					{fallback || <DefaultFallbackIcon />}
				</AvatarFallback>
			);
		};

		return (
			<StyledAvatar theme={theme} ref={ref} {...avatarProps}>
				{renderContent()}
				{showStatus && (
					<StatusIndicator
						theme={theme}
						statusColor={statusColor}
						statusPlacement={statusPlacement}
						size={size}
					/>
				)}
			</StyledAvatar>
		);
	},
);

Avatar.displayName = "Avatar";

// Avatar Group Component
export interface AvatarGroupProps extends React.HTMLAttributes<HTMLDivElement> {
	/** Maximum number of avatars to show */
	max?: number;
	/** Avatar size for all children */
	size?: "xs" | "sm" | "md" | "lg" | "xl";
	/** Spacing between avatars (negative for overlap) */
	spacing?: number;
	/** Show border on avatars */
	isBordered?: boolean;
	/** Avatar radius for all children */
	radius?: "none" | "sm" | "md" | "lg" | "full";
	/** Custom class name */
	className?: string;
	/** Custom styles */
	css?: any;
	/** Children avatars */
	children: React.ReactNode;
}

const StyledAvatarGroup = styled.div<StyledProps<AvatarGroupProps>>`
  display: flex;
  align-items: center;

  ${(props) => props.css}
`;

const AvatarGroupItem = styled.div<{ spacing: number; index: number }>`
  position: relative;
  margin-left: ${(props) => (props.index > 0 ? `${props.spacing}px` : "0")};

  &:hover {
    z-index: 1;
  }
`;

const ExtraAvatarsCount = styled(StyledAvatar)`
  background-color: ${(props) => props.theme.colors.neutral[200]};
  color: ${(props) => props.theme.colors.text.secondary};
  font-weight: ${(props) => props.theme.fontWeights.semibold};
`;

export const AvatarGroup = React.forwardRef<HTMLDivElement, AvatarGroupProps>(
	(
		{
			children,
			max = 5,
			size = "md",
			spacing = -8,
			isBordered = false,
			radius = "full",
			className,
			css,
			...props
		},
		ref,
	) => {
		const { theme } = useTheme();
		const childrenArray = React.Children.toArray(children);
		const visibleChildren = childrenArray.slice(0, max);
		const extraCount = Math.max(0, childrenArray.length - max);

		const groupProps = {
			...props,
			className,
			css,
		};

		return (
			<StyledAvatarGroup theme={theme} ref={ref} {...groupProps}>
				{visibleChildren.map((child, index) => {
					if (React.isValidElement(child)) {
						const avatarProps = {
							size,
							isBordered,
							radius,
							...child.props,
						};

						return (
							<AvatarGroupItem key={index} spacing={spacing} index={index}>
								{React.cloneElement(child, avatarProps)}
							</AvatarGroupItem>
						);
					}
					return child;
				})}

				{extraCount > 0 && (
					<AvatarGroupItem spacing={spacing} index={visibleChildren.length}>
						<ExtraAvatarsCount
							theme={theme}
							size={size}
							radius={radius}
							isBordered={isBordered}
						>
							+{extraCount}
						</ExtraAvatarsCount>
					</AvatarGroupItem>
				)}
			</StyledAvatarGroup>
		);
	},
);

AvatarGroup.displayName = "AvatarGroup";
