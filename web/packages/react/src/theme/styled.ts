import styled from "@emotion/styled";
import type { Theme } from "./theme";

// Utility type for getting theme from props
export type StyledProps<T = Record<any, any>> = T & { theme: Theme };

// Helper function to create responsive styles
export const responsive = (
	styles: Record<string, any>,
	breakpoints = {
		sm: "640px",
		md: "768px",
		lg: "1024px",
		xl: "1280px",
	},
) => {
	return Object.entries(styles).map(([key, value]) => {
		if (key === "base") {
			return value;
		}
		const breakpoint = breakpoints[key as keyof typeof breakpoints];
		return `@media (min-width: ${breakpoint}) { ${value} }`;
	});
};

// Color variant utilities
export const getColorVariant = (
	theme: Theme,
	variant:
		| "primary"
		| "secondary"
		| "success"
		| "warning"
		| "danger" = "primary",
	shade: keyof typeof theme.colors.primary = 500,
) => {
	switch (variant) {
		case "primary":
			return theme.colors.primary[shade];
		case "secondary":
			return theme.colors.secondary[shade];
		case "success":
			return theme.colors.success[shade];
		case "warning":
			return theme.colors.warning[shade];
		case "danger":
			return theme.colors.danger[shade];
		default:
			return theme.colors.primary[shade];
	}
};

export default styled;
