import { tokens } from "./tokens";

export type ThemeMode = "light" | "dark";

export interface Theme {
	colors: typeof tokens.colors.light;
	spacing: typeof tokens.spacing;
	fontSizes: typeof tokens.fontSizes;
	fontWeights: typeof tokens.fontWeights;
	lineHeights: typeof tokens.lineHeights;
	borderRadius: typeof tokens.borderRadius;
	shadows: typeof tokens.shadows;
	transitions: typeof tokens.transitions;
	zIndex: typeof tokens.zIndex;
}

export const createTheme = (mode: ThemeMode = "light"): Theme => ({
	colors: tokens.colors[mode],
	spacing: tokens.spacing,
	fontSizes: tokens.fontSizes,
	fontWeights: tokens.fontWeights,
	lineHeights: tokens.lineHeights,
	borderRadius: tokens.borderRadius,
	shadows: tokens.shadows,
	transitions: tokens.transitions,
	zIndex: tokens.zIndex,
});

export const lightTheme = createTheme("light");
export const darkTheme = createTheme("dark");
