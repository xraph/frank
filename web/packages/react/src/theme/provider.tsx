import { ThemeProvider as EmotionThemeProvider } from "@emotion/react";
import { Global, css } from "@emotion/react";
import type React from "react";
import { useEffect, useState } from "react";
import { ThemeContext } from "./context";
import { type Theme, type ThemeMode, createTheme } from "./theme";

const globalStyles = (theme: Theme) => css`
  // * {
  //   box-sizing: border-box;
  // }
  //
  // html,
  // body {
  //   margin: 0;
  //   padding: 0;
  //   font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', 'Roboto',
  //     'Oxygen', 'Ubuntu', 'Cantarell', 'Fira Sans', 'Droid Sans',
  //     'Helvetica Neue', sans-serif;
  //   -webkit-font-smoothing: antialiased;
  //   -moz-osx-font-smoothing: grayscale;
  //   background-color: ${theme.colors.background.primary};
  //   color: ${theme.colors.text.primary};
  //   font-size: ${theme.fontSizes.base};
  //   line-height: ${theme.lineHeights.normal};
  //   transition: background-color ${theme.transitions.normal}, color ${theme.transitions.normal};
  // }
  //
  // button {
  //   font-family: inherit;
  // }
  //
  // input,
  // textarea,
  // select {
  //   font-family: inherit;
  // }
  //
  // * {
  //   border: 0 solid ${theme.colors.border.primary};
  // }
  //
  // /* Scrollbar styling for dark mode */
  // ::-webkit-scrollbar {
  //   width: 8px;
  //   height: 8px;
  // }
  //
  // ::-webkit-scrollbar-track {
  //   background: ${theme.colors.background.secondary};
  // }
  //
  // ::-webkit-scrollbar-thumb {
  //   background: ${theme.colors.border.secondary};
  //   border-radius: 4px;
  // }
  //
  // ::-webkit-scrollbar-thumb:hover {
  //   background: ${theme.colors.border.tertiary};
  // }
`;

interface ThemeProviderProps {
	children: React.ReactNode;
	defaultMode?: ThemeMode;
	customTheme?: Partial<Theme>;
	enableSystem?: boolean;
	enableLocalStorage?: boolean;
	storageKey?: string;
}

export const ThemeProvider: React.FC<ThemeProviderProps> = ({
	children,
	defaultMode = "light",
	customTheme,
	enableSystem = true,
	enableLocalStorage = true,
	storageKey = "heroui-theme",
}) => {
	const [mode, setModeState] = useState<ThemeMode>(() => {
		// Check localStorage first
		if (enableLocalStorage && typeof window !== "undefined") {
			const stored = localStorage.getItem(storageKey) as ThemeMode;
			if (stored === "light" || stored === "dark") {
				return stored;
			}
		}

		// Check system preference
		if (enableSystem && typeof window !== "undefined") {
			const systemPrefersDark = window.matchMedia(
				"(prefers-color-scheme: dark)",
			).matches;
			return systemPrefersDark ? "dark" : "light";
		}

		return defaultMode;
	});

	const setMode = (newMode: ThemeMode) => {
		setModeState(newMode);
		if (enableLocalStorage && typeof window !== "undefined") {
			localStorage.setItem(storageKey, newMode);
		}
	};

	const toggleMode = () => {
		setMode(mode === "light" ? "dark" : "light");
	};

	// Listen to system theme changes
	useEffect(() => {
		if (!enableSystem) return;

		const mediaQuery = window.matchMedia("(prefers-color-scheme: dark)");
		const handleChange = (e: MediaQueryListEvent) => {
			// Only follow system if no manual preference is stored
			if (!enableLocalStorage || !localStorage.getItem(storageKey)) {
				setModeState(e.matches ? "dark" : "light");
			}
		};

		mediaQuery.addListener(handleChange);
		return () => mediaQuery.removeListener(handleChange);
	}, [enableSystem, enableLocalStorage, storageKey]);

	const theme = createTheme(mode);
	const mergedTheme = customTheme ? { ...theme, ...customTheme } : theme;

	const contextValue = {
		mode,
		setMode,
		toggleMode,
		theme: mergedTheme,
	};

	return (
		<ThemeContext.Provider value={contextValue}>
			<EmotionThemeProvider theme={mergedTheme}>
				<Global styles={globalStyles(mergedTheme)} />
				{children}
			</EmotionThemeProvider>
		</ThemeContext.Provider>
	);
};
