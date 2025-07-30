import { createContext, useContext } from "react";
import type { Theme, ThemeMode } from "./theme";

export type ThemeContextType = {
	mode: ThemeMode;
	setMode: (mode: ThemeMode) => void;
	toggleMode: () => void;
	theme: Theme;
};

export const ThemeContext = createContext<ThemeContextType | undefined>(
	undefined,
);

export const useTheme = () => {
	const context = useContext(ThemeContext);
	if (context === undefined) {
		throw new Error("useTheme must be used within a ThemeProvider");
	}
	return context;
};
