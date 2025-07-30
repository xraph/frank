export const colorTokens = {
	// Primary colors
	primary: {
		50: "#eff6ff",
		100: "#dbeafe",
		200: "#bfdbfe",
		300: "#93c5fd",
		400: "#60a5fa",
		500: "#3b82f6",
		600: "#2563eb",
		700: "#1d4ed8",
		800: "#1e40af",
		900: "#1e3a8a",
	},
	// Secondary colors
	secondary: {
		50: "#f8fafc",
		100: "#f1f5f9",
		200: "#e2e8f0",
		300: "#cbd5e1",
		400: "#94a3b8",
		500: "#64748b",
		600: "#475569",
		700: "#334155",
		800: "#1e293b",
		900: "#0f172a",
	},
	// Success colors
	success: {
		50: "#f0fdf4",
		100: "#dcfce7",
		200: "#bbf7d0",
		300: "#86efac",
		400: "#4ade80",
		500: "#22c55e",
		600: "#16a34a",
		700: "#15803d",
		800: "#166534",
		900: "#14532d",
	},
	// Warning colors
	warning: {
		50: "#fffbeb",
		100: "#fef3c7",
		200: "#fde68a",
		300: "#fcd34d",
		400: "#fbbf24",
		500: "#f59e0b",
		600: "#d97706",
		700: "#b45309",
		800: "#92400e",
		900: "#78350f",
	},
	// Danger colors
	danger: {
		50: "#fef2f2",
		100: "#fee2e2",
		200: "#fecaca",
		300: "#fca5a5",
		400: "#f87171",
		500: "#ef4444",
		600: "#dc2626",
		700: "#b91c1c",
		800: "#991b1b",
		900: "#7f1d1d",
	},
	// Neutral colors
	neutral: {
		50: "#fafafa",
		100: "#f4f4f5",
		200: "#e4e4e7",
		300: "#d4d4d8",
		400: "#a1a1aa",
		500: "#71717a",
		600: "#52525b",
		700: "#3f3f46",
		800: "#27272a",
		900: "#18181b",
	},
};

const lightThemeColors = {
	...colorTokens,
	// Background colors
	background: {
		primary: "#ffffff",
		secondary: "#f8fafc",
		tertiary: "#f1f5f9",
	},
	// Content colors
	content: {
		primary: "#0f172a",
		secondary: "#475569",
		tertiary: "#64748b",
		quaternary: "#94a3b8",
		inverse: "#ffffff",
	},
	// Foreground colors (alias for content)
	foreground: {
		primary: "#0f172a",
		secondary: "#475569",
		tertiary: "#64748b",
		quaternary: "#94a3b8",
		inverse: "#ffffff",
	},
	// Text colors (alias for content)
	text: {
		primary: "#0f172a",
		secondary: "#475569",
		tertiary: "#64748b",
		quaternary: "#94a3b8",
		inverse: "#ffffff",
	},
	// Border colors
	border: {
		primary: "#e2e8f0",
		secondary: "#cbd5e1",
		tertiary: "#94a3b8",
		focus: "#3b82f6",
	},
	// Divider colors
	divider: {
		primary: "#e2e8f0",
		secondary: "#cbd5e1",
	},
	// Overlay colors
	overlay: {
		primary: "rgba(0, 0, 0, 0.5)",
		secondary: "rgba(0, 0, 0, 0.3)",
	},
};

const darkThemeColors = {
	...colorTokens,
	// Background colors
	background: {
		primary: "#0f172a",
		secondary: "#1e293b",
		tertiary: "#334155",
	},
	// Content colors
	content: {
		primary: "#f8fafc",
		secondary: "#e2e8f0",
		tertiary: "#cbd5e1",
		quaternary: "#94a3b8",
		inverse: "#0f172a",
	},
	// Foreground colors (alias for content)
	foreground: {
		primary: "#f8fafc",
		secondary: "#e2e8f0",
		tertiary: "#cbd5e1",
		quaternary: "#94a3b8",
		inverse: "#0f172a",
	},
	// Text colors (alias for content)
	text: {
		primary: "#f8fafc",
		secondary: "#e2e8f0",
		tertiary: "#cbd5e1",
		quaternary: "#94a3b8",
		inverse: "#0f172a",
	},
	// Border colors
	border: {
		primary: "#334155",
		secondary: "#475569",
		tertiary: "#64748b",
		focus: "#60a5fa",
	},
	// Divider colors
	divider: {
		primary: "#334155",
		secondary: "#475569",
	},
	// Overlay colors
	overlay: {
		primary: "rgba(0, 0, 0, 0.7)",
		secondary: "rgba(0, 0, 0, 0.5)",
	},
};

export const tokens = {
	colors: {
		light: lightThemeColors,
		dark: darkThemeColors,
	},
	spacing: {
		0: "0px",
		1: "0.25rem",
		2: "0.5rem",
		3: "0.75rem",
		4: "1rem",
		5: "1.25rem",
		6: "1.5rem",
		8: "2rem",
		10: "2.5rem",
		12: "3rem",
		16: "4rem",
		20: "5rem",
		24: "6rem",
		32: "8rem",
	},
	fontSizes: {
		xs: "0.75rem",
		sm: "0.875rem",
		base: "1rem",
		lg: "1.125rem",
		xl: "1.25rem",
		"2xl": "1.5rem",
		"3xl": "1.875rem",
		"4xl": "2.25rem",
	},
	fontWeights: {
		light: 300,
		normal: 400,
		medium: 500,
		semibold: 600,
		bold: 700,
	},
	lineHeights: {
		tight: 1.25,
		normal: 1.5,
		relaxed: 1.75,
	},
	borderRadius: {
		none: "0px",
		sm: "0.125rem",
		base: "0.25rem",
		md: "0.375rem",
		lg: "0.5rem",
		xl: "0.75rem",
		"2xl": "1rem",
		full: "9999px",
	},
	shadows: {
		xs: "0 1px 2px 0 rgb(0 0 0 / 0.05)",
		sm: "0 1px 3px 0 rgb(0 0 0 / 0.1), 0 1px 2px -1px rgb(0 0 0 / 0.1)",
		base: "0 4px 6px -1px rgb(0 0 0 / 0.1), 0 2px 4px -2px rgb(0 0 0 / 0.1)",
		md: "0 10px 15px -3px rgb(0 0 0 / 0.1), 0 4px 6px -4px rgb(0 0 0 / 0.1)",
		lg: "0 20px 25px -5px rgb(0 0 0 / 0.1), 0 8px 10px -6px rgb(0 0 0 / 0.1)",
		xl: "0 25px 50px -12px rgb(0 0 0 / 0.25)",
	},
	transitions: {
		fast: "150ms ease-in-out",
		normal: "200ms ease-in-out",
		slow: "300ms ease-in-out",
	},
	zIndex: {
		hide: -1,
		auto: "auto",
		base: 0,
		docked: 10,
		dropdown: 1000,
		sticky: 1100,
		banner: 1200,
		overlay: 1300,
		modal: 1400,
		popover: 1500,
		tooltip: 1600,
		toast: 1700,
	},
};
