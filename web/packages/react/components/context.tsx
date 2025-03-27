"use client";

import type {ReactNode} from "react";
import React, {createContext} from "react";
import {Key} from "lucide-react";
import {
	AuthVerifyEmailError,
	client,
	SendEmailVerificationRequestBody,
	SendEmailVerificationResponseBody,
	SendResponseBody,
	User,
	VerifyEmailRequest
} from "@frank-auth/sdk";

// Define types for the FrankAuth configuration
export type AuthMethod = "password" | "passwordless" | "passkey" | "mfa";
export type AuthView =
	| "login"
	| "signup"
	| "forgot-password"
	| "verify-otp"
	| "mfa";
export type AuthTabs = AuthView; //"login" | "signup" | "mfa"
export type FieldType =
	| "text"
	| "email"
	| "password"
	| "tel"
	| "number"
	| "checkbox"
	| "select";

export interface FormField {
	name: string;
	label: string;
	type: FieldType;
	placeholder?: string;
	required?: boolean;
	isFirstName?: boolean;
	isLastName?: boolean;
	isEmail?: boolean;
	options?: { value: string; label: string }[]; // For select fields
	validation?: {
		pattern?: string;
		minLength?: number;
		maxLength?: number;
		min?: number;
		max?: number;
	};
	row?: string | number;
	width?: "full" | "half" | "third";
}

export interface Link {
	preText?: string;
	text: string;
	url: string;
}

export interface LegalLink extends Link {
	// Extending the base Link interface for legal links
}

export interface ThemeConfig {
	primaryColor?: string;
	backgroundColor?: string;
	textColor?: string;
	borderRadius?: string;
}

export type ThemeConfigPreset = ThemeConfig | keyof typeof themePresets;

export interface OAuthProvider {
	name: string;
	icon: ReactNode;
	onClick: () => void;
}

export interface Session {
	user: User | null;
	expires?: string;
	accessToken?: string;
	refreshToken?: string;
	[key: string]: any; // Allow for additional custom properties
}

// Define theme presets
export const themePresets = {
	default: {
		primaryColor: "bg-primary",
		backgroundColor: "bg-background",
		textColor: "text-foreground",
		borderRadius: "rounded-md",
	},
	blue: {
		primaryColor: "bg-blue-600 hover:bg-blue-700",
		backgroundColor: "bg-background",
		textColor: "text-foreground",
		borderRadius: "rounded-md",
	},
	green: {
		primaryColor: "bg-emerald-600 hover:bg-emerald-700",
		backgroundColor: "bg-background",
		textColor: "text-foreground",
		borderRadius: "rounded-md",
	},
	purple: {
		primaryColor: "bg-purple-600 hover:bg-purple-700",
		backgroundColor: "bg-background",
		textColor: "text-foreground",
		borderRadius: "rounded-md",
	},
	dark: {
		primaryColor: "bg-slate-800 hover:bg-slate-900",
		backgroundColor: "bg-slate-950",
		textColor: "text-white",
		borderRadius: "rounded-md",
	},
};

export interface FrankConfig {
	logo?: ReactNode;
	title?: string;
	titleAlign?: "left" | "center" | "right";
	description?: string;
	oauthProviders?: OAuthProvider[];
	onLogin?: (data: any) => Promise<boolean>;
	onSignup?: (data: any) => Promise<void>;
	onPasswordless?: (email: string) => Promise<void>;
	onPasskey?: () => Promise<void>;
	onMfa?: (code: string) => Promise<void>;
	onForgotPassword?: (email: string) => Promise<void>;
	onVerifyOtp?: (otp: string, email: string) => Promise<void>;
	onResendVerification?: (email: string) => Promise<void>;
	supportedMethods?: AuthMethod[];
	showTabs?: boolean;
	availableTabs?: AuthTabs[];
	initialView?: AuthView;
	signupFields?: FormField[];
	verification?: {
		input?: "otp" | "input";
		codeLength?: number;
	};
	links?: {
		showAuthLinks?: boolean;
		login?: Link;
		legal?: LegalLink[];
		signup?: Link;
		verify?: Link;
		mfa?: Link;
		forgotPassword?: Link;
		redirectAfterLogin?: string;
	};
	theme?: ThemeConfigPreset;

	api?: {
		baseUrl?: string;
		projectId?: string;
		secret?: string;
	};
}

// Create the context with default values
export const FrankContext = createContext<{
	config: FrankConfig;
	updateConfig: (newConfig: Partial<FrankConfig>) => void;
	getTheme: (theme?: ThemeConfigPreset) => ThemeConfig;
	client: typeof client;
	session: Session | null;
	user: User | null;
	isLoading: boolean;
	isAuthenticated: boolean;
	signIn: (credentials: any) => Promise<boolean>;
	signOut: () => Promise<void>;
	resendVerification: (data: SendEmailVerificationRequestBody) => Promise<{data: SendEmailVerificationResponseBody, error: undefined} | {}>;
	verifyEmail: (data: VerifyEmailRequest) => Promise<{data: SendResponseBody, error: undefined} | {data: undefined, error: AuthVerifyEmailError}>;
	updateSession: (newSession: Session | null) => void;
	updateUser: (newUser: User | null) => void;
	resendCooldown: number; // Cooldown time in seconds
}>({
	config: {
		logo: <Key className="h-6 w-6" />,
		title: "Welcome Back",
		description: "Sign in to your account",
		oauthProviders: [],
		supportedMethods: ["password", "passwordless", "passkey"],
		showTabs: true,
		availableTabs: ["login", "signup"],
		initialView: "login",
		signupFields: [
			{
				name: "name",
				label: "Name",
				type: "text",
				placeholder: "John Doe",
				required: true,
			},
			{
				name: "email",
				label: "Email",
				type: "email",
				placeholder: "name@example.com",
				required: true,
			},
			{ name: "password", label: "Password", type: "password", required: true },
		],
		theme: {
			primaryColor: "bg-primary",
			backgroundColor: "bg-background",
			textColor: "text-foreground",
			borderRadius: "rounded-md",
		},
		verification: {
			codeLength: 6,
			input: "otp",
		},
	},
	updateConfig: () => {},
	getTheme: (theme?: ThemeConfigPreset) => {
		if (!theme) return themePresets.default;

		if (typeof theme === "string") {
			return themePresets[theme] ?? themePresets.default;
		}
		return theme ?? themePresets.default;
	},
	client: client,
	session: null,
	user: null,
	isLoading: true,
	resendCooldown: 60,
	isAuthenticated: false,
	signIn: async () => false,
	signOut: async () => {},
	updateSession: () => {},
	updateUser: () => {},
	// @ts-ignore
	resendVerification: () => {},
	// @ts-ignore
	verifyEmail: () => {}
});
