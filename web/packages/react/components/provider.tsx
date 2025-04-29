'use client'

// Create the provider component
import React, {ReactNode, useCallback, useState} from "react";
import {Key} from "lucide-react";
import {
	authSendEmailVerification,
	authVerifyEmail,
	client,
	SendEmailVerificationRequestBody,
	User,
	VerifyEmailRequest,
} from "@frank-auth/sdk";
import {FrankConfig, FrankContext, Session, ThemeConfigPreset, themePresets,} from "@/components/context";
import {AuthProvider} from "../auth/AuthProvider";
import {getConfig} from "@/config";

export function FrankProvider({
	children,
	initialConfig = {},
}: {
	children: ReactNode;
	initialConfig?: Partial<FrankConfig>;
}) {
	return (
		<AuthProvider organizationId={initialConfig.api?.projectId ?? "default"}>
			<_FrankProvider initialConfig={initialConfig}>{children}</_FrankProvider>
		</AuthProvider>
	);
}

function _FrankProvider({
	children,
	initialConfig = {},
}: {
	children: ReactNode;
	initialConfig?: Partial<FrankConfig>;
}) {
	const [config, setConfig] = useState<FrankConfig>({
		frontendUrl: initialConfig.frontendUrl ?? "http://localhost:3000",
		logo: initialConfig.logo ?? <Key className="h-6 w-6" />,
		title: initialConfig.title ?? "Welcome Back",
		description: initialConfig.description ?? "Sign in to your account",
		oauthProviders: initialConfig.oauthProviders ?? [],
		onLogin: initialConfig.onLogin,
		onSignup: initialConfig.onSignup,
		onPasswordless: initialConfig.onPasswordless,
		onPasskey: initialConfig.onPasskey,
		onMfa: initialConfig.onMfa,
		onForgotPassword: initialConfig.onForgotPassword,
		onVerifyOtp: initialConfig.onVerifyOtp,
		onResetPassword: initialConfig.onResetPassword,
		supportedMethods: initialConfig.supportedMethods ?? [
			"password",
			"passwordless",
			"passkey",
		],
		showTabs: initialConfig.showTabs ?? true,
		availableTabs: initialConfig.availableTabs ?? ["login", "signup"],
		initialView: initialConfig.initialView ?? "login",
		signupFields: initialConfig.signupFields ?? [
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
		links: {
			legal: initialConfig.links?.legal ?? [],
			redirectAfterLogin: initialConfig.links?.redirectAfterLogin ?? "/",
			verify: initialConfig.links?.verify,
			mfa: initialConfig.links?.mfa,
			showAuthLinks: initialConfig.links?.showAuthLinks ?? true,
			login: initialConfig.links?.login ?? {
				preText: "Already have an account?",
				text: "Log in",
				url: "/login",
			},
			signup: initialConfig.links?.signup ?? {
				preText: "Don't have an account?",
				text: "Sign up",
				url: "/signup",
			},
			resetPassword: {
				text: "Sign up",
				url: initialConfig.frontendUrl + "/login/reset-password",
			},
			...(initialConfig.links ?? {}),
		},
		theme: initialConfig.theme ?? {
			primaryColor: "bg-primary",
			backgroundColor: "bg-background",
			textColor: "text-foreground",
			borderRadius: "rounded-md",
		},
		api: initialConfig.api ?? {
			projectId: "default",
		},
		cssClasses: initialConfig.cssClasses ?? {},
		components: initialConfig.components ?? {},
	});
	const apiConfig = getConfig();

	const getTheme = (theme?: ThemeConfigPreset) => {
		if (!theme) return themePresets.default;

		if (typeof theme === "string") {
			return themePresets[theme] ?? themePresets.default;
		}
		return theme ?? themePresets.default;
	};

	const [session, setSession] = useState<Session | null>(null);
	const [isLoading, setIsLoading] = useState(true);

	// Derive user from session for convenience
	const user = session?.user || null;
	const isAuthenticated = !!session?.user;

	// Update session and trigger callback if provided
	const updateSession = useCallback((newSession: Session | null) => {
		setSession(newSession);
	}, []);

	// Update user by creating a new session with the updated user
	const updateUser = useCallback((newUser: User | null) => {
		setSession((prev) => {
			if (!prev && !newUser) return null;
			if (!prev && newUser) return { user: newUser };
			if (prev && !newUser) return null;
			return { ...prev, user: newUser };
		});
	}, []);

	// Sign in function that uses the onLogin handler from config
	const signIn = useCallback(
		async (credentials: any) => {
			if (!config.onLogin) return false;

			try {
				const requiresMfa = await config.onLogin(credentials);

				// If MFA is not required, we assume the login was successful
				// The actual session update should be handled by the onLogin implementation
				return requiresMfa;
			} catch (error) {
				console.error("Sign in error:", error);
				return false;
			}
		},
		[config.onLogin],
	);

	// Sign out function
	const signOut = useCallback(async () => {
		// Clear the session
		updateSession(null);
		// Additional sign out logic can be added here
	}, [updateSession]);

	const resendVerification = async (data: SendEmailVerificationRequestBody) => {
		return await authSendEmailVerification({
			body: data,
		});
	};

	const verifyEmail = async (data: VerifyEmailRequest) => {
		return await authVerifyEmail({
			body: data,
		});
	};

	const updateConfig = (newConfig: Partial<FrankConfig>) => {
		setConfig((prevConfig) => ({
			...prevConfig,
			...newConfig,
			// Handle nested objects
			theme: getTheme(newConfig.theme ?? prevConfig.theme),
		}));
	};

	client.setConfig({
		baseUrl: initialConfig.api?.baseUrl ?? apiConfig.baseUrl,
		credentials: "include",
		auth: (auth) => {
			if (initialConfig.api?.secret && auth.scheme === "bearer") {
				return initialConfig.api?.secret;
			}
			return undefined;
		},
		headers: initialConfig.api?.secret
			? {
					"X-API-KEY": initialConfig.api?.secret,
					"X-Organization-ID": initialConfig.api?.projectId ?? "frank-auth",
				}
			: {},
	});

	return (
		<FrankContext.Provider
			value={{
				config,
				updateConfig,
				getTheme,
				client,
				signIn,
				signOut,
				updateSession,
				updateUser,
				resendVerification,
				verifyEmail,
				resendCooldown: 60,
				session: null,
				user: null,
				isLoading: true,
				isAuthenticated: false,
			}}
		>
			{children}
		</FrankContext.Provider>
	);
}
