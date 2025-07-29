/**
 * @frank-auth/react - Auth Provider
 *
 * Main authentication provider that manages auth state, session management,
 * and organization context for multi-tenant authentication.
 */

"use client";

import React, {
	createContext,
	useCallback,
	useContext,
	useEffect,
	useMemo,
	useReducer,
} from "react";

import type {
	LoginRequest,
	Organization,
	PasswordResetConfirmRequest,
	RegisterRequest,
	ResendVerificationRequest,
	Session,
	User,
	ValidateTokenInputBody,
	VerificationRequest,
} from "@frank-auth/client";
import {
	AuthSDK,
	FrankAuthError,
	OrganizationSDK,
	type PasswordResetRequest,
	SessionSDK,
	UserSDK,
} from "@frank-auth/sdk";

import type {
	AuthContextValue,
	AuthError,
	AuthFeatures,
	AuthProviderProps,
	AuthState,
	OrganizationMembership,
	SetActiveParams,
	SignInParams,
	SignInResult,
	SignUpParams,
	SignUpResult,
	UpdateUserParams,
} from "./types";

// ============================================================================
// Auth Context
// ============================================================================

const AuthContext = createContext<AuthContextValue | null>(null);

// ============================================================================
// Auth Reducer
// ============================================================================

type AuthAction =
	| { type: "SET_LOADING"; payload: boolean }
	| { type: "SET_LOADED"; payload: boolean }
	| { type: "SET_USER"; payload: User | null }
	| { type: "SET_SESSION"; payload: Session | null }
	| { type: "SET_ORGANIZATION"; payload: Organization | null }
	| { type: "SET_ACTIVE_ORGANIZATION"; payload: Organization | null }
	| { type: "SET_MEMBERSHIPS"; payload: OrganizationMembership[] }
	| { type: "SET_FEATURES"; payload: AuthFeatures }
	| { type: "SET_ERROR"; payload: AuthError | null }
	| { type: "RESET_STATE" };

function authReducer(state: AuthState, action: AuthAction): AuthState {
	switch (action.type) {
		case "SET_LOADING":
			return { ...state, isLoading: action.payload };

		case "SET_LOADED":
			return { ...state, isLoaded: action.payload };

		case "SET_USER":
			return {
				...state,
				user: action.payload,
				isSignedIn: !!action.payload,
				error: null,
			};

		case "SET_SESSION":
			return {
				...state,
				session: action.payload,
				error: null,
			};

		case "SET_ORGANIZATION":
			return {
				...state,
				organization: action.payload,
				error: null,
			};

		case "SET_ACTIVE_ORGANIZATION":
			return {
				...state,
				activeOrganization: action.payload,
				error: null,
			};

		case "SET_MEMBERSHIPS":
			return {
				...state,
				organizationMemberships: action.payload,
				error: null,
			};

		case "SET_FEATURES":
			return {
				...state,
				features: action.payload,
			};

		case "SET_ERROR":
			return {
				...state,
				error: action.payload,
				isLoading: false,
			};

		case "RESET_STATE":
			return {
				...initialAuthState,
				isLoaded: true,
			};

		default:
			return state;
	}
}

// ============================================================================
// Initial State
// ============================================================================

const initialAuthState: AuthState = {
	isLoaded: false,
	isLoading: false,
	isSignedIn: false,
	user: null,
	session: null,
	organization: null,
	organizationMemberships: [],
	activeOrganization: null,
	error: null,
	features: {
		signUp: true,
		signIn: true,
		passwordReset: true,
		mfa: false,
		passkeys: false,
		oauth: false,
		magicLink: false,
		sso: false,
		organizationManagement: false,
		userProfile: true,
		sessionManagement: true,
	},
	// @ts-expect-error
	sdk: undefined,
};

// ============================================================================
// Auth Provider Component
// ============================================================================

export function AuthProvider({
	children,
	publishableKey,
	userType = "external",
	apiUrl,
	secretKey,
	projectId,
	initialState,
	onError,
	onSignIn,
	onSignOut,
	debug = false,
}: AuthProviderProps) {
	const [state, dispatch] = useReducer(authReducer, {
		...initialAuthState,
		...initialState,
	});

	// Initialize Frank Auth SDK
	const authSdk = useMemo(() => {
		return new AuthSDK({
			publishableKey,
			apiUrl,
			enableDevMode: debug,
			userType: userType,
			projectId,
			secretKey,
		});
	}, [publishableKey, apiUrl, debug]);

	// Initialize Frank Auth SDK
	const orgSdk = useMemo(() => {
		return new OrganizationSDK({
			publishableKey,
			apiUrl,
			enableDevMode: debug,
			userType: userType,
			projectId,
			secretKey,
		});
	}, [publishableKey, apiUrl, debug]);

	// Initialize Frank Auth SDK
	const sessionSdk = useMemo(() => {
		return new SessionSDK({
			publishableKey,
			apiUrl,
			enableDevMode: debug,
			userType: userType,
			projectId,
			secretKey,
		});
	}, [publishableKey, apiUrl, debug]);
	const userSdk = useMemo(() => {
		return new UserSDK({
			publishableKey,
			apiUrl,
			enableDevMode: debug,
			userType: userType,
			projectId,
			secretKey,
		});
	}, [publishableKey, apiUrl, debug]);
	const allSdk = useMemo(() => {
		return {
			auth: authSdk,
			organization: orgSdk,
			session: sessionSdk,
			user: userSdk,
		};
	}, [userSdk, authSdk, orgSdk, sessionSdk]);

	// Error handler
	const handleError = useCallback(
		(error: any) => {
			const authError: AuthError = {
				code: error.code || "UNKNOWN_ERROR",
				message: error.message || "An unknown error occurred",
				details: error.details,
				field: error.field,
			};

			dispatch({ type: "SET_ERROR", payload: authError });
			onError?.(authError);

			if (debug) {
				console.error("[FrankAuth] Error:", authError);
			}
		},
		[onError, debug],
	);

	// Load initial auth state
	const loadAuthState = useCallback(async () => {
		try {
			dispatch({ type: "SET_LOADING", payload: true });

			// Get auth status
			const authStatus = await authSdk.getAuthStatus();

			if (authStatus.isAuthenticated && authStatus.user) {
				dispatch({ type: "SET_USER", payload: authStatus.user });
				dispatch({ type: "SET_SESSION", payload: authStatus.session });

				// Load organization context if available
				if (projectId || authStatus.user.organizationId) {
					try {
						const orgId = projectId || authStatus.user.organizationId || "";
						const org = await orgSdk.getOrganization(orgId);
						dispatch({ type: "SET_ORGANIZATION", payload: org });
						dispatch({ type: "SET_ACTIVE_ORGANIZATION", payload: org });

						// Load organization memberships
						const memberships = await orgSdk.listMembers(orgId);
						dispatch({ type: "SET_MEMBERSHIPS", payload: memberships.data });
					} catch (orgError) {
						if (debug) {
							console.warn(
								"[FrankAuth] Failed to load organization:",
								orgError,
							);
						}
					}
				}

				// Determine available features based on user type and organization
				const features = await determineFeatures(
					authStatus.user,
					state.organization,
					userType,
				);
				dispatch({ type: "SET_FEATURES", payload: features });
			}

			dispatch({ type: "SET_LOADED", payload: true });
		} catch (error) {
			handleError(error);
		} finally {
			dispatch({ type: "SET_LOADING", payload: false });
		}
	}, [authSdk, projectId, userType, debug, handleError]);

	// Determine available features based on context
	const determineFeatures = async (
		user: User | null,
		organization: Organization | null,
		userType: string,
	): Promise<AuthFeatures> => {
		// Base features for all user types
		const baseFeatures: AuthFeatures = {
			signUp: true,
			signIn: true,
			passwordReset: true,
			mfa: false,
			passkeys: false,
			oauth: false,
			magicLink: false,
			sso: false,
			organizationManagement: false,
			userProfile: true,
			sessionManagement: true,
		};

		if (!user) return baseFeatures;

		// Features based on user type
		switch (userType) {
			case "internal":
				return {
					...baseFeatures,
					mfa: true,
					passkeys: true,
					organizationManagement: true,
					sso: true,
				};

			case "external":
				return {
					...baseFeatures,
					mfa: organization?.settings?.mfaSettings?.enabled || false,
					passkeys:
						organization?.settings?.authConfig?.passkeysEnabled || false,
					oauth: organization?.settings?.authConfig?.oauthEnabled || false,
					sso: organization?.settings?.authConfig?.ssoEnabled || false,
					organizationManagement: true,
				};

			case "end_user":
				return {
					...baseFeatures,
					mfa: organization?.settings?.mfaSettings?.enabled || false,
					passkeys:
						organization?.settings?.authConfig?.passkeysEnabled || false,
					oauth: organization?.settings?.authConfig?.oauthEnabled || false,
					organizationManagement: false,
				};

			default:
				return baseFeatures;
		}
	};

	// Sign in method
	const signIn = useCallback(
		async (params: SignInParams): Promise<SignInResult> => {
			try {
				dispatch({ type: "SET_LOADING", payload: true });
				dispatch({ type: "SET_ERROR", payload: null });

				let result;
				let status = "complete";

				switch (params.strategy) {
					case "password":
						if (!params.identifier || !params.password) {
							throw new Error("Email/username and password are required");
						}

						const loginRequest: LoginRequest = {
							email: params.identifier,
							password: params.password,
							organizationId: params.organizationId,
							rememberMe: true,
						};

						result = await authSdk.signIn(loginRequest);

						if (result.mfaRequired) {
							status = "needs_mfa";
						} else if (result.verificationRequired) {
							status = "needs_verification";
						}

						break;

					case "oauth":
						if (!params.provider) {
							throw new Error("OAuth provider is required");
						}

						result = await authSdk.initiateOAuthLogin(params.provider, {
							redirectUrl: params.redirectUrl,
							organizationId: params.organizationId,
						});
						break;

					case "magic_link":
						if (!params.identifier) {
							throw new Error("Email is required for magic link");
						}

						result = await authSdk.sendMagicLink({
							email: params.identifier,
							redirectUrl: params.redirectUrl,
							// organizationId: params.organizationId,
						});
						break;

					case "passkey":
						result = await authSdk.beginPasskeyAuthentication({
							// todo fix
						});

						status = "needs_passkey";
						break;

					case "sso":
						if (!params.organizationId) {
							throw new Error("Organization ID is required for SSO");
						}

						result = await authSdk.initiateSSOLogin(params.organizationId, {
							redirectUrl: params.redirectUrl,
						});
						break;

					default:
						throw new Error(`Unsupported sign-in strategy: ${params.strategy}`);
				}

				// Handle successful authentication
				if (result.user && result.session) {
					dispatch({ type: "SET_USER", payload: result.user });
					dispatch({ type: "SET_SESSION", payload: result.session });
					onSignIn?.(result.user);
				}

				return {
					status: status as any,
					user: result.user,
					session: result.session,
					verificationId: result.verificationId,
					mfaToken: result.mfaToken,
				};
			} catch (error) {
				handleError(error);
				return {
					status: "complete",
					error: {
						code: "SIGN_IN_FAILED",
						message:
							error instanceof FrankAuthError
								? error.message
								: "Sign in failed",
					},
				};
			} finally {
				dispatch({ type: "SET_LOADING", payload: false });
			}
		},
		[authSdk, onSignIn, handleError],
	);

	// Sign up method
	const signUp = useCallback(
		async (params: SignUpParams): Promise<SignUpResult> => {
			try {
				dispatch({ type: "SET_LOADING", payload: true });
				dispatch({ type: "SET_ERROR", payload: null });

				const registerRequest: RegisterRequest = {
					email: params.emailAddress,
					password: params.password,
					firstName: params.firstName,
					lastName: params.lastName,
					username: params.username,
					userType: userType,
					acceptTerms: params.acceptTerms,
					marketingConsent: params.marketingConsent,
					phoneNumber: params.phoneNumber,
					locale: params.locale ?? "en",
					organizationId: params.organizationId,
					invitationToken: params.invitationToken,
					customAttributes: params.unsafeMetadata,
				};

				const result = await authSdk.signUp(registerRequest);

				// Handle successful registration
				if (result.user && result.session) {
					dispatch({ type: "SET_USER", payload: result.user });
					dispatch({ type: "SET_SESSION", payload: result.session });
					onSignIn?.(result.user);
				}

				let status = "complete";
				if (result.verificationRequired) {
					status = "needs_verification";
				}

				return {
					status: status as any,
					user: result.user,
					session: result.session,
					verificationId: result.verificationToken,
				};
			} catch (error) {
				handleError(error);
				return {
					status: "missing_requirements",
					error: {
						code: "SIGN_UP_FAILED",
						message: error instanceof Error ? error.message : "Sign up failed",
					},
				};
			} finally {
				dispatch({ type: "SET_LOADING", payload: false });
			}
		},
		[authSdk, onSignIn, handleError],
	);

	// Sign out method
	const signOut = useCallback(async () => {
		try {
			dispatch({ type: "SET_LOADING", payload: true });
			await authSdk.signOut({ logoutAll: false });
			authSdk.authStorage.clearAll();

			dispatch({ type: "RESET_STATE" });
			onSignOut?.();
		} catch (error) {
			handleError(error);
		} finally {
			dispatch({ type: "SET_LOADING", payload: false });
		}
	}, [authSdk, onSignOut, handleError]);

	// Create session method
	const createSession = useCallback(
		async (token: string): Promise<Session> => {
			try {
				sessionSdk.activeSession = token;
				const session = await sessionSdk.getCurrentSession();
				dispatch({ type: "SET_SESSION", payload: session });
				return session;
			} catch (error) {
				handleError(error);
				throw error;
			}
		},
		[authSdk, handleError],
	);

	// Set active method
	const setActive = useCallback(
		async (params: SetActiveParams) => {
			try {
				if (params.session) {
					const session = params.session;
					if (typeof params.session === "string") {
						sessionSdk.activeSession = params.session;
						await sessionSdk.getCurrentSession();
					}
					dispatch({ type: "SET_SESSION", payload: session });
				}

				if (params.organization) {
					const organization =
						typeof params.organization === "string"
							? await orgSdk.getOrganization(params.organization)
							: params.organization;
					dispatch({ type: "SET_ACTIVE_ORGANIZATION", payload: organization });
				}
			} catch (error) {
				handleError(error);
			}
		},
		[authSdk, handleError],
	);

	// Set active organization
	const setActiveOrganization = useCallback(
		async (org: string | Organization) => {
			try {
				let organization;
				if (typeof org === "string") {
					organization = await orgSdk.getOrganization(org);
				} else {
					organization = org;
				}
				dispatch({ type: "SET_ACTIVE_ORGANIZATION", payload: organization });
			} catch (error) {
				handleError(error);
			}
		},
		[authSdk, handleError],
	);

	// Switch organization
	const switchOrganization = useCallback(
		async (organizationId: string) => {
			try {
				dispatch({ type: "SET_LOADING", payload: true });

				const organization = await authSdk.switchOrganization(organizationId);
				dispatch({ type: "SET_ACTIVE_ORGANIZATION", payload: organization });

				// Reload user data with new organization context
				await loadAuthState();
			} catch (error) {
				handleError(error);
			} finally {
				dispatch({ type: "SET_LOADING", payload: false });
			}
		},
		[authSdk, handleError, loadAuthState],
	);

	// Update user method
	const updateUser = useCallback(
		async (params: UpdateUserParams): Promise<User> => {
			try {
				const updatedUser = await authSdk.updateProfile(params);
				dispatch({ type: "SET_USER", payload: updatedUser });
				return updatedUser;
			} catch (error) {
				handleError(error);
				throw error;
			}
		},
		[authSdk, handleError],
	);

	// Delete user method
	const deleteUser = useCallback(async () => {
		try {
			await userSdk.deleteUser();
			dispatch({ type: "RESET_STATE" });
			onSignOut?.();
		} catch (error) {
			handleError(error);
		}
	}, [authSdk, handleError, onSignOut]);

	// Password request method
	const requestPasswordReset = useCallback(
		async (request: PasswordResetRequest) => {
			try {
				dispatch({ type: "SET_LOADING", payload: true });
				return await authSdk.requestPasswordReset(request);
			} catch (error) {
				handleError(error);
				throw error;
			} finally {
				dispatch({ type: "SET_LOADING", payload: false });
			}
		},
		[authSdk, handleError],
	);

	// Password request method
	const resetPassword = useCallback(
		async (request: PasswordResetConfirmRequest) => {
			try {
				dispatch({ type: "SET_LOADING", payload: true });
				return await authSdk.resetPassword(request);
			} catch (error) {
				handleError(error);
				throw error;
			} finally {
				dispatch({ type: "SET_LOADING", payload: false });
			}
		},
		[authSdk, handleError],
	);

	// Resend verification method
	const resendVerification = useCallback(
		async (request: ResendVerificationRequest) => {
			try {
				dispatch({ type: "SET_LOADING", payload: true });
				return await authSdk.resendVerification(request);
			} catch (error) {
				handleError(error);
				throw error;
			} finally {
				dispatch({ type: "SET_LOADING", payload: false });
			}
		},
		[authSdk, handleError],
	);

	// Resend verification method
	const verifyIdentity = useCallback(
		async (type: "email" | "phone", request: VerificationRequest) => {
			try {
				dispatch({ type: "SET_LOADING", payload: true });
				if (type === "phone") return await authSdk.verifyPhone(request);
				return await authSdk.verifyEmail(request);
			} catch (error) {
				handleError(error);
				throw error;
			} finally {
				dispatch({ type: "SET_LOADING", payload: false });
			}
		},
		[authSdk, handleError],
	);

	// Resend verification method
	const validateToken = useCallback(
		async (request: ValidateTokenInputBody) => {
			try {
				dispatch({ type: "SET_LOADING", payload: true });
				return await authSdk.validateToken(request);
			} catch (error) {
				handleError(error);
				throw error;
			} finally {
				dispatch({ type: "SET_LOADING", payload: false });
			}
		},
		[authSdk, handleError],
	);

	// Reload method
	const reload = useCallback(async () => {
		await loadAuthState();
	}, [loadAuthState]);

	// Load initial state on mount
	useEffect(() => {
		loadAuthState();
	}, [loadAuthState]);

	// Context value
	const contextValue: AuthContextValue = {
		// State
		...state,

		// Methods
		signIn,
		signUp,
		signOut,
		createSession,
		setActive,
		setActiveOrganization,
		switchOrganization,
		updateUser,
		deleteUser,
		reload,
		requestPasswordReset,
		resetPassword,
		validateToken,
		resendVerification,
		verifyIdentity,
		sdk: allSdk,
	};

	return (
		<AuthContext.Provider value={contextValue}>{children}</AuthContext.Provider>
	);
}

// ============================================================================
// Hook to use auth context
// ============================================================================

export function useAuth() {
	const context = useContext(AuthContext);

	if (!context) {
		throw new Error("useAuth must be used within an AuthProvider");
	}

	return context;
}

// ============================================================================
// Hook for authentication guard
// ============================================================================

export function useAuthGuard() {
	const { isLoaded, isSignedIn, user } = useAuth();

	return {
		isLoaded,
		isSignedIn,
		user,
		isAuthenticated: isLoaded && isSignedIn,
		requireAuth: () => {
			if (!isLoaded) {
				throw new Error("Authentication not loaded");
			}
			if (!isSignedIn) {
				throw new Error("Authentication required");
			}
		},
	};
}

// ============================================================================
// Export auth provider
// ============================================================================

export { AuthContext };
export type { AuthContextValue };
