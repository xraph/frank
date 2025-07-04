'use client'


/**
 * @frank-auth/react - useOAuth Hook
 *
 * OAuth authentication hook that provides integration with multiple OAuth providers
 * including Google, Microsoft, GitHub, and other social authentication services.
 */

import {useCallback, useEffect, useMemo, useState} from 'react';

import type {AuthProvider, SSOCallbackRequest, SSOLoginRequest,} from '@frank-auth/client';

import {useAuth} from './use-auth';
import {useConfig} from '../provider/config-provider';

import type {AuthError} from '../provider/types';

// ============================================================================
// OAuth Hook Interface
// ============================================================================

export interface UseOAuthReturn {
    // OAuth state
    providers: AuthProvider[];
    isLoading: boolean;
    error: AuthError | null;

    // OAuth authentication
    signInWithProvider: (provider: string, options?: OAuthSignInOptions) => Promise<void>;
    handleCallback: (provider: string, code?: string, state?: string) => Promise<OAuthCallbackResult>;

    // Provider management
    connectProvider: (provider: string, options?: OAuthConnectOptions) => Promise<void>;
    disconnectProvider: (provider: string) => Promise<void>;

    // Provider information
    isProviderConnected: (provider: string) => boolean;
    getProviderInfo: (provider: string) => AuthProvider | null;

    // Common providers
    signInWithGoogle: (options?: OAuthSignInOptions) => Promise<void>;
    signInWithMicrosoft: (options?: OAuthSignInOptions) => Promise<void>;
    signInWithGitHub: (options?: OAuthSignInOptions) => Promise<void>;
    signInWithApple: (options?: OAuthSignInOptions) => Promise<void>;
    signInWithFacebook: (options?: OAuthSignInOptions) => Promise<void>;
    signInWithTwitter: (options?: OAuthSignInOptions) => Promise<void>;
    signInWithLinkedIn: (options?: OAuthSignInOptions) => Promise<void>;
    signInWithDiscord: (options?: OAuthSignInOptions) => Promise<void>;

    // Utility methods
    refreshProviders: () => Promise<void>;
    getAuthUrl: (provider: string, options?: OAuthSignInOptions) => Promise<string>;
}

export interface OAuthSignInOptions {
    redirectUrl?: string;
    scopes?: string[];
    state?: string;
    prompt?: 'none' | 'consent' | 'select_account';
    organizationId?: string;
    connection?: string;
}

export interface OAuthConnectOptions {
    redirectUrl?: string;
    scopes?: string[];
    state?: string;
}

export interface OAuthCallbackResult {
    success: boolean;
    user?: any;
    session?: any;
    error?: string;
}

// ============================================================================
// OAuth Provider Configurations
// ============================================================================

export const OAUTH_PROVIDERS = {
    google: {
        name: 'Google',
        displayName: 'Google',
        icon: '🔴',
        color: '#4285f4',
        defaultScopes: ['openid', 'profile', 'email'],
    },
    microsoft: {
        name: 'Microsoft',
        displayName: 'Microsoft',
        icon: '🟦',
        color: '#00a1f1',
        defaultScopes: ['openid', 'profile', 'email'],
    },
    github: {
        name: 'GitHub',
        displayName: 'GitHub',
        icon: '⚫',
        color: '#333333',
        defaultScopes: ['user:email'],
    },
    apple: {
        name: 'Apple',
        displayName: 'Apple',
        icon: '🍎',
        color: '#000000',
        defaultScopes: ['name', 'email'],
    },
    facebook: {
        name: 'Facebook',
        displayName: 'Facebook',
        icon: '🔵',
        color: '#1877f2',
        defaultScopes: ['email', 'public_profile'],
    },
    twitter: {
        name: 'Twitter',
        displayName: 'Twitter',
        icon: '🐦',
        color: '#1da1f2',
        defaultScopes: ['users.read', 'tweet.read'],
    },
    linkedin: {
        name: 'LinkedIn',
        displayName: 'LinkedIn',
        icon: '🔵',
        color: '#0077b5',
        defaultScopes: ['r_liteprofile', 'r_emailaddress'],
    },
    discord: {
        name: 'Discord',
        displayName: 'Discord',
        icon: '🎮',
        color: '#5865f2',
        defaultScopes: ['identify', 'email'],
    },
} as const;

export type OAuthProviderType = keyof typeof OAUTH_PROVIDERS;

// ============================================================================
// Main useOAuth Hook
// ============================================================================

/**
 * OAuth authentication hook providing integration with multiple providers
 *
 * @example Basic OAuth sign-in
 * ```tsx
 * import { useOAuth } from '@frank-auth/react';
 *
 * function OAuthSignIn() {
 *   const {
 *     providers,
 *     signInWithGoogle,
 *     signInWithGitHub,
 *     signInWithProvider,
 *     isLoading
 *   } = useOAuth();
 *
 *   return (
 *     <div>
 *       <h3>Sign in with</h3>
 *       <button
 *         onClick={() => signInWithGoogle()}
 *         disabled={isLoading}
 *       >
 *         Continue with Google
 *       </button>
 *       <button
 *         onClick={() => signInWithGitHub()}
 *         disabled={isLoading}
 *       >
 *         Continue with GitHub
 *       </button>
 *
 *       {providers.map(provider => (
 *         <button
 *           key={provider.name}
 *           onClick={() => signInWithProvider(provider.name)}
 *           disabled={isLoading}
 *         >
 *           Continue with {provider.displayName}
 *         </button>
 *       ))}
 *     </div>
 *   );
 * }
 * ```
 *
 * @example OAuth callback handling
 * ```tsx
 * import { useEffect } from 'react';
 * import { useOAuth } from '@frank-auth/react';
 * import { useSearchParams } from 'react-router-dom';
 *
 * function OAuthCallback() {
 *   const { handleCallback } = useOAuth();
 *   const [searchParams] = useSearchParams();
 *
 *   useEffect(() => {
 *     const code = searchParams.get('code');
 *     const state = searchParams.get('state');
 *     const provider = searchParams.get('provider') || 'google';
 *
 *     if (code) {
 *       handleCallback(provider, code, state)
 *         .then(result => {
 *           if (result.success) {
 *             console.log('OAuth sign-in successful:', result.user);
 *             // Redirect to dashboard or handle success
 *           } else {
 *             console.error('OAuth sign-in failed:', result.error);
 *           }
 *         })
 *         .catch(error => {
 *           console.error('OAuth callback error:', error);
 *         });
 *     }
 *   }, [handleCallback, searchParams]);
 *
 *   return <div>Processing OAuth callback...</div>;
 * }
 * ```
 *
 * @example Provider connection management
 * ```tsx
 * function ConnectedAccounts() {
 *   const {
 *     providers,
 *     isProviderConnected,
 *     connectProvider,
 *     disconnectProvider
 *   } = useOAuth();
 *
 *   return (
 *     <div>
 *       <h3>Connected Accounts</h3>
 *       {providers.map(provider => {
 *         const isConnected = isProviderConnected(provider.name);
 *
 *         return (
 *           <div key={provider.name}>
 *             <span>{provider.displayName}</span>
 *             {isConnected ? (
 *               <button onClick={() => disconnectProvider(provider.name)}>
 *                 Disconnect
 *               </button>
 *             ) : (
 *               <button onClick={() => connectProvider(provider.name)}>
 *                 Connect
 *               </button>
 *             )}
 *           </div>
 *         );
 *       })}
 *     </div>
 *   );
 * }
 * ```
 */
export function useOAuth(): UseOAuthReturn {
    const {user, activeOrganization, reload, sdk} = useAuth();
    const {features} = useConfig();

    const [providers, setProviders] = useState<AuthProvider[]>([]);
    const [isLoading, setIsLoading] = useState(false);
    const [error, setError] = useState<AuthError | null>(null);

    // Check if OAuth is available
    const isOAuthAvailable = useMemo(() => features.oauth, [features.oauth]);

    // Error handler
    const handleError = useCallback((err: any) => {
        const authError: AuthError = {
            code: err.code || 'UNKNOWN_ERROR',
            message: err.message || 'An unknown error occurred',
            details: err.details,
            field: err.field,
        };
        setError(authError);
        throw authError;
    }, []);

    // Load available OAuth providers
    const loadProviders = useCallback(async () => {
        if (!isOAuthAvailable) return;

        try {
            setIsLoading(true);
            setError(null);

            const providersList = await sdk.auth.getOAuthProviders();
            setProviders(providersList);
        } catch (err) {
            console.error('Failed to load OAuth providers:', err);
            setError({
                code: 'OAUTH_PROVIDERS_LOAD_FAILED',
                message: 'Failed to load OAuth providers',
            });
        } finally {
            setIsLoading(false);
        }
    }, [sdk.auth, isOAuthAvailable]);

    useEffect(() => {
        loadProviders();
    }, [loadProviders]);

    // Generate OAuth authentication URL
    const getAuthUrl = useCallback(async (provider: string, options?: OAuthSignInOptions): Promise<string> => {
        if (!isOAuthAvailable) throw new Error('OAuth not available');

        try {
            const ssoLoginRequest: SSOLoginRequest = {
                provider,
                redirectUrl: options?.redirectUrl || `${window.location.origin}/auth/callback`,
                scopes: options?.scopes,
                state: options?.state,
                prompt: options?.prompt,
                organizationId: options?.organizationId || activeOrganization?.id,
                connection: options?.connection,
            };

            const response = await sdk.auth.initiateSSOLogin(ssoLoginRequest);
            return response.authUrl;
        } catch (err) {
            handleError(err);
            return '';
        }
    }, [sdk.auth, isOAuthAvailable, activeOrganization, handleError]);

    // Sign in with OAuth provider
    const signInWithProvider = useCallback(async (provider: string, options?: OAuthSignInOptions): Promise<void> => {
        if (!isOAuthAvailable) throw new Error('OAuth not available');

        try {
            setIsLoading(true);
            setError(null);

            const authUrl = await getAuthUrl(provider, options);

            // Redirect to OAuth provider
            window.location.href = authUrl;
        } catch (err) {
            handleError(err);
        } finally {
            setIsLoading(false);
        }
    }, [getAuthUrl, isOAuthAvailable, handleError]);

    // Handle OAuth callback
    const handleCallback = useCallback(async (
        provider: string,
        code?: string,
        state?: string
    ): Promise<OAuthCallbackResult> => {
        if (!isOAuthAvailable) throw new Error('OAuth not available');

        try {
            setIsLoading(true);
            setError(null);

            const callbackRequest: SSOCallbackRequest = {
                provider,
                code: code || new URLSearchParams(window.location.search).get('code') || '',
                state: state || new URLSearchParams(window.location.search).get('state') || '',
            };

            const response = await sdk.auth.handleSSOCallback(callbackRequest);

            if (response.success) {
                // Reload user data
                await reload();

                return {
                    success: true,
                    user: response.user,
                    session: response.session,
                };
            } else {
                return {
                    success: false,
                    error: response.error || 'OAuth authentication failed',
                };
            }
        } catch (err) {
            return {
                success: false,
                error: err.message || 'OAuth callback failed',
            };
        } finally {
            setIsLoading(false);
        }
    }, [sdk.auth, isOAuthAvailable, reload]);

    // Connect OAuth provider to existing account
    const connectProvider = useCallback(async (provider: string, options?: OAuthConnectOptions): Promise<void> => {
        if (!user) throw new Error('User not authenticated');
        if (!isOAuthAvailable) throw new Error('OAuth not available');

        try {
            setIsLoading(true);
            setError(null);

            const authUrl = await getAuthUrl(provider, {
                ...options,
                state: `connect:${provider}:${user.id}`,
            });

            // Redirect to OAuth provider for connection
            window.location.href = authUrl;
        } catch (err) {
            handleError(err);
        } finally {
            setIsLoading(false);
        }
    }, [user, getAuthUrl, isOAuthAvailable, handleError]);

    // Disconnect OAuth provider
    const disconnectProvider = useCallback(async (provider: string): Promise<void> => {
        if (!user) throw new Error('User not authenticated');
        if (!isOAuthAvailable) throw new Error('OAuth not available');

        try {
            setIsLoading(true);
            setError(null);

            await sdk.auth.disconnectOAuthProvider(provider);

            // Reload user data
            await reload();
        } catch (err) {
            handleError(err);
        } finally {
            setIsLoading(false);
        }
    }, [sdk.auth, user, isOAuthAvailable, reload, handleError]);

    // Check if provider is connected
    const isProviderConnected = useCallback((provider: string): boolean => {
        if (!user?.connectedAccounts) return false;
        return user.connectedAccounts.some((account: any) => account.provider === provider);
    }, [user]);

    // Get provider information
    const getProviderInfo = useCallback((provider: string): AuthProvider | null => {
        return providers.find(p => p.name === provider) || null;
    }, [providers]);

    // Common provider sign-in methods
    const signInWithGoogle = useCallback((options?: OAuthSignInOptions) => {
        return signInWithProvider('google', {
            scopes: OAUTH_PROVIDERS.google.defaultScopes,
            ...options,
        });
    }, [signInWithProvider]);

    const signInWithMicrosoft = useCallback((options?: OAuthSignInOptions) => {
        return signInWithProvider('microsoft', {
            scopes: OAUTH_PROVIDERS.microsoft.defaultScopes,
            ...options,
        });
    }, [signInWithProvider]);

    const signInWithGitHub = useCallback((options?: OAuthSignInOptions) => {
        return signInWithProvider('github', {
            scopes: OAUTH_PROVIDERS.github.defaultScopes,
            ...options,
        });
    }, [signInWithProvider]);

    const signInWithApple = useCallback((options?: OAuthSignInOptions) => {
        return signInWithProvider('apple', {
            scopes: OAUTH_PROVIDERS.apple.defaultScopes,
            ...options,
        });
    }, [signInWithProvider]);

    const signInWithFacebook = useCallback((options?: OAuthSignInOptions) => {
        return signInWithProvider('facebook', {
            scopes: OAUTH_PROVIDERS.facebook.defaultScopes,
            ...options,
        });
    }, [signInWithProvider]);

    const signInWithTwitter = useCallback((options?: OAuthSignInOptions) => {
        return signInWithProvider('twitter', {
            scopes: OAUTH_PROVIDERS.twitter.defaultScopes,
            ...options,
        });
    }, [signInWithProvider]);

    const signInWithLinkedIn = useCallback((options?: OAuthSignInOptions) => {
        return signInWithProvider('linkedin', {
            scopes: OAUTH_PROVIDERS.linkedin.defaultScopes,
            ...options,
        });
    }, [signInWithProvider]);

    const signInWithDiscord = useCallback((options?: OAuthSignInOptions) => {
        return signInWithProvider('discord', {
            scopes: OAUTH_PROVIDERS.discord.defaultScopes,
            ...options,
        });
    }, [signInWithProvider]);

    // Refresh providers
    const refreshProviders = useCallback(async (): Promise<void> => {
        await loadProviders();
    }, [loadProviders]);

    return {
        // OAuth state
        providers,
        isLoading,
        error,

        // OAuth authentication
        signInWithProvider,
        handleCallback,

        // Provider management
        connectProvider,
        disconnectProvider,

        // Provider information
        isProviderConnected,
        getProviderInfo,

        // Common providers
        signInWithGoogle,
        signInWithMicrosoft,
        signInWithGitHub,
        signInWithApple,
        signInWithFacebook,
        signInWithTwitter,
        signInWithLinkedIn,
        signInWithDiscord,

        // Utility methods
        refreshProviders,
        getAuthUrl,
    };
}

// ============================================================================
// Specialized OAuth Hooks
// ============================================================================

/**
 * Hook for specific OAuth provider
 */
export function useOAuthProvider(providerName: OAuthProviderType) {
    const {
        signInWithProvider,
        connectProvider,
        disconnectProvider,
        isProviderConnected,
        getProviderInfo,
        isLoading,
        error,
    } = useOAuth();

    const provider = useMemo(() => OAUTH_PROVIDERS[providerName], [providerName]);
    const providerInfo = useMemo(() => getProviderInfo(providerName), [getProviderInfo, providerName]);
    const isConnected = useMemo(() => isProviderConnected(providerName), [isProviderConnected, providerName]);

    const signIn = useCallback((options?: OAuthSignInOptions) => {
        return signInWithProvider(providerName, {
            scopes: provider.defaultScopes,
            ...options,
        });
    }, [signInWithProvider, providerName, provider.defaultScopes]);

    const connect = useCallback((options?: OAuthConnectOptions) => {
        return connectProvider(providerName, options);
    }, [connectProvider, providerName]);

    const disconnect = useCallback(() => {
        return disconnectProvider(providerName);
    }, [disconnectProvider, providerName]);

    return {
        provider,
        providerInfo,
        isConnected,
        signIn,
        connect,
        disconnect,
        isLoading,
        error,
        isEnabled: !!providerInfo?.enabled,
    };
}

/**
 * Hook for OAuth callback handling
 */
export function useOAuthCallback() {
    const {handleCallback} = useOAuth();
    const [callbackState, setCallbackState] = useState<'idle' | 'processing' | 'success' | 'error'>('idle');
    const [callbackResult, setCallbackResult] = useState<OAuthCallbackResult | null>(null);

    const processCallback = useCallback(async (
        provider?: string,
        code?: string,
        state?: string
    ) => {
        // Extract from URL if not provided
        const urlParams = new URLSearchParams(window.location.search);
        const callbackProvider = provider || urlParams.get('provider') || 'google';
        const callbackCode = code || urlParams.get('code') || '';
        const callbackState = state || urlParams.get('state') || '';

        if (!callbackCode) {
            setCallbackState('error');
            setCallbackResult({
                success: false,
                error: 'No authorization code received',
            });
            return;
        }

        try {
            setCallbackState('processing');
            const result = await handleCallback(callbackProvider, callbackCode, callbackState);

            setCallbackResult(result);
            setCallbackState(result.success ? 'success' : 'error');

            return result;
        } catch (error) {
            const errorResult = {
                success: false,
                error: error.message || 'OAuth callback failed',
            };

            setCallbackResult(errorResult);
            setCallbackState('error');

            return errorResult;
        }
    }, [handleCallback]);

    return {
        processCallback,
        state: callbackState,
        result: callbackResult,
        isProcessing: callbackState === 'processing',
        isSuccess: callbackState === 'success',
        isError: callbackState === 'error',
    };
}
