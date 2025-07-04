/**
 * @frank-auth/react - usePasskeys Hook
 *
 * Comprehensive passkeys (WebAuthn/FIDO2) hook that provides passkey registration,
 * authentication, and management for passwordless authentication.
 */

import {useCallback, useEffect, useMemo, useState} from 'react';

import type {
    PasskeyAuthenticationFinishRequest,
    PasskeyRegistrationFinishRequest,
    PasskeySummary,
    UpdatePasskeyRequest,
} from '@frank-auth/client';

import {useAuth} from './use-auth';
import {useConfig} from '../provider/config-provider';

import type {AuthError} from '../provider/types';

// ============================================================================
// Passkeys Hook Interface
// ============================================================================

export interface UsePasskeysReturn {
    // Passkey state
    passkeys: PasskeySummary[];
    isSupported: boolean;
    isAvailable: boolean;
    isLoaded: boolean;
    isLoading: boolean;
    error: AuthError | null;

    // Passkey registration
    beginRegistration: (name?: string) => Promise<PasskeyRegistrationData>;
    finishRegistration: (registrationData: PasskeyRegistrationData, credential: any) => Promise<PasskeySummary>;
    registerPasskey: (name?: string) => Promise<PasskeySummary>;

    // Passkey authentication
    beginAuthentication: () => Promise<PasskeyAuthenticationData>;
    finishAuthentication: (authenticationData: PasskeyAuthenticationData, credential: any) => Promise<AuthenticationResult>;
    authenticateWithPasskey: () => Promise<AuthenticationResult>;

    // Passkey management
    updatePasskey: (passkeyId: string, updates: UpdatePasskeyRequest) => Promise<PasskeySummary>;
    deletePasskey: (passkeyId: string) => Promise<void>;
    renamePasskey: (passkeyId: string, name: string) => Promise<PasskeySummary>;

    // Passkey information
    primaryPasskey: PasskeySummary | null;
    passkeyCount: number;

    // Utility methods
    refreshPasskeys: () => Promise<void>;
    checkSupport: () => Promise<boolean>;
}

export interface PasskeyRegistrationData {
    challenge: string;
    options: PublicKeyCredentialCreationOptions;
    sessionId?: string;
}

export interface PasskeyAuthenticationData {
    challenge: string;
    options: PublicKeyCredentialRequestOptions;
    sessionId?: string;
}

export interface AuthenticationResult {
    success: boolean;
    session?: any;
    user?: any;
    error?: string;
}

// ============================================================================
// WebAuthn Utilities
// ============================================================================

/**
 * Check if WebAuthn is supported in the current browser
 */
function isWebAuthnSupported(): boolean {
    return typeof window !== 'undefined' &&
        'navigator' in window &&
        'credentials' in navigator &&
        'create' in navigator.credentials &&
        'get' in navigator.credentials;
}

/**
 * Check if platform authenticator (like Touch ID, Face ID) is available
 */
async function isPlatformAuthenticatorAvailable(): Promise<boolean> {
    if (!isWebAuthnSupported()) return false;

    try {
        return await PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable();
    } catch {
        return false;
    }
}

/**
 * Convert base64url to ArrayBuffer
 */
function base64urlToArrayBuffer(base64url: string): ArrayBuffer {
    const base64 = base64url.replace(/-/g, '+').replace(/_/g, '/');
    const padded = base64.padEnd(base64.length + (4 - base64.length % 4) % 4, '=');
    const binary = atob(padded);
    const buffer = new ArrayBuffer(binary.length);
    const bytes = new Uint8Array(buffer);

    for (let i = 0; i < binary.length; i++) {
        bytes[i] = binary.charCodeAt(i);
    }

    return buffer;
}

/**
 * Convert ArrayBuffer to base64url
 */
function arrayBufferToBase64url(buffer: ArrayBuffer): string {
    const bytes = new Uint8Array(buffer);
    let binary = '';

    for (let i = 0; i < bytes.byteLength; i++) {
        binary += String.fromCharCode(bytes[i]);
    }

    return btoa(binary)
        .replace(/\+/g, '-')
        .replace(/\//g, '_')
        .replace(/=/g, '');
}

/**
 * Convert server credential creation options to browser format
 */
function parseCredentialCreationOptions(options: any): PublicKeyCredentialCreationOptions {
    return {
        ...options,
        challenge: base64urlToArrayBuffer(options.challenge),
        user: {
            ...options.user,
            id: base64urlToArrayBuffer(options.user.id),
        },
        excludeCredentials: options.excludeCredentials?.map((cred: any) => ({
            ...cred,
            id: base64urlToArrayBuffer(cred.id),
        })),
    };
}

/**
 * Convert server credential request options to browser format
 */
function parseCredentialRequestOptions(options: any): PublicKeyCredentialRequestOptions {
    return {
        ...options,
        challenge: base64urlToArrayBuffer(options.challenge),
        allowCredentials: options.allowCredentials?.map((cred: any) => ({
            ...cred,
            id: base64urlToArrayBuffer(cred.id),
        })),
    };
}

/**
 * Convert browser credential to server format
 */
function serializeCredential(credential: PublicKeyCredential): any {
    const response = credential.response as AuthenticatorAttestationResponse | AuthenticatorAssertionResponse;

    const serialized: any = {
        id: credential.id,
        rawId: arrayBufferToBase64url(credential.rawId),
        type: credential.type,
        response: {
            clientDataJSON: arrayBufferToBase64url(response.clientDataJSON),
        },
    };

    if (response instanceof AuthenticatorAttestationResponse) {
        serialized.response.attestationObject = arrayBufferToBase64url(response.attestationObject);
    } else if (response instanceof AuthenticatorAssertionResponse) {
        serialized.response.authenticatorData = arrayBufferToBase64url(response.authenticatorData);
        serialized.response.signature = arrayBufferToBase64url(response.signature);

        if (response.userHandle) {
            serialized.response.userHandle = arrayBufferToBase64url(response.userHandle);
        }
    }

    return serialized;
}

// ============================================================================
// Main usePasskeys Hook
// ============================================================================

/**
 * Comprehensive passkeys hook for WebAuthn/FIDO2 authentication
 *
 * @example Basic passkey registration
 * ```tsx
 * import { usePasskeys } from '@frank-auth/react';
 *
 * function PasskeySetup() {
 *   const {
 *     isSupported,
 *     isAvailable,
 *     registerPasskey,
 *     passkeys,
 *     isLoading
 *   } = usePasskeys();
 *
 *   const handleRegisterPasskey = async () => {
 *     try {
 *       const passkey = await registerPasskey('My Security Key');
 *       console.log('Passkey registered:', passkey);
 *     } catch (error) {
 *       console.error('Registration failed:', error);
 *     }
 *   };
 *
 *   if (!isSupported) {
 *     return <div>Passkeys are not supported in this browser</div>;
 *   }
 *
 *   if (!isAvailable) {
 *     return <div>No authenticators available</div>;
 *   }
 *
 *   return (
 *     <div>
 *       <h3>Your Passkeys ({passkeys.length})</h3>
 *       {passkeys.map(passkey => (
 *         <div key={passkey.id}>
 *           <span>{passkey.name}</span>
 *           <span>Created: {passkey.createdAt}</span>
 *         </div>
 *       ))}
 *       <button onClick={handleRegisterPasskey} disabled={isLoading}>
 *         Add New Passkey
 *       </button>
 *     </div>
 *   );
 * }
 * ```
 *
 * @example Passkey authentication
 * ```tsx
 * function PasskeySignIn() {
 *   const { authenticateWithPasskey, isSupported } = usePasskeys();
 *
 *   const handleSignIn = async () => {
 *     try {
 *       const result = await authenticateWithPasskey();
 *       if (result.success) {
 *         console.log('Signed in successfully:', result.user);
 *       }
 *     } catch (error) {
 *       console.error('Authentication failed:', error);
 *     }
 *   };
 *
 *   if (!isSupported) {
 *     return <div>Passkey authentication not supported</div>;
 *   }
 *
 *   return (
 *     <button onClick={handleSignIn}>
 *       Sign in with Passkey
 *     </button>
 *   );
 * }
 * ```
 *
 * @example Passkey management
 * ```tsx
 * function PasskeyManagement() {
 *   const {
 *     passkeys,
 *     deletePasskey,
 *     renamePasskey,
 *     updatePasskey
 *   } = usePasskeys();
 *
 *   const [editingId, setEditingId] = useState(null);
 *   const [newName, setNewName] = useState('');
 *
 *   const handleRename = async (passkeyId) => {
 *     try {
 *       await renamePasskey(passkeyId, newName);
 *       setEditingId(null);
 *       setNewName('');
 *     } catch (error) {
 *       console.error('Rename failed:', error);
 *     }
 *   };
 *
 *   const handleDelete = async (passkeyId) => {
 *     if (confirm('Are you sure you want to delete this passkey?')) {
 *       try {
 *         await deletePasskey(passkeyId);
 *       } catch (error) {
 *         console.error('Delete failed:', error);
 *       }
 *     }
 *   };
 *
 *   return (
 *     <div>
 *       {passkeys.map(passkey => (
 *         <div key={passkey.id}>
 *           {editingId === passkey.id ? (
 *             <div>
 *               <input
 *                 value={newName}
 *                 onChange={(e) => setNewName(e.target.value)}
 *                 defaultValue={passkey.name}
 *               />
 *               <button onClick={() => handleRename(passkey.id)}>
 *                 Save
 *               </button>
 *               <button onClick={() => setEditingId(null)}>
 *                 Cancel
 *               </button>
 *             </div>
 *           ) : (
 *             <div>
 *               <span>{passkey.name}</span>
 *               <span>Last used: {passkey.lastUsedAt}</span>
 *               <button onClick={() => {
 *                 setEditingId(passkey.id);
 *                 setNewName(passkey.name);
 *               }}>
 *                 Rename
 *               </button>
 *               <button onClick={() => handleDelete(passkey.id)}>
 *                 Delete
 *               </button>
 *             </div>
 *           )}
 *         </div>
 *       ))}
 *     </div>
 *   );
 * }
 * ```
 */
export function usePasskeys(): UsePasskeysReturn {
    const {user, sdk} = useAuth();
    const {apiUrl, publishableKey, features} = useConfig();

    const [passkeys, setPasskeys] = useState<PasskeySummary[]>([]);
    const [isLoading, setIsLoading] = useState(false);
    const [error, setError] = useState<AuthError | null>(null);
    const [isAvailable, setIsAvailable] = useState(false);

    // Check WebAuthn support
    const isSupported = useMemo(() => isWebAuthnSupported(), []);

    // Check if passkeys are available in the configuration
    const isPasskeysEnabled = useMemo(() => features.passkeys, [features.passkeys]);

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

    // Check platform authenticator availability
    const checkSupport = useCallback(async (): Promise<boolean> => {
        if (!isSupported) return false;

        try {
            const available = await isPlatformAuthenticatorAvailable();
            setIsAvailable(available);
            return available;
        } catch {
            setIsAvailable(false);
            return false;
        }
    }, [isSupported]);

    // Load user's passkeys
    const loadPasskeys = useCallback(async () => {
        if (!sdk.user || !user || !isPasskeysEnabled) return;

        try {
            setIsLoading(true);
            setError(null);

            const response = await sdk.user.getPasskeys({fields: []});
            setPasskeys(response.data || []);
        } catch (err) {
            console.error('Failed to load passkeys:', err);
            setError({
                code: 'PASSKEYS_LOAD_FAILED',
                message: 'Failed to load passkeys',
            });
        } finally {
            setIsLoading(false);
        }
    }, [sdk.user, user, isPasskeysEnabled]);

    // Initialize hook
    useEffect(() => {
        checkSupport();
        loadPasskeys();
    }, [checkSupport, loadPasskeys]);

    // Begin passkey registration
    const beginRegistration = useCallback(async (name?: string): Promise<PasskeyRegistrationData> => {
        if (!sdk.user) throw new Error('User not authenticated');
        if (!isSupported) throw new Error('WebAuthn not supported');
        if (!isPasskeysEnabled) throw new Error('Passkeys not enabled');

        try {
            setIsLoading(true);
            setError(null);

            const response = await sdk.auth.beginPasskeyRegistration({
                name: name || `Passkey ${passkeys.length + 1}`,
            });

            const options = parseCredentialCreationOptions(response.options);

            return {
                challenge: response.challenge,
                options,
                sessionId: response.sessionId,
            };
        } catch (err) {
            return handleError(err);
        } finally {
            setIsLoading(false);
        }
    }, [sdk.auth, isSupported, isPasskeysEnabled, passkeys.length, handleError]);

    // Finish passkey registration
    const finishRegistration = useCallback(async (
        registrationData: PasskeyRegistrationData,
        credential: PublicKeyCredential
    ): Promise<PasskeySummary> => {
        if (!sdk.user) throw new Error('User not authenticated');

        try {
            setIsLoading(true);
            setError(null);

            const serializedCredential = serializeCredential(credential);

            const request: PasskeyRegistrationFinishRequest = {
                sessionId: registrationData.sessionId,
                credential: serializedCredential,
            };

            const response = await sdk.auth.finishPasskeyRegistration(request);

            // Refresh passkeys list
            await loadPasskeys();

            return response.passkey;
        } catch (err) {
            return handleError(err);
        } finally {
            setIsLoading(false);
        }
    }, [sdk.user, loadPasskeys, handleError]);

    // Complete passkey registration (convenience method)
    const registerPasskey = useCallback(async (name?: string): Promise<PasskeySummary> => {
        const registrationData = await beginRegistration(name);

        try {
            const credential = await navigator.credentials.create({
                publicKey: registrationData.options,
            }) as PublicKeyCredential;

            if (!credential) {
                throw new Error('Failed to create credential');
            }

            return await finishRegistration(registrationData, credential);
        } catch (err) {
            if (err.name === 'NotAllowedError') {
                throw new Error('User cancelled the registration process');
            } else if (err.name === 'InvalidStateError') {
                throw new Error('This authenticator is already registered');
            } else {
                throw new Error(`Registration failed: ${err.message}`);
            }
        }
    }, [beginRegistration, finishRegistration]);

    // Begin passkey authentication
    const beginAuthentication = useCallback(async (): Promise<PasskeyAuthenticationData> => {
        if (!sdk.auth) throw new Error('User not authenticated');
        if (!isSupported) throw new Error('WebAuthn not supported');

        try {
            setIsLoading(true);
            setError(null);

            const response = await sdk.auth.beginPasskeyAuthentication({});

            const options = parseCredentialRequestOptions(response.options);

            return {
                challenge: response.challenge,
                options,
                sessionId: response.sessionId,
            };
        } catch (err) {
            return handleError(err);
        } finally {
            setIsLoading(false);
        }
    }, [sdk.auth, isSupported, handleError]);

    // Finish passkey authentication
    const finishAuthentication = useCallback(async (
        authenticationData: PasskeyAuthenticationData,
        credential: PublicKeyCredential
    ): Promise<AuthenticationResult> => {
        if (!sdk.user) throw new Error('User not authenticated');

        try {
            setIsLoading(true);
            setError(null);

            const serializedCredential = serializeCredential(credential);

            const request: PasskeyAuthenticationFinishRequest = {
                sessionId: authenticationData.sessionId,
                credential: serializedCredential,
            };

            const response = await sdk.auth.finishPasskeyAuthentication(request);

            return {
                success: true,
                session: response.session,
                user: response.user,
            };
        } catch (err) {
            return {
                success: false,
                error: err.message,
            };
        } finally {
            setIsLoading(false);
        }
    }, [sdk.auth, handleError]);

    // Complete passkey authentication (convenience method)
    const authenticateWithPasskey = useCallback(async (): Promise<AuthenticationResult> => {
        const authenticationData = await beginAuthentication();

        try {
            const credential = await navigator.credentials.get({
                publicKey: authenticationData.options,
            }) as PublicKeyCredential;

            if (!credential) {
                throw new Error('Failed to get credential');
            }

            return await finishAuthentication(authenticationData, credential);
        } catch (err) {
            if (err.name === 'NotAllowedError') {
                return {
                    success: false,
                    error: 'User cancelled the authentication process',
                };
            } else {
                return {
                    success: false,
                    error: `Authentication failed: ${err.message}`,
                };
            }
        }
    }, [beginAuthentication, finishAuthentication]);

    // Update passkey
    const updatePasskey = useCallback(async (passkeyId: string, updates: UpdatePasskeyRequest): Promise<PasskeySummary> => {
        if (!sdk.user) throw new Error('User not authenticated');

        try {
            setIsLoading(true);
            setError(null);

            const response = await sdk.user.updatePasskey(passkeyId, updates);

            // Refresh passkeys list
            await loadPasskeys();

            return response.passkey;
        } catch (err) {
            return handleError(err);
        } finally {
            setIsLoading(false);
        }
    }, [sdk.user, loadPasskeys, handleError]);

    // Delete passkey
    const deletePasskey = useCallback(async (passkeyId: string): Promise<void> => {
        if (!sdk.user) throw new Error('User not authenticated');

        try {
            setIsLoading(true);
            setError(null);

            await sdk.user.deletePasskey(passkeyId);

            // Refresh passkeys list
            await loadPasskeys();
        } catch (err) {
            handleError(err);
        } finally {
            setIsLoading(false);
        }
    }, [sdk.user, loadPasskeys, handleError]);

    // Rename passkey (convenience method)
    const renamePasskey = useCallback(async (passkeyId: string, name: string): Promise<PasskeySummary> => {
        return updatePasskey(passkeyId, {name});
    }, [updatePasskey]);

    // Refresh passkeys
    const refreshPasskeys = useCallback(async (): Promise<void> => {
        await loadPasskeys();
    }, [loadPasskeys]);

    // Computed properties
    const primaryPasskey = useMemo(() => {
        return passkeys.find(passkey => passkey.isPrimary) || passkeys[0] || null;
    }, [passkeys]);

    const passkeyCount = useMemo(() => passkeys.length, [passkeys]);

    return {
        // Passkey state
        passkeys,
        isSupported,
        isAvailable,
        isLoaded: !!user && isPasskeysEnabled,
        isLoading,
        error,

        // Passkey registration
        beginRegistration,
        finishRegistration,
        registerPasskey,

        // Passkey authentication
        beginAuthentication,
        finishAuthentication,
        authenticateWithPasskey,

        // Passkey management
        updatePasskey,
        deletePasskey,
        renamePasskey,

        // Passkey information
        primaryPasskey,
        passkeyCount,

        // Utility methods
        refreshPasskeys,
        checkSupport,
    };
}

// ============================================================================
// Specialized Passkey Hooks
// ============================================================================

/**
 * Hook for passkey registration flow
 */
export function usePasskeyRegistration() {
    const {
        registerPasskey,
        isSupported,
        isAvailable,
        isLoading,
        error,
    } = usePasskeys();

    const [registrationState, setRegistrationState] = useState<'idle' | 'registering' | 'success' | 'error'>('idle');

    const register = useCallback(async (name?: string) => {
        if (!isSupported || !isAvailable) {
            setRegistrationState('error');
            throw new Error('Passkeys not supported or available');
        }

        try {
            setRegistrationState('registering');
            const passkey = await registerPasskey(name);
            setRegistrationState('success');
            return passkey;
        } catch (err) {
            setRegistrationState('error');
            throw err;
        }
    }, [registerPasskey, isSupported, isAvailable]);

    return {
        register,
        state: registrationState,
        isSupported,
        isAvailable,
        isLoading,
        error,
        canRegister: isSupported && isAvailable && !isLoading,
    };
}

/**
 * Hook for passkey authentication flow
 */
export function usePasskeyAuthentication() {
    const {
        authenticateWithPasskey,
        isSupported,
        isAvailable,
        isLoading,
        error,
    } = usePasskeys();

    const [authenticationState, setAuthenticationState] = useState<'idle' | 'authenticating' | 'success' | 'error'>('idle');

    const authenticate = useCallback(async () => {
        if (!isSupported || !isAvailable) {
            setAuthenticationState('error');
            throw new Error('Passkeys not supported or available');
        }

        try {
            setAuthenticationState('authenticating');
            const result = await authenticateWithPasskey();

            if (result.success) {
                setAuthenticationState('success');
            } else {
                setAuthenticationState('error');
            }

            return result;
        } catch (err) {
            setAuthenticationState('error');
            throw err;
        }
    }, [authenticateWithPasskey, isSupported, isAvailable]);

    return {
        authenticate,
        state: authenticationState,
        isSupported,
        isAvailable,
        isLoading,
        error,
        canAuthenticate: isSupported && isAvailable && !isLoading,
    };
}