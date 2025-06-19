/**
 * @frank-auth/react - useMFA Hook
 *
 * Multi-Factor Authentication hook that provides comprehensive MFA management
 * including TOTP, SMS, email, backup codes, and WebAuthn authentication.
 */

import {useCallback, useEffect, useMemo, useState} from 'react';

import type {
    MFAMethod,
    MFAVerifyRequest,
    MFAVerifyResponse,
    SetupMFARequest,
    VerifyMFASetupRequest,
} from '@frank-auth/client';

import {FrankUser} from '@frank-auth/sdk';
import {useAuth} from './use-auth';
import {useConfig} from '../provider/config-provider';

import type {AuthError} from '../provider/types';

// ============================================================================
// MFA Hook Interface
// ============================================================================

export interface UseMFAReturn {
    // MFA state
    mfaMethods: MFAMethod[];
    isEnabled: boolean;
    isRequired: boolean;
    primaryMethod: MFAMethod | null;
    backupCodes: string[];
    isLoaded: boolean;
    isLoading: boolean;
    error: AuthError | null;

    // MFA setup
    setupTOTP: () => Promise<MFASetupData>;
    setupSMS: (phoneNumber: string) => Promise<MFASetupData>;
    setupEmail: (email?: string) => Promise<MFASetupData>;
    setupWebAuthn: () => Promise<MFASetupData>;

    // MFA verification during setup
    verifySetup: (method: string, code: string, methodId?: string) => Promise<MFAMethod>;

    // MFA verification during authentication
    verifyMFA: (method: string, code: string, token: string) => Promise<MFAVerifyResponse>;

    // Method management
    removeMFAMethod: (methodId: string) => Promise<void>;
    setPrimaryMethod: (methodId: string) => Promise<void>;
    regenerateBackupCodes: () => Promise<string[]>;

    // MFA status checking
    hasTOTP: boolean;
    hasSMS: boolean;
    hasEmail: boolean;
    hasWebAuthn: boolean;
    hasBackupCodes: boolean;

    // Method availability
    availableMethods: MFAMethodType[];

    // Convenience methods
    disable: () => Promise<void>;
    enable: () => Promise<void>;
    refreshMethods: () => Promise<void>;
}

export interface MFASetupData {
    method: string;
    qrCode?: string;
    secret?: string;
    backupCodes?: string[];
    challenge?: any;
    verificationRequired: boolean;
}

export type MFAMethodType = 'totp' | 'sms' | 'email' | 'webauthn' | 'backup_codes';

// ============================================================================
// MFA Method Configurations
// ============================================================================

export const MFA_METHOD_CONFIGS = {
    totp: {
        name: 'Authenticator App',
        description: 'Use an authenticator app like Google Authenticator or Authy',
        icon: '📱',
        setupSteps: [
            'Install an authenticator app on your phone',
            'Scan the QR code or enter the secret key',
            'Enter the 6-digit code from your app',
        ],
    },
    sms: {
        name: 'SMS',
        description: 'Receive codes via text message',
        icon: '💬',
        setupSteps: [
            'Enter your phone number',
            'Wait for the verification code',
            'Enter the code to confirm',
        ],
    },
    email: {
        name: 'Email',
        description: 'Receive codes via email',
        icon: '✉️',
        setupSteps: [
            'Confirm your email address',
            'Wait for the verification code',
            'Enter the code to confirm',
        ],
    },
    webauthn: {
        name: 'Security Key',
        description: 'Use a hardware security key or biometric authentication',
        icon: '🔐',
        setupSteps: [
            'Insert your security key or prepare biometric authentication',
            'Follow your browser\'s authentication prompts',
            'Confirm the registration',
        ],
    },
    backup_codes: {
        name: 'Backup Codes',
        description: 'Single-use codes for emergency access',
        icon: '🔢',
        setupSteps: [
            'Save these codes in a secure location',
            'Each code can only be used once',
            'Generate new codes when running low',
        ],
    },
} as const;

// ============================================================================
// Main useMFA Hook
// ============================================================================

/**
 * Multi-Factor Authentication hook providing comprehensive MFA management
 *
 * @example Basic MFA setup
 * ```tsx
 * import { useMFA } from '@frank-auth/react';
 *
 * function MFASetup() {
 *   const {
 *     isEnabled,
 *     setupTOTP,
 *     verifySetup,
 *     mfaMethods,
 *     isLoading
 *   } = useMFA();
 *
 *   const [setupData, setSetupData] = useState(null);
 *   const [verificationCode, setVerificationCode] = useState('');
 *
 *   const handleSetupTOTP = async () => {
 *     try {
 *       const data = await setupTOTP();
 *       setSetupData(data);
 *     } catch (error) {
 *       console.error('Setup failed:', error);
 *     }
 *   };
 *
 *   const handleVerifySetup = async () => {
 *     try {
 *       await verifySetup('totp', verificationCode);
 *       alert('MFA setup complete!');
 *       setSetupData(null);
 *     } catch (error) {
 *       console.error('Verification failed:', error);
 *     }
 *   };
 *
 *   if (isEnabled) {
 *     return (
 *       <div>
 *         <h3>MFA is enabled</h3>
 *         <p>Active methods: {mfaMethods.length}</p>
 *       </div>
 *     );
 *   }
 *
 *   return (
 *     <div>
 *       {!setupData ? (
 *         <button onClick={handleSetupTOTP} disabled={isLoading}>
 *           Setup Authenticator App
 *         </button>
 *       ) : (
 *         <div>
 *           <img src={setupData.qrCode} alt="QR Code" />
 *           <p>Secret: {setupData.secret}</p>
 *           <input
 *             value={verificationCode}
 *             onChange={(e) => setVerificationCode(e.target.value)}
 *             placeholder="Enter 6-digit code"
 *           />
 *           <button onClick={handleVerifySetup}>
 *             Verify & Enable
 *           </button>
 *         </div>
 *       )}
 *     </div>
 *   );
 * }
 * ```
 *
 * @example MFA verification during login
 * ```tsx
 * function MFAVerification({ mfaToken, onSuccess }) {
 *   const { verifyMFA, availableMethods } = useMFA();
 *   const [selectedMethod, setSelectedMethod] = useState('totp');
 *   const [code, setCode] = useState('');
 *
 *   const handleVerify = async () => {
 *     try {
 *       const result = await verifyMFA(selectedMethod, code, mfaToken);
 *       if (result.success) {
 *         onSuccess(result.session);
 *       }
 *     } catch (error) {
 *       console.error('MFA verification failed:', error);
 *     }
 *   };
 *
 *   return (
 *     <div>
 *       <h3>Enter your verification code</h3>
 *       <select
 *         value={selectedMethod}
 *         onChange={(e) => setSelectedMethod(e.target.value)}
 *       >
 *         {availableMethods.map(method => (
 *           <option key={method} value={method}>
 *             {MFA_METHOD_CONFIGS[method].name}
 *           </option>
 *         ))}
 *       </select>
 *       <input
 *         value={code}
 *         onChange={(e) => setCode(e.target.value)}
 *         placeholder="Enter code"
 *       />
 *       <button onClick={handleVerify}>Verify</button>
 *     </div>
 *   );
 * }
 * ```
 *
 * @example MFA method management
 * ```tsx
 * function MFAManagement() {
 *   const {
 *     mfaMethods,
 *     removeMFAMethod,
 *     setPrimaryMethod,
 *     regenerateBackupCodes,
 *     backupCodes
 *   } = useMFA();
 *
 *   return (
 *     <div>
 *       <h3>Your MFA Methods</h3>
 *       {mfaMethods.map(method => (
 *         <div key={method.id}>
 *           <span>{method.type} - {method.name}</span>
 *           {method.isPrimary && <span>(Primary)</span>}
 *           <button onClick={() => setPrimaryMethod(method.id)}>
 *             Set as Primary
 *           </button>
 *           <button onClick={() => removeMFAMethod(method.id)}>
 *             Remove
 *           </button>
 *         </div>
 *       ))}
 *
 *       <h4>Backup Codes</h4>
 *       <ul>
 *         {backupCodes.map((code, index) => (
 *           <li key={index}>{code}</li>
 *         ))}
 *       </ul>
 *       <button onClick={regenerateBackupCodes}>
 *         Generate New Backup Codes
 *       </button>
 *     </div>
 *   );
 * }
 * ```
 */
export function useMFA(): UseMFAReturn {
    const { user, session, reload } = useAuth();
    const { apiUrl, publishableKey, features } = useConfig();

    const [mfaMethods, setMFAMethods] = useState<MFAMethod[]>([]);
    const [backupCodes, setBackupCodes] = useState<string[]>([]);
    const [isLoading, setIsLoading] = useState(false);
    const [error, setError] = useState<AuthError | null>(null);

    // Initialize Frank User SDK
    const frankUser = useMemo(() => {
        if (!session?.accessToken) return null;
        return new FrankUser({
            publishableKey,
            apiUrl,
        }, session.accessToken);
    }, [publishableKey, apiUrl, session?.accessToken]);

    // Check if MFA is available
    const isMFAAvailable = useMemo(() => features.mfa, [features.mfa]);

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

    // Load MFA methods and backup codes
    const loadMFAData = useCallback(async () => {
        if (!frankUser || !user || !isMFAAvailable) return;

        try {
            setIsLoading(true);
            setError(null);

            // Load MFA methods
            const methods = await frankUser.getMFAMethods();
            setMFAMethods(methods.data || []);

            // Load backup codes if MFA is enabled
            if (user.mfaEnabled) {
                try {
                    const codes = await frankUser.getMFABackupCodes();
                    setBackupCodes(codes.codes || []);
                } catch (backupError) {
                    // Backup codes might not be set up yet
                    console.warn('Could not load backup codes:', backupError);
                }
            }
        } catch (err) {
            console.error('Failed to load MFA data:', err);
            setError({
                code: 'MFA_LOAD_FAILED',
                message: 'Failed to load MFA data',
            });
        } finally {
            setIsLoading(false);
        }
    }, [frankUser, user, isMFAAvailable]);

    useEffect(() => {
        loadMFAData();
    }, [loadMFAData]);

    // MFA setup methods
    const setupTOTP = useCallback(async (): Promise<MFASetupData> => {
        if (!frankUser) throw new Error('User not authenticated');
        if (!isMFAAvailable) throw new Error('MFA not available');

        try {
            setIsLoading(true);
            setError(null);

            const setupRequest: SetupMFARequest = {
                method: 'totp',
            };

            const response = await frankUser.setupMFA(setupRequest);

            return {
                method: 'totp',
                qrCode: response.qrCode,
                secret: response.secret,
                backupCodes: response.backupCodes,
                verificationRequired: true,
            };
        } catch (err) {
            return handleError(err);
        } finally {
            setIsLoading(false);
        }
    }, [frankUser, isMFAAvailable, handleError]);

    const setupSMS = useCallback(async (phoneNumber: string): Promise<MFASetupData> => {
        if (!frankUser) throw new Error('User not authenticated');
        if (!isMFAAvailable) throw new Error('MFA not available');

        try {
            setIsLoading(true);
            setError(null);

            const setupRequest: SetupMFARequest = {
                method: 'sms',
                phoneNumber,
            };

            const response = await frankUser.setupMFA(setupRequest);

            return {
                method: 'sms',
                verificationRequired: true,
            };
        } catch (err) {
            return handleError(err);
        } finally {
            setIsLoading(false);
        }
    }, [frankUser, isMFAAvailable, handleError]);

    const setupEmail = useCallback(async (email?: string): Promise<MFASetupData> => {
        if (!frankUser) throw new Error('User not authenticated');
        if (!isMFAAvailable) throw new Error('MFA not available');

        try {
            setIsLoading(true);
            setError(null);

            const setupRequest: SetupMFARequest = {
                method: 'email',
                email: email || user?.primaryEmailAddress,
            };

            const response = await frankUser.setupMFA(setupRequest);

            return {
                method: 'email',
                verificationRequired: true,
            };
        } catch (err) {
            return handleError(err);
        } finally {
            setIsLoading(false);
        }
    }, [frankUser, user, isMFAAvailable, handleError]);

    const setupWebAuthn = useCallback(async (): Promise<MFASetupData> => {
        if (!frankUser) throw new Error('User not authenticated');
        if (!isMFAAvailable) throw new Error('MFA not available');

        try {
            setIsLoading(true);
            setError(null);

            const setupRequest: SetupMFARequest = {
                method: 'webauthn',
            };

            const response = await frankUser.setupMFA(setupRequest);

            return {
                method: 'webauthn',
                challenge: response.challenge,
                verificationRequired: true,
            };
        } catch (err) {
            return handleError(err);
        } finally {
            setIsLoading(false);
        }
    }, [frankUser, isMFAAvailable, handleError]);

    // MFA verification during setup
    const verifySetup = useCallback(async (method: string, code: string, methodId?: string): Promise<MFAMethod> => {
        if (!frankUser) throw new Error('User not authenticated');

        try {
            setIsLoading(true);
            setError(null);

            const verifyRequest: VerifyMFASetupRequest = {
                method,
                code,
                methodId,
            };

            const response = await frankUser.verifyMFASetup(verifyRequest);

            // Refresh MFA data and user state
            await loadMFAData();
            await reload();

            return response.method;
        } catch (err) {
            return handleError(err);
        } finally {
            setIsLoading(false);
        }
    }, [frankUser, loadMFAData, reload, handleError]);

    // MFA verification during authentication
    const verifyMFA = useCallback(async (method: string, code: string, token: string): Promise<MFAVerifyResponse> => {
        if (!frankUser) throw new Error('User not authenticated');

        try {
            setIsLoading(true);
            setError(null);

            const verifyRequest: MFAVerifyRequest = {
                method,
                code,
                mfaToken: token,
                context: 'login',
            };

            const response = await frankUser.verifyMFA(verifyRequest);

            return response;
        } catch (err) {
            return handleError(err);
        } finally {
            setIsLoading(false);
        }
    }, [frankUser, handleError]);

    // Method management
    const removeMFAMethod = useCallback(async (methodId: string): Promise<void> => {
        if (!frankUser) throw new Error('User not authenticated');

        try {
            setIsLoading(true);
            setError(null);

            await frankUser.removeMFAMethod(methodId);

            // Refresh MFA data
            await loadMFAData();
            await reload();
        } catch (err) {
            handleError(err);
        } finally {
            setIsLoading(false);
        }
    }, [frankUser, loadMFAData, reload, handleError]);

    const setPrimaryMethod = useCallback(async (methodId: string): Promise<void> => {
        if (!frankUser) throw new Error('User not authenticated');

        try {
            setIsLoading(true);
            setError(null);

            await frankUser.setPrimaryMFAMethod(methodId);

            // Refresh MFA data
            await loadMFAData();
        } catch (err) {
            handleError(err);
        } finally {
            setIsLoading(false);
        }
    }, [frankUser, loadMFAData, handleError]);

    const regenerateBackupCodes = useCallback(async (): Promise<string[]> => {
        if (!frankUser) throw new Error('User not authenticated');

        try {
            setIsLoading(true);
            setError(null);

            const response = await frankUser.regenerateMFABackupCodes();

            setBackupCodes(response.codes);
            return response.codes;
        } catch (err) {
            return handleError(err);
        } finally {
            setIsLoading(false);
        }
    }, [frankUser, handleError]);

    // MFA status and method checking
    const isEnabled = useMemo(() => user?.mfaEnabled || false, [user]);
    const isRequired = useMemo(() => {
        // Check organization settings or user-specific requirements
        return false; // This would be determined by organization policy
    }, []);

    const primaryMethod = useMemo(() => {
        return mfaMethods.find(method => method.isPrimary) || null;
    }, [mfaMethods]);

    const hasTOTP = useMemo(() =>
            mfaMethods.some(method => method.type === 'totp'),
        [mfaMethods]
    );

    const hasSMS = useMemo(() =>
            mfaMethods.some(method => method.type === 'sms'),
        [mfaMethods]
    );

    const hasEmail = useMemo(() =>
            mfaMethods.some(method => method.type === 'email'),
        [mfaMethods]
    );

    const hasWebAuthn = useMemo(() =>
            mfaMethods.some(method => method.type === 'webauthn'),
        [mfaMethods]
    );

    const hasBackupCodes = useMemo(() =>
            backupCodes.length > 0,
        [backupCodes]
    );

    // Available methods (configured methods)
    const availableMethods = useMemo((): MFAMethodType[] => {
        const methods: MFAMethodType[] = [];

        if (hasTOTP) methods.push('totp');
        if (hasSMS) methods.push('sms');
        if (hasEmail) methods.push('email');
        if (hasWebAuthn) methods.push('webauthn');
        if (hasBackupCodes) methods.push('backup_codes');

        return methods;
    }, [hasTOTP, hasSMS, hasEmail, hasWebAuthn, hasBackupCodes]);

    // Convenience methods
    const disable = useCallback(async (): Promise<void> => {
        if (!frankUser) throw new Error('User not authenticated');

        try {
            setIsLoading(true);
            setError(null);

            await frankUser.disableMFA();

            // Clear local state
            setMFAMethods([]);
            setBackupCodes([]);

            await reload();
        } catch (err) {
            handleError(err);
        } finally {
            setIsLoading(false);
        }
    }, [frankUser, reload, handleError]);

    const enable = useCallback(async (): Promise<void> => {
        if (!frankUser) throw new Error('User not authenticated');

        try {
            setIsLoading(true);
            setError(null);

            await frankUser.enableMFA();
            await reload();
        } catch (err) {
            handleError(err);
        } finally {
            setIsLoading(false);
        }
    }, [frankUser, reload, handleError]);

    const refreshMethods = useCallback(async (): Promise<void> => {
        await loadMFAData();
    }, [loadMFAData]);

    return {
        // MFA state
        mfaMethods,
        isEnabled,
        isRequired,
        primaryMethod,
        backupCodes,
        isLoaded: !!user && isMFAAvailable,
        isLoading,
        error,

        // MFA setup
        setupTOTP,
        setupSMS,
        setupEmail,
        setupWebAuthn,

        // MFA verification
        verifySetup,
        verifyMFA,

        // Method management
        removeMFAMethod,
        setPrimaryMethod,
        regenerateBackupCodes,

        // MFA status checking
        hasTOTP,
        hasSMS,
        hasEmail,
        hasWebAuthn,
        hasBackupCodes,

        // Method availability
        availableMethods,

        // Convenience methods
        disable,
        enable,
        refreshMethods,
    };
}

// ============================================================================
// Specialized MFA Hooks
// ============================================================================

/**
 * Hook for TOTP (Time-based One-Time Password) management
 */
export function useTOTP() {
    const {
        setupTOTP,
        verifySetup,
        hasTOTP,
        mfaMethods,
        removeMFAMethod,
        isLoading,
        error,
    } = useMFA();

    const totpMethod = useMemo(() =>
            mfaMethods.find(method => method.type === 'totp'),
        [mfaMethods]
    );

    return {
        isEnabled: hasTOTP,
        method: totpMethod,
        setup: setupTOTP,
        verify: (code: string) => verifySetup('totp', code),
        remove: totpMethod ? () => removeMFAMethod(totpMethod.id) : undefined,
        isLoading,
        error,
    };
}

/**
 * Hook for SMS MFA management
 */
export function useSMSMFA() {
    const {
        setupSMS,
        verifySetup,
        hasSMS,
        mfaMethods,
        removeMFAMethod,
        isLoading,
        error,
    } = useMFA();

    const smsMethod = useMemo(() =>
            mfaMethods.find(method => method.type === 'sms'),
        [mfaMethods]
    );

    return {
        isEnabled: hasSMS,
        method: smsMethod,
        setup: setupSMS,
        verify: (code: string) => verifySetup('sms', code),
        remove: smsMethod ? () => removeMFAMethod(smsMethod.id) : undefined,
        phoneNumber: smsMethod?.phoneNumber || null,
        isLoading,
        error,
    };
}

/**
 * Hook for backup codes management
 */
export function useBackupCodes() {
    const {
        backupCodes,
        regenerateBackupCodes,
        hasBackupCodes,
        isLoading,
        error,
    } = useMFA();

    const unusedCodes = useMemo(() =>
            backupCodes.filter(code => !code.used),
        [backupCodes]
    );

    const usedCodes = useMemo(() =>
            backupCodes.filter(code => code.used),
        [backupCodes]
    );

    return {
        codes: backupCodes,
        unusedCodes,
        usedCodes,
        hasBackupCodes,
        regenerate: regenerateBackupCodes,
        remainingCodes: unusedCodes.length,
        totalCodes: backupCodes.length,
        isRunningLow: unusedCodes.length <= 2,
        isLoading,
        error,
    };
}