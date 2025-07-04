/**
 * @frank-auth/react - useUser Hook
 *
 * User-specific operations hook that provides access to user profile management,
 * MFA operations, email/phone verification, and other user-related functionality.
 */

import {useCallback, useMemo, useState} from 'react';

import type {ChangePasswordRequest, User, UserProfileUpdateRequest, VerificationRequest,} from '@frank-auth/client';

import {useAuth} from './use-auth';
import {useConfig} from '../provider/config-provider';

import type {AuthError} from '../provider/types';
import {undefined} from "zod";

// ============================================================================
// User Hook Interface
// ============================================================================

export interface UseUserReturn {
    // User state
    user: User | null;
    isLoaded: boolean;
    isLoading: boolean;
    error: AuthError | null;

    // Profile management
    updateProfile: (data: UserProfileUpdateRequest) => Promise<User>;
    changePassword: (data: ChangePasswordRequest) => Promise<void>;
    deleteAccount: () => Promise<void>;

    // Email management
    updateEmail: (email: string) => Promise<void>;
    verifyEmail: (code: string) => Promise<void>;
    resendEmailVerification: () => Promise<void>;

    // Phone management
    updatePhone: (phone: string) => Promise<void>;
    verifyPhone: (code: string) => Promise<void>;
    resendPhoneVerification: () => Promise<void>;

    // Profile image
    updateProfileImage: (imageUrl: string) => Promise<User>;
    removeProfileImage: () => Promise<User>;

    // Metadata management
    updateMetadata: (metadata: Record<string, any>) => Promise<User>;

    // Convenience properties
    firstName: string | null;
    lastName: string | null;
    fullName: string | null;
    email: string | null;
    phone: string | null;
    profileImageUrl: string | null;
    username: string | null;

    // Verification status
    isEmailVerified: boolean;
    isPhoneVerified: boolean;
    needsEmailVerification: boolean;
    needsPhoneVerification: boolean;

    // Account status
    isActive: boolean;
    isBlocked: boolean;
    createdAt: Date | null;
    lastSignInAt: Date | null;
}

// ============================================================================
// Main useUser Hook
// ============================================================================

/**
 * User management hook providing access to user profile and account operations
 *
 * @example Basic profile management
 * ```tsx
 * import { useUser } from '@frank-auth/react';
 *
 * function UserProfile() {
 *   const { user, updateProfile, isLoading } = useUser();
 *
 *   const handleUpdate = async (data) => {
 *     try {
 *       await updateProfile(data);
 *       toast.success('Profile updated!');
 *     } catch (error) {
 *       toast.error('Failed to update profile');
 *     }
 *   };
 *
 *   if (!user) return <div>Please sign in</div>;
 *
 *   return (
 *     <form onSubmit={(e) => {
 *       e.preventDefault();
 *       const formData = new FormData(e.target);
 *       handleUpdate({
 *         firstName: formData.get('firstName'),
 *         lastName: formData.get('lastName'),
 *       });
 *     }}>
 *       <input name="firstName" defaultValue={user.firstName} />
 *       <input name="lastName" defaultValue={user.lastName} />
 *       <button type="submit" disabled={isLoading}>
 *         Update Profile
 *       </button>
 *     </form>
 *   );
 * }
 * ```
 *
 * @example Email verification
 * ```tsx
 * function EmailVerification() {
 *   const { needsEmailVerification, verifyEmail, resendEmailVerification } = useUser();
 *   const [code, setCode] = useState('');
 *
 *   if (!needsEmailVerification) return null;
 *
 *   return (
 *     <div>
 *       <p>Please verify your email address</p>
 *       <input
 *         value={code}
 *         onChange={(e) => setCode(e.target.value)}
 *         placeholder="Enter verification code"
 *       />
 *       <button onClick={() => verifyEmail(code)}>
 *         Verify
 *       </button>
 *       <button onClick={resendEmailVerification}>
 *         Resend Code
 *       </button>
 *     </div>
 *   );
 * }
 * ```
 */
export function useUser(): UseUserReturn {
    const {user, updateUser, deleteUser, reload, sdk} = useAuth();

    const [isLoading, setIsLoading] = useState(false);
    const [error, setError] = useState<AuthError | null>(null);

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

    // Profile management
    const updateProfile = useCallback(async (data: UserProfileUpdateRequest): Promise<User> => {
        if (!sdk.user) throw new Error('User not authenticated');

        try {
            setIsLoading(true);
            setError(null);

            const updatedUser = await sdk.user.updateProfile(data);
            await reload(); // Refresh auth state

            return updatedUser;
        } catch (err) {
            return handleError(err);
        } finally {
            setIsLoading(false);
        }
    }, [sdk.user, reload, handleError]);

    const changePassword = useCallback(async (data: ChangePasswordRequest): Promise<void> => {
        if (!sdk.user) throw new Error('User not authenticated');

        try {
            setIsLoading(true);
            setError(null);

            await sdk.user.changePassword(data);
        } catch (err) {
            handleError(err);
        } finally {
            setIsLoading(false);
        }
    }, [sdk.user, handleError]);

    const deleteAccount = useCallback(async (): Promise<void> => {
        try {
            setIsLoading(true);
            setError(null);

            await deleteUser();
        } catch (err) {
            handleError(err);
        } finally {
            setIsLoading(false);
        }
    }, [deleteUser, handleError]);

    // Email management
    const updateEmail = useCallback(async (email: string): Promise<void> => {
        try {
            setIsLoading(true);
            setError(null);

            await updateProfile({primaryEmailAddress: email});
        } catch (err) {
            handleError(err);
        } finally {
            setIsLoading(false);
        }
    }, [updateProfile, handleError]);

    const verifyEmail = useCallback(async (code: string): Promise<void> => {
        if (!sdk.user) throw new Error('User not authenticated');

        try {
            setIsLoading(true);
            setError(null);

            const verificationRequest: VerificationRequest = {
                code,
                type: 'email',
            };

            await sdk.auth.verifyEmail(verificationRequest);
            await reload(); // Refresh auth state
        } catch (err) {
            handleError(err);
        } finally {
            setIsLoading(false);
        }
    }, [sdk.user, reload, handleError]);

    const resendEmailVerification = useCallback(async (): Promise<void> => {
        if (!sdk.user || !user?.primaryEmailAddress) throw new Error('User not authenticated');

        try {
            setIsLoading(true);
            setError(null);

            await sdk.user.resendEmailVerification(user.primaryEmailAddress);
        } catch (err) {
            handleError(err);
        } finally {
            setIsLoading(false);
        }
    }, [sdk.user, user?.primaryEmailAddress, handleError]);

    // Phone management
    const updatePhone = useCallback(async (phone: string): Promise<void> => {
        try {
            setIsLoading(true);
            setError(null);

            await updateProfile({primaryPhoneNumber: phone});
        } catch (err) {
            handleError(err);
        } finally {
            setIsLoading(false);
        }
    }, [updateProfile, handleError]);

    const verifyPhone = useCallback(async (code: string): Promise<void> => {
        if (!sdk.user) throw new Error('User not authenticated');

        try {
            setIsLoading(true);
            setError(null);

            const verificationRequest: VerificationRequest = {
                code,
                type: 'phone',
            };

            await sdk.auth.verifyPhone(verificationRequest);
            await reload(); // Refresh auth state
        } catch (err) {
            handleError(err);
        } finally {
            setIsLoading(false);
        }
    }, [sdk.user, reload, handleError]);

    const resendPhoneVerification = useCallback(async (): Promise<void> => {
        if (!sdk.user || !user?.primaryPhoneNumber) throw new Error('User not authenticated');

        try {
            setIsLoading(true);
            setError(null);

            await sdk.user.resendPhoneVerification(user.primaryPhoneNumber);
        } catch (err) {
            handleError(err);
        } finally {
            setIsLoading(false);
        }
    }, [sdk.user, user?.primaryPhoneNumber, handleError]);

    // Profile image management
    const updateProfileImage = useCallback(async (imageUrl: string): Promise<User> => {
        return updateProfile({profileImageUrl: imageUrl});
    }, [updateProfile]);

    const removeProfileImage = useCallback(async (): Promise<User> => {
        return updateProfile({profileImageUrl: undefined()});
    }, [updateProfile]);

    // Metadata management
    const updateMetadata = useCallback(async (metadata: Record<string, any>): Promise<User> => {
        return updateProfile({unsafeMetadata: metadata});
    }, [updateProfile]);

    // Convenience properties
    const firstName = useMemo(() => user?.firstName || null, [user]);
    const lastName = useMemo(() => user?.lastName || null, [user]);
    const fullName = useMemo(() => {
        if (!user) return null;
        const parts = [user.firstName, user.lastName].filter(Boolean);
        return parts.length > 0 ? parts.join(' ') : null;
    }, [user]);

    const email = useMemo(() => user?.primaryEmailAddress || null, [user]);
    const phone = useMemo(() => user?.primaryPhoneNumber || null, [user]);
    const profileImageUrl = useMemo(() => user?.profileImageUrl || null, [user]);
    const username = useMemo(() => user?.username || null, [user]);

    // Verification status
    const isEmailVerified = useMemo(() => user?.emailVerified || false, [user]);
    const isPhoneVerified = useMemo(() => user?.phoneVerified || false, [user]);
    const needsEmailVerification = useMemo(() => !!user && !user.emailVerified, [user]);
    const needsPhoneVerification = useMemo(() => !!user && !!user.primaryPhoneNumber && !user.phoneVerified, [user]);

    // Account status
    const isActive = useMemo(() => user?.active || false, [user]);
    const isBlocked = useMemo(() => user?.blocked || false, [user]);
    const createdAt = useMemo(() => user?.createdAt ? new Date(user.createdAt) : null, [user]);
    const lastSignInAt = useMemo(() => user?.lastSignInAt ? new Date(user.lastSignInAt) : null, [user]);

    return {
        // User state
        user,
        isLoaded: !!user,
        isLoading,
        error,

        // Profile management
        updateProfile,
        changePassword,
        deleteAccount,

        // Email management
        updateEmail,
        verifyEmail,
        resendEmailVerification,

        // Phone management
        updatePhone,
        verifyPhone,
        resendPhoneVerification,

        // Profile image
        updateProfileImage,
        removeProfileImage,

        // Metadata management
        updateMetadata,

        // Convenience properties
        firstName,
        lastName,
        fullName,
        email,
        phone,
        profileImageUrl,
        username,

        // Verification status
        isEmailVerified,
        isPhoneVerified,
        needsEmailVerification,
        needsPhoneVerification,

        // Account status
        isActive,
        isBlocked,
        createdAt,
        lastSignInAt,
    };
}

// ============================================================================
// Specialized User Hooks
// ============================================================================

/**
 * Hook for user profile data only (no methods)
 */
export function useUserProfile() {
    const {
        user,
        firstName,
        lastName,
        fullName,
        email,
        phone,
        profileImageUrl,
        username,
        isEmailVerified,
        isPhoneVerified,
        isActive,
        isBlocked,
        createdAt,
        lastSignInAt,
    } = useUser();

    return {
        user,
        firstName,
        lastName,
        fullName,
        email,
        phone,
        profileImageUrl,
        username,
        isEmailVerified,
        isPhoneVerified,
        isActive,
        isBlocked,
        createdAt,
        lastSignInAt,
    };
}

/**
 * Hook for user verification operations
 */
export function useUserVerification() {
    const {
        isEmailVerified,
        isPhoneVerified,
        needsEmailVerification,
        needsPhoneVerification,
        verifyEmail,
        verifyPhone,
        resendEmailVerification,
        resendPhoneVerification,
        isLoading,
        error,
    } = useUser();

    return {
        isEmailVerified,
        isPhoneVerified,
        needsEmailVerification,
        needsPhoneVerification,
        verifyEmail,
        verifyPhone,
        resendEmailVerification,
        resendPhoneVerification,
        isLoading,
        error,
        needsVerification: needsEmailVerification || needsPhoneVerification,
    };
}

/**
 * Hook for user profile management operations
 */
export function useUserActions() {
    const {
        updateProfile,
        changePassword,
        deleteAccount,
        updateEmail,
        updatePhone,
        updateProfileImage,
        removeProfileImage,
        updateMetadata,
        isLoading,
        error,
    } = useUser();

    return {
        updateProfile,
        changePassword,
        deleteAccount,
        updateEmail,
        updatePhone,
        updateProfileImage,
        removeProfileImage,
        updateMetadata,
        isLoading,
        error,
    };
}