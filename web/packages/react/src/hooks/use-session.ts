/**
 * @frank-auth/react - useSession Hook
 *
 * Session management hook that provides access to session operations,
 * multi-session handling, and session security features.
 */

import {useCallback, useEffect, useMemo, useState} from 'react';

import type {Session, SessionInfo} from '@frank-auth/client';
import {FrankSession} from '@frank-auth/sdk';

import {useAuth} from './use-auth';
import {useConfig} from '../provider/config-provider';

import type {AuthError} from '../provider/types';

// ============================================================================
// Session Hook Interface
// ============================================================================

export interface UseSessionReturn {
    // Session state
    session: Session | null;
    sessions: SessionInfo[];
    isLoaded: boolean;
    isLoading: boolean;
    error: AuthError | null;

    // Session management
    createSession: (token: string) => Promise<Session>;
    setActiveSession: (sessionId: string) => Promise<void>;
    refreshSession: () => Promise<Session | null>;
    revokeSession: (sessionId: string) => Promise<void>;
    revokeAllSessions: (exceptCurrent?: boolean) => Promise<void>;
    endSession: () => Promise<void>;

    // Session information
    sessionId: string | null;
    sessionToken: string | null;
    expiresAt: Date | null;
    lastActiveAt: Date | null;

    // Session status
    isActive: boolean;
    isExpired: boolean;
    isExpiring: boolean; // Expires within 5 minutes
    timeUntilExpiry: number | null; // Minutes until expiry

    // Device information
    deviceInfo: DeviceInfo | null;

    // Security features
    isCurrentDevice: boolean;
    isTrustedDevice: boolean;

    // Multi-session support
    hasMultipleSessions: boolean;
    sessionCount: number;
    otherSessions: SessionInfo[];
}

export interface DeviceInfo {
    userAgent: string;
    browser: string;
    os: string;
    device: string;
    ipAddress: string;
    location?: {
        city?: string;
        country?: string;
        region?: string;
    };
}

// ============================================================================
// Main useSession Hook
// ============================================================================

/**
 * Session management hook providing access to all session functionality
 *
 * @example Basic session management
 * ```tsx
 * import { useSession } from '@frank-auth/react';
 *
 * function SessionManager() {
 *   const {
 *     session,
 *     sessions,
 *     revokeSession,
 *     revokeAllSessions,
 *     isExpiring
 *   } = useSession();
 *
 *   if (isExpiring) {
 *     return (
 *       <div className="session-warning">
 *         <p>Your session is about to expire</p>
 *         <button onClick={refreshSession}>Extend Session</button>
 *       </div>
 *     );
 *   }
 *
 *   return (
 *     <div>
 *       <h3>Active Sessions ({sessions.length})</h3>
 *       {sessions.map((session) => (
 *         <div key={session.id}>
 *           <p>{session.deviceInfo?.browser} on {session.deviceInfo?.os}</p>
 *           <p>Last active: {session.lastActiveAt}</p>
 *           <button onClick={() => revokeSession(session.id)}>
 *             Revoke Session
 *           </button>
 *         </div>
 *       ))}
 *       <button onClick={() => revokeAllSessions(true)}>
 *         Revoke All Other Sessions
 *       </button>
 *     </div>
 *   );
 * }
 * ```
 *
 * @example Session expiry warning
 * ```tsx
 * function SessionExpiryWarning() {
 *   const { isExpiring, timeUntilExpiry, refreshSession } = useSession();
 *
 *   if (!isExpiring || !timeUntilExpiry) return null;
 *
 *   return (
 *     <div className="alert alert-warning">
 *       <p>Session expires in {timeUntilExpiry} minutes</p>
 *       <button onClick={refreshSession}>
 *         Extend Session
 *       </button>
 *     </div>
 *   );
 * }
 * ```
 */
export function useSession(): UseSessionReturn {
    const { session, createSession: authCreateSession, reload } = useAuth();
    const { apiUrl, publishableKey } = useConfig();

    const [sessions, setSessions] = useState<SessionInfo[]>([]);
    const [isLoading, setIsLoading] = useState(false);
    const [error, setError] = useState<AuthError | null>(null);

    // Initialize Frank Session SDK
    const frankSession = useMemo(() => {
        if (!session?.accessToken) return null;
        return new FrankSession({
            publishableKey,
            apiUrl,
        }, session.accessToken);
    }, [publishableKey, apiUrl, session?.accessToken]);

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

    // Load sessions on mount and session change
    const loadSessions = useCallback(async () => {
        if (!frankSession) return;

        try {
            setIsLoading(true);
            setError(null);

            const sessionsData = await frankSession.listSessions();
            setSessions(sessionsData.data as any);
        } catch (err) {
            console.error('Failed to load sessions:', err);
            setError({
                code: 'SESSIONS_LOAD_FAILED',
                message: 'Failed to load sessions',
            });
        } finally {
            setIsLoading(false);
        }
    }, [frankSession]);

    useEffect(() => {
        loadSessions();
    }, [loadSessions]);

    // Session management methods
    const createSession = useCallback(async (token: string): Promise<Session> => {
        return authCreateSession(token);
    }, [authCreateSession]);

    const setActiveSession = useCallback(async (sessionId: string): Promise<void> => {
        if (!frankSession) throw new Error('Session not available');

        try {
            setIsLoading(true);
            setError(null);

            frankSession.setActiveSession(sessionId);
            await reload(); // Refresh auth state
            await loadSessions(); // Refresh sessions list
        } catch (err) {
            handleError(err);
        } finally {
            setIsLoading(false);
        }
    }, [frankSession, reload, loadSessions, handleError]);

    const refreshSession = useCallback(async (): Promise<Session | null> => {
        if (!frankSession) throw new Error('Session not available');

        try {
            setIsLoading(true);
            setError(null);

            const refreshedSession = await frankSession.refreshSession();
            await reload(); // Refresh auth state

            return refreshedSession;
        } catch (err) {
            handleError(err);
            return null;
        } finally {
            setIsLoading(false);
        }
    }, [frankSession, reload, handleError]);

    const revokeSession = useCallback(async (sessionId: string): Promise<void> => {
        if (!frankSession) throw new Error('Session not available');

        try {
            setIsLoading(true);
            setError(null);

            await frankSession.revokeSession(sessionId);

            // If we revoked the current session, reload auth state
            if (sessionId === session?.id) {
                await reload();
            } else {
                // Just refresh the sessions list
                await loadSessions();
            }
        } catch (err) {
            handleError(err);
        } finally {
            setIsLoading(false);
        }
    }, [frankSession, session?.id, reload, loadSessions, handleError]);

    const revokeAllSessions = useCallback(async (exceptCurrent = false): Promise<void> => {
        if (!frankSession) throw new Error('Session not available');

        try {
            setIsLoading(true);
            setError(null);

            await frankSession.revokeAllSessions({
                exceptCurrent,
            });

            if (!exceptCurrent) {
                // All sessions revoked, user is signed out
                await reload();
            } else {
                // Only other sessions revoked, refresh sessions list
                await loadSessions();
            }
        } catch (err) {
            handleError(err);
        } finally {
            setIsLoading(false);
        }
    }, [frankSession, reload, loadSessions, handleError]);

    const endSession = useCallback(async (): Promise<void> => {
        if (!frankSession) throw new Error('Session not available');

        try {
            setIsLoading(true);
            setError(null);

            // await frankSession.endSession();
            await reload(); // This will sign out the user
        } catch (err) {
            handleError(err);
        } finally {
            setIsLoading(false);
        }
    }, [frankSession, reload, handleError]);

    // Session information
    const sessionId = useMemo(() => session?.id || null, [session]);
    const sessionToken = useMemo(() => session?.accessToken || null, [session]);
    const expiresAt = useMemo(() =>
            session?.expiresAt ? new Date(session.expiresAt) : null,
        [session]
    );
    const lastActiveAt = useMemo(() =>
            session?.lastActiveAt ? new Date(session.lastActiveAt) : null,
        [session]
    );

    // Session status
    const isActive = useMemo(() => !!session && !session.expired, [session]);
    const isExpired = useMemo(() => {
        if (!expiresAt) return false;
        return expiresAt.getTime() <= Date.now();
    }, [expiresAt]);

    const isExpiring = useMemo(() => {
        if (!expiresAt) return false;
        const fiveMinutesFromNow = Date.now() + (5 * 60 * 1000);
        return expiresAt.getTime() <= fiveMinutesFromNow && !isExpired;
    }, [expiresAt, isExpired]);

    const timeUntilExpiry = useMemo(() => {
        if (!expiresAt) return null;
        const msUntilExpiry = expiresAt.getTime() - Date.now();
        return Math.max(0, Math.floor(msUntilExpiry / 60000)); // Convert to minutes
    }, [expiresAt]);

    // Device information
    const deviceInfo = useMemo((): DeviceInfo | null => {
        if (!session?.deviceInfo) return null;

        return {
            userAgent: session.deviceInfo.userAgent || '',
            browser: session.deviceInfo.browser || 'Unknown',
            os: session.deviceInfo.os || 'Unknown',
            device: session.deviceInfo.device || 'Unknown',
            ipAddress: session.deviceInfo.ipAddress || '',
            location: session.deviceInfo.location,
        };
    }, [session]);

    // Security features
    const isCurrentDevice = useMemo(() => {
        if (!session || !deviceInfo) return false;

        // Check if this is the current device by comparing user agent
        return typeof navigator !== 'undefined' &&
            deviceInfo.userAgent === navigator.userAgent;
    }, [session, deviceInfo]);

    const isTrustedDevice = useMemo(() =>
            session?.trustedDevice || false,
        [session]
    );

    // Multi-session support
    const hasMultipleSessions = useMemo(() => sessions.length > 1, [sessions]);
    const sessionCount = useMemo(() => sessions.length, [sessions]);
    const otherSessions = useMemo(() =>
            sessions.filter(s => s.id !== sessionId),
        [sessions, sessionId]
    );

    return {
        // Session state
        session,
        sessions,
        isLoaded: !!session,
        isLoading,
        error,

        // Session management
        createSession,
        setActiveSession,
        refreshSession,
        revokeSession,
        revokeAllSessions,
        endSession,

        // Session information
        sessionId,
        sessionToken,
        expiresAt,
        lastActiveAt,

        // Session status
        isActive,
        isExpired,
        isExpiring,
        timeUntilExpiry,

        // Device information
        deviceInfo,

        // Security features
        isCurrentDevice,
        isTrustedDevice,

        // Multi-session support
        hasMultipleSessions,
        sessionCount,
        otherSessions,
    };
}

// ============================================================================
// Specialized Session Hooks
// ============================================================================

/**
 * Hook for session status monitoring
 */
export function useSessionStatus() {
    const {
        isActive,
        isExpired,
        isExpiring,
        timeUntilExpiry,
        expiresAt,
        refreshSession,
    } = useSession();

    return {
        isActive,
        isExpired,
        isExpiring,
        timeUntilExpiry,
        expiresAt,
        refreshSession,
        status: isExpired ? 'expired' : isExpiring ? 'expiring' : isActive ? 'active' : 'inactive',
    };
}

/**
 * Hook for multi-session management
 */
export function useMultiSession() {
    const {
        sessions,
        sessionCount,
        otherSessions,
        hasMultipleSessions,
        revokeSession,
        revokeAllSessions,
        setActiveSession,
        isLoading,
        error,
    } = useSession();

    return {
        sessions,
        sessionCount,
        otherSessions,
        hasMultipleSessions,
        revokeSession,
        revokeAllSessions,
        setActiveSession,
        isLoading,
        error,
        revokeAllOthers: () => revokeAllSessions(true),
    };
}

/**
 * Hook for device and security information
 */
export function useSessionSecurity() {
    const {
        deviceInfo,
        isCurrentDevice,
        isTrustedDevice,
        sessionId,
        lastActiveAt,
    } = useSession();

    return {
        deviceInfo,
        isCurrentDevice,
        isTrustedDevice,
        sessionId,
        lastActiveAt,
        isSecure: isTrustedDevice && isCurrentDevice,
    };
}

// ============================================================================
// Session Expiry Hook with Auto-refresh
// ============================================================================

/**
 * Hook that automatically handles session expiry and refresh
 */
export function useSessionExpiry(options: {
    autoRefresh?: boolean;
    refreshThreshold?: number; // Minutes before expiry to refresh
    onExpiry?: () => void;
    onExpiring?: () => void;
} = {}) {
    const {
        autoRefresh = false,
        refreshThreshold = 5,
        onExpiry,
        onExpiring,
    } = options;

    const {
        isExpired,
        isExpiring,
        timeUntilExpiry,
        refreshSession,
    } = useSession();

    // Auto-refresh when approaching expiry
    useEffect(() => {
        if (autoRefresh && isExpiring && timeUntilExpiry && timeUntilExpiry <= refreshThreshold) {
            refreshSession().catch(console.error);
        }
    }, [autoRefresh, isExpiring, timeUntilExpiry, refreshThreshold, refreshSession]);

    // Handle expiry callback
    useEffect(() => {
        if (isExpired) {
            onExpiry?.();
        }
    }, [isExpired, onExpiry]);

    // Handle expiring callback
    useEffect(() => {
        if (isExpiring) {
            onExpiring?.();
        }
    }, [isExpiring, onExpiring]);

    return {
        isExpired,
        isExpiring,
        timeUntilExpiry,
        refreshSession,
        autoRefresh,
    };
}
