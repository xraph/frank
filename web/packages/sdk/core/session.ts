import {AuthenticationApi, Configuration, PaginatedOutputSessionInfo, Session, SessionInfo,} from '@frank-auth/client';

import {FrankAuthConfig} from './index';
import {handleError} from './errors';

export class FrankSession {
    private config: FrankAuthConfig;
    private authenticationApi: AuthenticationApi;
    private accessToken: string | null = null;
    private activeSessionId?: string | null = null;

    constructor(config: FrankAuthConfig, accessToken?: string) {
        this.config = config;
        this.accessToken = accessToken || null;

        const configuration = new Configuration({
            basePath: config.apiUrl,
            accessToken: () => this.accessToken || '',
            credentials: 'include',
            headers: {
                'X-Publishable-Key': config.publishableKey,
            },
        });

        this.authenticationApi = new AuthenticationApi(configuration);
    }

    // Update access token (called by FrankAuth when token changes)
    setAccessToken(token: string | null): void {
        this.accessToken = token;
    }

    // Update access token (called by FrankAuth when token changes)
    setActiveSession(session: string | null): void {
        this.activeSessionId = session;
    }

    // List all active sessions for the current user
    async listSessions(options?: {
        after?: string;
        before?: string;
        first?: number;
        last?: number;
        limit?: number;
        offset?: number;
        fields?: string[];
        orderBy?: string[];
        page?: number;
        userId?: string;
    }): Promise<PaginatedOutputSessionInfo> {
        try {
            return await this.authenticationApi.listSessions({
                after: options?.after,
                before: options?.before,
                first: options?.first,
                last: options?.last,
                limit: options?.limit,
                offset: options?.offset,
                fields: options?.fields,
                orderBy: options?.orderBy,
                page: options?.page,
                userId: options?.userId,
            });
        } catch (error) {
            throw await handleError(error)
        }
    }

    // Revoke a specific session
    async revokeSession(sessionId: string): Promise<void> {
        try {
            await this.authenticationApi.revokeSession({ id: sessionId });
        } catch (error) {
            throw await handleError(error)
        }
    }

    // Revoke all sessions except the current one
    async revokeAllOtherSessions(): Promise<void> {
        try {
            await this.authenticationApi.revokeAllSessions({ exceptCurrent: true });
        } catch (error) {
            throw await handleError(error)
        }
    }

    // Revoke all sessions including the current one
    async revokeAllSessions({ exceptCurrent }: { exceptCurrent: boolean }): Promise<void> {
        try {
            await this.authenticationApi.revokeAllSessions({ exceptCurrent: false });
        } catch (error) {
            throw await handleError(error)
        }
    }


    // Revoke all sessions including the current one
    async refreshSession(): Promise<Session> {
        try {
            return await this.authenticationApi.refreshSession();
        } catch (error) {
            throw await handleError(error)
        }
    }

    // Get session information with device details
    async getSessionInfo(sessionId?: string): Promise<SessionInfo[]> {
        if (!sessionId) {
            // Get all sessions if no specific session ID provided
            const response = await this.listSessions();
            return response.data || [];
        }

        try {
            // Note: The API doesn't have a single session endpoint, so we filter from all sessions
            const response = await this.listSessions();
            const sessions = response.data || [];
            const targetSession = sessions.find(s => s.id === sessionId);
            return targetSession ? [targetSession] : [];
        } catch (error) {
            throw await handleError(error)
        }
    }

    // Check if current session is valid
    async validateCurrentSession(): Promise<boolean> {
        try {
            const sessions = await this.listSessions();
            return (sessions.data?.length || 0) > 0;
        } catch (error) {
            // If we can't list sessions, assume session is invalid
            return false;
        }
    }

    // Get session activity/history
    async getSessionActivity(options?: {
        limit?: number;
        offset?: number;
        startDate?: Date;
        endDate?: Date;
    }): Promise<SessionInfo[]> {
        try {
            const response = await this.listSessions({
                limit: options?.limit,
                offset: options?.offset,
            });

            let sessions = response.data || [];

            // Filter by date range if provided
            if (options?.startDate || options?.endDate) {
                sessions = sessions.filter(session => {
                    if (!session.createdAt) return true;

                    const sessionDate = new Date(session.createdAt);

                    if (options.startDate && sessionDate < options.startDate) {
                        return false;
                    }

                    if (options.endDate && sessionDate > options.endDate) {
                        return false;
                    }

                    return true;
                });
            }

            return sessions;
        } catch (error) {
            throw await handleError(error)
        }
    }

    // Get device information from sessions
    async getDevices(): Promise<Array<{
        id: string;
        deviceType?: string;
        browser?: string;
        os?: string;
        location?: string;
        ipAddress?: string;
        lastActive?: Date;
        isCurrent?: boolean;
    }>> {
        try {
            const response = await this.listSessions();
            const sessions = response.data || [];

            return sessions.map(session => ({
                id: session.id || '',
                deviceId: session.deviceId,
                browser: session.userAgent,
                os: session.userAgent, // Parse OS from user agent if needed
                location: session.location,
                ipAddress: session.ipAddress,
                // lastActive: session.lastActivity ? new Date(session.lastActivity) : undefined,
                // isCurrent: session.isCurrent,
            }));
        } catch (error) {
            throw await handleError(error)
        }
    }

    // Revoke session by device
    async revokeDeviceSession(deviceId: string): Promise<void> {
        return this.revokeSession(deviceId);
    }

    // Get security insights about sessions
    async getSecurityInsights(): Promise<{
        totalActiveSessions: number;
        suspiciousSessions: number;
        devicesCount: number;
        lastLoginLocation?: string;
        lastLoginTime?: Date;
        recentSuspiciousActivity: boolean;
    }> {
        try {
            const sessions = await this.getSessionActivity();

            const insights = {
                totalActiveSessions: sessions.length,
                suspiciousSessions: sessions.filter(s => s.suspicious).length,
                devicesCount: new Set(sessions.map(s => s.deviceType).filter(Boolean)).size,
                lastLoginLocation: sessions[0]?.location,
                lastLoginTime: sessions[0]?.createdAt ? new Date(sessions[0].createdAt) : undefined,
                recentSuspiciousActivity: sessions.some(s =>
                    s.suspicious &&
                    s.createdAt &&
                    new Date(s.createdAt) > new Date(Date.now() - 24 * 60 * 60 * 1000) // Last 24 hours
                ),
            };

            return insights;
        } catch (error) {
            throw await handleError(error)
        }
    }

    // Session utilities
    getCurrentSessionId(): string | null {
        // This would typically be stored in a cookie or local storage
        if (typeof window === 'undefined') return null;

        const sessionCookie = document.cookie
            .split('; ')
            .find(row => row.startsWith(`${this.config.sessionCookieName}=`));

        return sessionCookie ? sessionCookie.split('=')[1] : null;
    }

    isSessionExpired(session: SessionInfo): boolean {
        if (!session.expiresAt) return false;
        return new Date(session.expiresAt) < new Date();
    }

    getSessionDuration(session: SessionInfo): number | null {
        if (!session.createdAt || !session.lastActivity) return null;

        const start = new Date(session.createdAt);
        const end = new Date(session.lastActivity);

        return end.getTime() - start.getTime();
    }
}