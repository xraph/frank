import {
    AuthenticationApi,
    type ListSessionsRequest,
    type PaginatedOutputSessionInfo,
    type Session,
    type SessionInfo,
} from '@frank-auth/client';

import {BaseSDK, type FrankAuthConfig} from './index';

export class SessionSDK extends BaseSDK {
    private authenticationApi: AuthenticationApi;

    constructor(config: FrankAuthConfig, accessToken?: string) {
        super(config, accessToken);
        this.authenticationApi = new AuthenticationApi(super.config);
    }

    // List all active sessions for the current user
    async listSessions(requestParameters: ListSessionsRequest): Promise<PaginatedOutputSessionInfo> {
        return this.executeApiCall(async () => {
            return await this.authenticationApi.listSessions(
                requestParameters,
                this.mergeHeaders()
            );
        });
    }

    // Revoke a specific session
    async revokeSession(sessionId: string): Promise<void> {
        return this.executeApiCall(async () => {
            await this.authenticationApi.revokeSession(
                {id: sessionId},
                this.mergeHeaders()
            );
        });
    }

    // Revoke all sessions except the current one
    async revokeAllOtherSessions(): Promise<void> {
        return this.executeApiCall(async () => {
            await this.authenticationApi.revokeAllSessions(
                {exceptCurrent: true},
                this.mergeHeaders()
            );
        });
    }

    // Revoke all sessions including the current one
    async revokeAllSessions({exceptCurrent}: { exceptCurrent: boolean }): Promise<void> {
        return this.executeApiCall(async () => {
            await this.authenticationApi.revokeAllSessions(
                {exceptCurrent: false},
                this.mergeHeaders()
            );
        });
    }

    // Revoke all sessions including the current one
    async refreshSession(): Promise<Session> {
        return this.executeApiCall(async () => {
            return await this.authenticationApi.refreshSession(this.mergeHeaders());
        });
    }

    // Get session information with device details
    async getSessionInfo(sessionId?: string): Promise<SessionInfo[]> {
        return this.executeApiCall(async () => {
            if (!sessionId) {
                // Get all sessions if no specific session ID provided
                const response = await this.listSessions({
                    fields: null,
                });
                return response.data || [];
            }

            // Note: The API doesn't have a single session endpoint, so we filter from all sessions
            const response = await this.listSessions({fields: null});
            const sessions = response.data || [];
            const targetSession = sessions.find(s => s.id === sessionId);
            return targetSession ? [targetSession] : [];
        });
    }

    // Check if current session is valid
    async validateCurrentSession(): Promise<boolean> {
        return this.executeApiCall(async () => {
            const sessions = await this.listSessions({fields: null});
            return (sessions.data?.length || 0) > 0;
        }, false).catch(() => false); // If we can't list sessions, assume session is invalid
    }

    // Get session activity/history
    async getSessionActivity(options?: {
        limit?: number;
        offset?: number;
        startDate?: Date;
        endDate?: Date;
    }): Promise<SessionInfo[]> {
        return this.executeApiCall(async () => {
            const response = await this.listSessions({
                fields: null,
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
        });
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
        return this.executeApiCall(async () => {
            const response = await this.listSessions({
                fields: null,
            });
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
        });
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
        return this.executeApiCall(async () => {
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
        });
    }

    // Session utilities
    getCurrentSessionId(): string | null {
        // This would typically be stored in a cookie or local storage
        if (typeof window === 'undefined') return null;

        const sessionCookie = document.cookie
            .split('; ')
            .find(row => row.startsWith(`${this.options.sessionCookieName}=`));

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

    // Additional utility methods for session management with prehooks

    /**
     * Get current session with latest token information
     */
    async getCurrentSession(): Promise<SessionInfo | null> {
        return this.executeApiCall(async () => {
            const sessionId = this.getCurrentSessionId();
            if (!sessionId) return null;

            const sessions = await this.getSessionInfo(sessionId);
            return sessions[0] || null;
        }, false).catch(() => null);
    }

    /**
     * Validate and refresh current session if needed
     */
    async validateAndRefreshSession(): Promise<boolean> {
        return this.executeApiCall(async () => {
            const isValid = await this.validateCurrentSession();

            if (!isValid) {
                // Try to refresh the session
                try {
                    await this.refreshSession();
                    return true;
                } catch {
                    return false;
                }
            }

            return true;
        }, false).catch(() => false);
    }

    /**
     * Get session summary with enhanced information
     */
    async getSessionSummary(): Promise<{
        currentSessionId: string | null;
        totalSessions: number;
        currentSessionValid: boolean;
        securityInsights: {
            totalActiveSessions: number;
            suspiciousSessions: number;
            devicesCount: number;
            lastLoginLocation?: string;
            lastLoginTime?: Date;
            recentSuspiciousActivity: boolean;
        };
    }> {
        return this.executeApiCall(async () => {
            const [currentSessionId, sessions, securityInsights] = await Promise.all([
                Promise.resolve(this.getCurrentSessionId()),
                this.listSessions({ fields: null }),
                this.getSecurityInsights(),
            ]);

            return {
                currentSessionId,
                totalSessions: sessions.data?.length || 0,
                currentSessionValid: (sessions.data?.length || 0) > 0,
                securityInsights,
            };
        });
    }

    /**
     * Clean up expired sessions
     */
    async cleanupExpiredSessions(): Promise<number> {
        return this.executeApiCall(async () => {
            const sessions = await this.getSessionActivity();
            const expiredSessions = sessions.filter(session => this.isSessionExpired(session));

            let cleanedCount = 0;
            for (const session of expiredSessions) {
                try {
                    await this.revokeSession(session.id || '');
                    cleanedCount++;
                } catch {
                    // Continue with other sessions if one fails
                }
            }

            return cleanedCount;
        }, false).catch(() => 0);
    }

    /**
     * Get sessions by device type
     */
    async getSessionsByDeviceType(deviceType?: string): Promise<SessionInfo[]> {
        return this.executeApiCall(async () => {
            const sessions = await this.getSessionActivity();

            if (!deviceType) {
                return sessions;
            }

            return sessions.filter(session =>
                session.deviceType?.toLowerCase().includes(deviceType.toLowerCase())
            );
        }, false).catch(() => []);
    }

    /**
     * Check for suspicious activity in sessions
     */
    async checkForSuspiciousActivity(): Promise<{
        hasSuspiciousActivity: boolean;
        suspiciousSessions: SessionInfo[];
        recommendations: string[];
    }> {
        return this.executeApiCall(async () => {
            const sessions = await this.getSessionActivity();
            const suspiciousSessions = sessions.filter(s => s.suspicious);

            const recommendations: string[] = [];

            if (suspiciousSessions.length > 0) {
                recommendations.push('Review and revoke suspicious sessions');
            }

            const uniqueLocations = new Set(sessions.map(s => s.location).filter(Boolean));
            if (uniqueLocations.size > 3) {
                recommendations.push('Multiple login locations detected - verify all sessions');
            }

            const recentSessions = sessions.filter(s =>
                s.createdAt &&
                new Date(s.createdAt) > new Date(Date.now() - 24 * 60 * 60 * 1000)
            );

            if (recentSessions.length > 5) {
                recommendations.push('Multiple recent sessions - ensure account security');
            }

            return {
                hasSuspiciousActivity: suspiciousSessions.length > 0,
                suspiciousSessions,
                recommendations,
            };
        }, false).catch(() => ({
            hasSuspiciousActivity: false,
            suspiciousSessions: [],
            recommendations: [],
        }));
    }
}