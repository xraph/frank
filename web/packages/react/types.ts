import {OrganizationResponse, User} from '../sdk/index';

export interface AuthConfig {
    baseUrl: string;
    storagePrefix?: string;
    tokenStorageType?: 'cookie' | 'localStorage' | 'sessionStorage' | 'memory';
    organizationId?: string;
}

export interface TokenData {
    token: string;
    refreshToken: string;
    expiresAt: number;
}

export interface AuthState {
    user: User | null | undefined;
    isAuthenticated: boolean;
    isLoading: boolean;
    error: Error | null;
    organization: OrganizationResponse | null;
}