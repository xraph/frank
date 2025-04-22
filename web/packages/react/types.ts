import {OrganizationResponse, User} from "@frank-auth/sdk";

export interface AuthConfig {
	baseUrl: string;
	storagePrefix?: string;
	tokenStorageType?: "cookie" | "localStorage" | "sessionStorage" | "memory";
	organizationId?: string;
	cookieName?: string;
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
