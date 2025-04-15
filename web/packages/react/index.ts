import "./styles/globals.css";

export * from "./components/ui-kit";
export * from "./components/context";
export * from "./components/provider";
export * from "./components/hooks";

// Main exports
export { AuthProvider } from './auth/AuthProvider';
export { OrganizationProvider } from './organization/OrganizationProvider';
export { setConfig, getConfig } from './config';

// Auth hooks
export { useAuth } from './auth/useAuth';
export { useLogin } from './auth/useLogin';
export { useLogout } from './auth/useLogout';
export { useRegister } from './auth/useRegister';
export { useUser } from './auth/useUser';

// Organization hooks
export { useOrganization } from './organization/useOrganization';

// Auth middleware (not Next.js)
export { createAuthMiddleware } from './middleware/authMiddleware';

// Utility functions
export {
    getToken,
    getRefreshToken,
    getTokenData,
    setTokenData,
    clearTokenData,
    isTokenExpired
} from './utils/token';

export {
    getItem,
    setItem,
    removeItem,
    clearStorage
} from './utils/storage';

export {
    createApiClient,
    createAuthenticatedClient,
    getAuthClient,
    refreshAuthToken
} from './utils/api';

// Types
export type { AuthConfig, TokenData, AuthState } from './types';
export type { AuthContextType, AuthProviderProps } from './auth/types';
export type { OrganizationContextType, OrganizationProviderProps } from './organization/types';
export type { AuthMiddlewareOptions } from './middleware/authMiddleware';