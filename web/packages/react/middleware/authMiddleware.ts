import {getTokenData, isTokenExpired} from '../utils/token';
import {refreshAuthToken} from '../utils/api';

export interface AuthMiddlewareOptions {
    redirectTo?: string;
    allowedPaths?: string[];
    onAuthFailure?: (path: string) => void;
}

export const createAuthMiddleware = (options: AuthMiddlewareOptions = {}) => {
    return async (
        path: string,
        next: () => Promise<void>
    ): Promise<void> => {
        // Skip auth check for allowed paths
        if (options.allowedPaths?.some((allowedPath) => {
            if (allowedPath.endsWith('*')) {
                return path.startsWith(allowedPath.slice(0, -1));
            }
            return path === allowedPath;
        })) {
            return next();
        }

        // Check if authenticated
        const tokenData = getTokenData();
        if (!tokenData) {
            if (options.onAuthFailure) {
                options.onAuthFailure(path);
            }
            return;
        }

        // Check token expiry and refresh if needed
        if (isTokenExpired()) {
            const refreshedToken = await refreshAuthToken();
            if (!refreshedToken) {
                if (options.onAuthFailure) {
                    options.onAuthFailure(path);
                }
                return;
            }
        }

        // Continue to next middleware/route
        return next();
    };
};