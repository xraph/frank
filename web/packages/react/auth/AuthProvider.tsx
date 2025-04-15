import React, {useEffect, useState} from 'react';
import {
    authLogin,
    authLogout,
    authMe,
    authRegister,
    LoginRequest,
    RegisterRequest,
    User,
    usersUpdateMe
} from '../../sdk/index';
import {AuthContext} from './AuthContext';
import {AuthProviderProps} from './types';
import {TokenData} from '../types';
import {clearTokenData, getTokenData, isTokenExpired, setTokenData} from '../utils/token';
import {setConfig} from '../config';
import {getAuthClient, refreshAuthToken} from '../utils/api';

export const AuthProvider: React.FC<AuthProviderProps> = ({
                                                              children,
                                                              organizationId
                                                          }) => {
    const [user, setUser] = useState<User | null | undefined>(null);
    const [isAuthenticated, setIsAuthenticated] = useState<boolean>(false);
    const [isLoading, setIsLoading] = useState<boolean>(true);
    const [error, setError] = useState<Error | null>(null);
    const [organization, setOrganization] = useState<any>(null);

    // Update config if organizationId is provided
    useEffect(() => {
        if (organizationId) {
            setConfig({ organizationId });
        }
    }, [organizationId]);

    // Initialize auth state
    useEffect(() => {
        const initAuth = async () => {
            setIsLoading(true);
            try {
                // Check if we have a token
                const tokenData = getTokenData();
                if (!tokenData) {
                    setIsLoading(false);
                    return;
                }

                // Check if token is expired
                if (isTokenExpired()) {
                    const newTokenData = await refreshAuthToken();
                    if (!newTokenData) {
                        clearTokenData();
                        setIsLoading(false);
                        return;
                    }
                }

                // Fetch current user
                const client = await getAuthClient();
                const { data } = await authMe({ client });

                setUser(data);
                setIsAuthenticated(true);
            } catch (err) {
                clearTokenData();
                setError(err instanceof Error ? err : new Error('Authentication failed'));
            } finally {
                setIsLoading(false);
            }
        };

        initAuth();
    }, []);

    const login = async (credentials: LoginRequest): Promise<User | null> => {
        setIsLoading(true);
        setError(null);

        try {
            const client = await getAuthClient();
            const { data } = await authLogin({
                body: credentials,
                throwOnError: true,
                client: client,
            });

            const tokenData: TokenData = {
                token: data.token,
                refreshToken: data.refresh_token,
                expiresAt: Number(data.expires_at),
            };

            setTokenData(tokenData);
            setUser(data.user);
            setIsAuthenticated(true);

            return data.user;
        } catch (err) {
            setError(err instanceof Error ? err : new Error('Login failed'));
            return null;
        } finally {
            setIsLoading(false);
        }
    };

    const logout = async (): Promise<void> => {
        setIsLoading(true);

        try {
            const client = await getAuthClient();
            await authLogout({ client });
        } catch (err) {
            // Continue with logout regardless of API error
        } finally {
            clearTokenData();
            setUser(null);
            setIsAuthenticated(false);
            setIsLoading(false);
        }
    };

    const register = async (data: RegisterRequest): Promise<User | null> => {
        setIsLoading(true);
        setError(null);

        try {
            const client = await getAuthClient();
            const response = await authRegister({
                client,
                body: data,
                throwOnError: true,
            });

            const tokenData: TokenData = {
                token: response.data.token,
                refreshToken: response.data.refresh_token,
                expiresAt: Number(response.data.expires_at),
            };

            setTokenData(tokenData);
            setUser(response.data.user);
            setIsAuthenticated(true);

            return response.data.user;
        } catch (err) {
            setError(err instanceof Error ? err : new Error('Registration failed'));
            return null;
        } finally {
            setIsLoading(false);
        }
    };

    const updateUser = async (userData: Partial<User>): Promise<User | null> => {
        setIsLoading(true);
        setError(null);

        try {
            const client = await getAuthClient();
            const { data } = await usersUpdateMe({
                client,
                body: userData,
                throwOnError: true,
            });

            setUser(data);
            return data;
        } catch (err) {
            setError(err instanceof Error ? err : new Error('Update failed'));
            return null;
        } finally {
            setIsLoading(false);
        }
    };

    return (
        <AuthContext.Provider
            value={{
                user,
                isAuthenticated,
                isLoading,
                error,
                organization,
                login,
                logout,
                register,
                refreshToken: refreshAuthToken,
                updateUser
            }}
        >
            {children}
        </AuthContext.Provider>
    );
};