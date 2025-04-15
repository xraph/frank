import React, {createContext} from 'react';
import {AuthContextType} from './types';
import {AuthState} from '../types';

// Default auth state
const defaultAuthState: AuthState = {
    user: null,
    isAuthenticated: false,
    isLoading: false,
    error: null,
    organization: null
};

// Create auth context with default values
export const AuthContext = createContext<AuthContextType>({
    ...defaultAuthState,
    login: async () => null,
    logout: async () => {},
    register: async () => null,
    refreshToken: async () => null,
    updateUser: async () => null
});

export const useAuthContext = () => {
    const context = React.useContext(AuthContext);
    if (!context) {
        throw new Error('useAuthContext must be used within an AuthProvider');
    }
    return context;
};