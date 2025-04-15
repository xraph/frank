import {AuthConfig} from '../types';

let config: AuthConfig = {
    baseUrl: '',
    storagePrefix: 'frank_auth_',
    tokenStorageType: 'localStorage'
};

export const setConfig = (newConfig: Partial<AuthConfig>): void => {
    config = { ...config, ...newConfig };
};

export const getConfig = (): AuthConfig => {
    return { ...config };
};