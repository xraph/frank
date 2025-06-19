import type {JSONObject, XID} from '../types';

// Storage types
export type StorageType = 'localStorage' | 'sessionStorage' | 'memoryStorage';

// Storage item with metadata
export interface StorageItem<T = any> {
    value: T;
    timestamp: number;
    expires?: number;
    version?: string;
}

// Storage configuration
export interface StorageConfig {
    type: StorageType;
    prefix: string;
    encryption?: boolean;
    compression?: boolean;
    ttl?: number; // Time to live in milliseconds
}

// Storage event
export interface StorageEvent<T = any> {
    key: string;
    oldValue: T | null;
    newValue: T | null;
    timestamp: number;
}

// Storage adapter interface
export interface StorageAdapter {
    get<T = any>(key: string): T | null;
    set<T = any>(key: string, value: T, options?: { ttl?: number }): void;
    remove(key: string): void;
    clear(): void;
    keys(): string[];
    size(): number;
    exists(key: string): boolean;
}

// Memory storage implementation (fallback)
class MemoryStorage implements Storage {
    private data: Map<string, string> = new Map();

    get length(): number {
        return this.data.size;
    }

    key(index: number): string | null {
        const keys = Array.from(this.data.keys());
        return keys[index] || null;
    }

    getItem(key: string): string | null {
        return this.data.get(key) || null;
    }

    setItem(key: string, value: string): void {
        this.data.set(key, value);
    }

    removeItem(key: string): void {
        this.data.delete(key);
    }

    clear(): void {
        this.data.clear();
    }
}

// Get storage instance
const getStorageInstance = (type: StorageType): Storage => {
    switch (type) {
        case 'localStorage':
            return typeof window !== 'undefined' && window.localStorage
                ? window.localStorage
                : new MemoryStorage();
        case 'sessionStorage':
            return typeof window !== 'undefined' && window.sessionStorage
                ? window.sessionStorage
                : new MemoryStorage();
        case 'memoryStorage':
        default:
            return new MemoryStorage();
    }
};

// Storage manager class
export class StorageManager implements StorageAdapter {
    private storage: Storage;
    private config: StorageConfig;
    private eventListeners: Map<string, Set<(event: StorageEvent) => void>> = new Map();

    constructor(config: Partial<StorageConfig> = {}) {
        this.config = {
            type: 'localStorage',
            prefix: 'frank_auth_',
            encryption: false,
            compression: false,
            ...config,
        };

        this.storage = getStorageInstance(this.config.type);

        // Listen for storage changes (only for localStorage/sessionStorage)
        if (typeof window !== 'undefined' && this.config.type !== 'memoryStorage') {
            window.addEventListener('storage', this.handleStorageChange.bind(this));
        }
    }

    private createKey(key: string): string {
        return `${this.config.prefix}${key}`;
    }

    private handleStorageChange(event: Event): void {
        const storageEvent = event as globalThis.StorageEvent;

        if (!storageEvent.key || !storageEvent.key.startsWith(this.config.prefix)) {
            return;
        }

        const key = storageEvent.key.substring(this.config.prefix.length);
        const oldValue = this.deserialize(storageEvent.oldValue);
        const newValue = this.deserialize(storageEvent.newValue);

        const customEvent: StorageEvent = {
            key,
            oldValue,
            newValue,
            timestamp: Date.now(),
        };

        this.emitEvent(key, customEvent);
    }

    private serialize<T>(value: T, options: { ttl?: number } = {}): string {
        const item: StorageItem<T> = {
            value,
            timestamp: Date.now(),
            version: '1.0',
        };

        if (options.ttl || this.config.ttl) {
            item.expires = Date.now() + (options.ttl || this.config.ttl!);
        }

        let serialized = JSON.stringify(item);

        // Apply compression if enabled
        if (this.config.compression) {
            serialized = this.compress(serialized);
        }

        // Apply encryption if enabled
        if (this.config.encryption) {
            serialized = this.encrypt(serialized);
        }

        return serialized;
    }

    private deserialize<T>(data: string | null): T | null {
        if (!data) return null;

        try {
            let processed = data;

            // Decrypt if needed
            if (this.config.encryption) {
                processed = this.decrypt(processed);
            }

            // Decompress if needed
            if (this.config.compression) {
                processed = this.decompress(processed);
            }

            const item: StorageItem<T> = JSON.parse(processed);

            // Check expiration
            if (item.expires && Date.now() > item.expires) {
                return null;
            }

            return item.value;
        } catch {
            return null;
        }
    }

    private compress(data: string): string {
        // Simple compression using LZ-string would go here
        // For now, just return the data as-is
        return data;
    }

    private decompress(data: string): string {
        // Simple decompression using LZ-string would go here
        // For now, just return the data as-is
        return data;
    }

    private encrypt(data: string): string {
        // Simple encryption would go here
        // For now, just return the data as-is
        return data;
    }

    private decrypt(data: string): string {
        // Simple decryption would go here
        // For now, just return the data as-is
        return data;
    }

    private emitEvent(key: string, event: StorageEvent): void {
        const listeners = this.eventListeners.get(key);
        if (listeners) {
            for (const listener of listeners) {
                listener(event);
            }
        }

        // Also emit to wildcard listeners
        const wildcardListeners = this.eventListeners.get('*');
        if (wildcardListeners) {
            for (const listener of wildcardListeners) {
                listener(event);
            }
        }
    }

    // Public API
    get<T = any>(key: string): T | null {
        try {
            const fullKey = this.createKey(key);
            const data = this.storage.getItem(fullKey);
            return this.deserialize<T>(data);
        } catch {
            return null;
        }
    }

    set<T = any>(key: string, value: T, options: { ttl?: number } = {}): void {
        try {
            const fullKey = this.createKey(key);
            const oldValue = this.get<T>(key);
            const serialized = this.serialize(value, options);

            this.storage.setItem(fullKey, serialized);

            // Emit change event
            const event: StorageEvent<T> = {
                key,
                oldValue,
                newValue: value,
                timestamp: Date.now(),
            };

            this.emitEvent(key, event);
        } catch (error) {
            console.error('Failed to set storage item:', error);
        }
    }

    remove(key: string): void {
        try {
            const fullKey = this.createKey(key);
            const oldValue = this.get(key);

            this.storage.removeItem(fullKey);

            // Emit change event
            const event: StorageEvent = {
                key,
                oldValue,
                newValue: null,
                timestamp: Date.now(),
            };

            this.emitEvent(key, event);
        } catch (error) {
            console.error('Failed to remove storage item:', error);
        }
    }

    clear(): void {
        try {
            const keys = this.keys();

            // Remove all items with our prefix
            for (const key of keys) {
                const fullKey = this.createKey(key);
                this.storage.removeItem(fullKey);
            }

            // Emit clear event for each key
            for (const key of keys) {
                const event: StorageEvent = {
                    key,
                    oldValue: null,
                    newValue: null,
                    timestamp: Date.now(),
                };

                this.emitEvent(key, event);
            }
        } catch (error) {
            console.error('Failed to clear storage:', error);
        }
    }

    keys(): string[] {
        try {
            const keys: string[] = [];
            const prefixLength = this.config.prefix.length;

            for (let i = 0; i < this.storage.length; i++) {
                const fullKey = this.storage.key(i);
                if (fullKey && fullKey.startsWith(this.config.prefix)) {
                    keys.push(fullKey.substring(prefixLength));
                }
            }

            return keys;
        } catch {
            return [];
        }
    }

    size(): number {
        return this.keys().length;
    }

    exists(key: string): boolean {
        const fullKey = this.createKey(key);
        return this.storage.getItem(fullKey) !== null;
    }

    // Event handling
    on(key: string, listener: (event: StorageEvent) => void): () => void {
        if (!this.eventListeners.has(key)) {
            this.eventListeners.set(key, new Set());
        }

        this.eventListeners.get(key)!.add(listener);

        // Return unsubscribe function
        return () => {
            this.eventListeners.get(key)?.delete(listener);
        };
    }

    off(key: string, listener: (event: StorageEvent) => void): void {
        this.eventListeners.get(key)?.delete(listener);
    }

    // Utility methods
    getObject<T extends JSONObject>(key: string): T | null {
        return this.get<T>(key);
    }

    setObject<T extends JSONObject>(key: string, value: T, options?: { ttl?: number }): void {
        this.set(key, value, options);
    }

    getString(key: string): string | null {
        return this.get<string>(key);
    }

    setString(key: string, value: string, options?: { ttl?: number }): void {
        this.set(key, value, options);
    }

    getNumber(key: string): number | null {
        return this.get<number>(key);
    }

    setNumber(key: string, value: number, options?: { ttl?: number }): void {
        this.set(key, value, options);
    }

    getBoolean(key: string): boolean | null {
        return this.get<boolean>(key);
    }

    setBoolean(key: string, value: boolean, options?: { ttl?: number }): void {
        this.set(key, value, options);
    }

    // Batch operations
    setMultiple(items: Record<string, any>, options?: { ttl?: number }): void {
        for (const [key, value] of Object.entries(items)) {
            this.set(key, value, options);
        }
    }

    getMultiple<T = any>(keys: string[]): Record<string, T | null> {
        const result: Record<string, T | null> = {};

        for (const key of keys) {
            result[key] = this.get<T>(key);
        }

        return result;
    }

    removeMultiple(keys: string[]): void {
        for (const key of keys) {
            this.remove(key);
        }
    }

    // Cleanup expired items
    cleanup(): number {
        const keys = this.keys();
        let cleanedCount = 0;

        for (const key of keys) {
            const value = this.get(key);
            if (value === null) {
                // Item was expired and returned null
                this.remove(key);
                cleanedCount++;
            }
        }

        return cleanedCount;
    }

    // Export/import functionality
    export(): Record<string, any> {
        const data: Record<string, any> = {};
        const keys = this.keys();

        for (const key of keys) {
            const value = this.get(key);
            if (value !== null) {
                data[key] = value;
            }
        }

        return data;
    }

    import(data: Record<string, any>, options?: { ttl?: number; merge?: boolean }): void {
        if (!options?.merge) {
            this.clear();
        }

        for (const [key, value] of Object.entries(data)) {
            this.set(key, value, options);
        }
    }
}

// Default storage manager instances
export const defaultStorage = new StorageManager({
    type: 'localStorage',
    prefix: 'frank_auth_',
});

export const sessionStorage = new StorageManager({
    type: 'sessionStorage',
    prefix: 'frank_auth_session_',
});

export const memoryStorage = new StorageManager({
    type: 'memoryStorage',
    prefix: 'frank_auth_memory_',
});

// Utility functions
export const createStorageKey = (key: string, organizationId?: XID): string => {
    return organizationId ? `${organizationId}_${key}` : key;
};

export const parseStorageKey = (storageKey: string): { key: string; organizationId?: XID } => {
    const parts = storageKey.split('_');

    if (parts.length >= 2 && parts[0].match(/^[a-zA-Z0-9]+$/)) {
        return {
            organizationId: parts[0] as XID,
            key: parts.slice(1).join('_'),
        };
    }

    return { key: storageKey };
};

export const isStorageAvailable = (type: StorageType): boolean => {
    if (typeof window === 'undefined') return false;
    if (type === 'memoryStorage') return true;

    try {
        const storage = type === 'localStorage' ? window.localStorage : window.sessionStorage;
        const testKey = '__frank_auth_test__';
        storage.setItem(testKey, 'test');
        storage.removeItem(testKey);
        return true;
    } catch {
        return false;
    }
};

export const getStorageSize = (type: StorageType): number => {
    if (typeof window === 'undefined') return 0;
    if (type === 'memoryStorage') return 0;

    try {
        const storage = type === 'localStorage' ? window.localStorage : window.sessionStorage;
        let total = 0;

        for (let i = 0; i < storage.length; i++) {
            const key = storage.key(i);
            if (key) {
                const value = storage.getItem(key);
                total += key.length + (value ? value.length : 0);
            }
        }

        return total;
    } catch {
        return 0;
    }
};

export const clearExpiredItems = (storage: StorageManager): number => {
    return storage.cleanup();
};

// Storage hooks for React (would be used in hooks directory)
export const createStorageHook = (storage: StorageManager) => {
    return <T>(key: string, defaultValue?: T): [T | null, (value: T | null) => void] => {
        // This would be implemented as a React hook in the hooks directory
        // For now, we'll just provide the structure
        const getValue = (): T | null => {
            return storage.get<T>(key) ?? defaultValue ?? null;
        };

        const setValue = (value: T | null): void => {
            if (value === null) {
                storage.remove(key);
            } else {
                storage.set(key, value);
            }
        };

        return [getValue(), setValue];
    };
};

// Auth-specific storage utilities
export const AuthStorage = {
    // Token management
    getAccessToken(): string | null {
        return defaultStorage.getString('access_token');
    },

    setAccessToken(token: string, ttl?: number): void {
        defaultStorage.setString('access_token', token, { ttl });
    },

    removeAccessToken(): void {
        defaultStorage.remove('access_token');
    },

    getRefreshToken(): string | null {
        return defaultStorage.getString('refresh_token');
    },

    setRefreshToken(token: string): void {
        defaultStorage.setString('refresh_token', token);
    },

    removeRefreshToken(): void {
        defaultStorage.remove('refresh_token');
    },

    // Session management
    getSessionId(): XID | null {
        return defaultStorage.getString('session_id') as XID;
    },

    setSessionId(sessionId: XID): void {
        defaultStorage.setString('session_id', sessionId);
    },

    removeSessionId(): void {
        defaultStorage.remove('session_id');
    },

    // User data
    getUserData(): any | null {
        return defaultStorage.getObject('user_data');
    },

    setUserData(userData: any): void {
        defaultStorage.setObject('user_data', userData);
    },

    removeUserData(): void {
        defaultStorage.remove('user_data');
    },

    // Organization context
    getOrganizationId(): XID | null {
        return defaultStorage.getString('organization_id') as XID;
    },

    setOrganizationId(organizationId: XID): void {
        defaultStorage.setString('organization_id', organizationId);
    },

    removeOrganizationId(): void {
        defaultStorage.remove('organization_id');
    },

    // Clear all auth data
    clearAll(): void {
        const authKeys = [
            'access_token',
            'refresh_token',
            'session_id',
            'user_data',
            'organization_id',
        ];

        defaultStorage.removeMultiple(authKeys);
    },

    // Device management
    getDeviceFingerprint(): string | null {
        return defaultStorage.getString('device_fingerprint');
    },

    setDeviceFingerprint(fingerprint: string): void {
        defaultStorage.setString('device_fingerprint', fingerprint);
    },

    // Remember me functionality
    getRememberMe(): boolean {
        return defaultStorage.getBoolean('remember_me') ?? false;
    },

    setRememberMe(remember: boolean): void {
        defaultStorage.setBoolean('remember_me', remember);
    },
};