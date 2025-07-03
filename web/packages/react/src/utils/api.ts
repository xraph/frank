import type {APIError, APIResponse, XID} from '../types';

// HTTP methods
export type HttpMethod = 'GET' | 'POST' | 'PUT' | 'PATCH' | 'DELETE';

// Request configuration
export interface RequestConfig {
    method?: HttpMethod;
    headers?: Record<string, string>;
    body?: any;
    params?: Record<string, any>;
    timeout?: number;
    retries?: number;
    cache?: boolean;
    organizationId?: XID;
}

// API client configuration
export interface APIClientConfig {
    baseUrl: string;
    apiKey?: string;
    publishableKey?: string;
    organizationId?: XID;
    timeout?: number;
    retries?: number;
    headers?: Record<string, string>;
}

// Request interceptor
export type RequestInterceptor = (config: RequestConfig) => RequestConfig | Promise<RequestConfig>;

// Response interceptor
export type ResponseInterceptor = (response: Response) => Response | Promise<Response>;

// Error handler
export type ErrorHandler = (error: APIError) => void;

// API client class
export class APIClient {
    private config: APIClientConfig;
    private requestInterceptors: RequestInterceptor[] = [];
    private responseInterceptors: ResponseInterceptor[] = [];
    private errorHandlers: ErrorHandler[] = [];

    constructor(config: APIClientConfig) {
        this.config = config;
    }

    // Configuration methods
    setConfig(config: Partial<APIClientConfig>): void {
        this.config = { ...this.config, ...config };
    }

    setOrganizationContext(organizationId: XID): void {
        this.config.organizationId = organizationId;
    }

    clearOrganizationContext(): void {
        delete this.config.organizationId;
    }

    // Interceptor methods
    addRequestInterceptor(interceptor: RequestInterceptor): void {
        this.requestInterceptors.push(interceptor);
    }

    addResponseInterceptor(interceptor: ResponseInterceptor): void {
        this.responseInterceptors.push(interceptor);
    }

    addErrorHandler(handler: ErrorHandler): void {
        this.errorHandlers.push(handler);
    }

    // Main request method
    async request<T = any>(
        endpoint: string,
        config: RequestConfig = {}
    ): Promise<APIResponse<T>> {
        const url = this.buildUrl(endpoint, config.params);
        let requestConfig = this.buildRequestConfig(config);

        // Apply request interceptors
        for (const interceptor of this.requestInterceptors) {
            requestConfig = await interceptor(requestConfig);
        }

        try {
            const response = await this.executeRequest(url, requestConfig);

            // Apply response interceptors
            let processedResponse = response;
            for (const interceptor of this.responseInterceptors) {
                processedResponse = await interceptor(processedResponse);
            }

            return await this.parseResponse<T>(processedResponse);
        } catch (error) {
            const apiError = this.createAPIError(error);

            // Call error handlers
            for (const handler of this.errorHandlers) {
                handler(apiError);
            }

            throw apiError;
        }
    }

    // Convenience methods
    async get<T = any>(endpoint: string, config?: RequestConfig): Promise<APIResponse<T>> {
        return this.request<T>(endpoint, { ...config, method: 'GET' });
    }

    async post<T = any>(endpoint: string, data?: any, config?: RequestConfig): Promise<APIResponse<T>> {
        return this.request<T>(endpoint, { ...config, method: 'POST', body: data });
    }

    async put<T = any>(endpoint: string, data?: any, config?: RequestConfig): Promise<APIResponse<T>> {
        return this.request<T>(endpoint, { ...config, method: 'PUT', body: data });
    }

    async patch<T = any>(endpoint: string, data?: any, config?: RequestConfig): Promise<APIResponse<T>> {
        return this.request<T>(endpoint, { ...config, method: 'PATCH', body: data });
    }

    async delete<T = any>(endpoint: string, config?: RequestConfig): Promise<APIResponse<T>> {
        return this.request<T>(endpoint, { ...config, method: 'DELETE' });
    }

    // Private helper methods
    private buildUrl(endpoint: string, params?: Record<string, any>): string {
        const url = new URL(endpoint, this.config.baseUrl);

        if (params) {
            for (const [key, value] of Object.entries(params)) {
                if (value !== undefined && value !== null) {
                    url.searchParams.set(key, String(value));
                }
            }
        }

        return url.toString();
    }

    private buildRequestConfig(config: RequestConfig): RequestConfig {
        const headers: Record<string, string> = {
            'Content-Type': 'application/json',
            ...this.config.headers,
            ...config.headers,
        };

        // Add API key
        if (this.config.apiKey) {
            headers['Authorization'] = `Bearer ${this.config.apiKey}`;
        } else if (this.config.publishableKey) {
            headers['X-Publishable-Key'] = this.config.publishableKey;
        }

        // Add organization context
        if (config.organizationId || this.config.organizationId) {
            headers['X-Organization-Id'] = config.organizationId || this.config.organizationId!;
        }

        return {
            method: 'GET',
            timeout: this.config.timeout || 30000,
            retries: this.config.retries || 3,
            ...config,
            headers,
        };
    }

    private async executeRequest(url: string, config: RequestConfig): Promise<Response> {
        const controller = new AbortController();
        const timeoutId = config.timeout ?
            setTimeout(() => controller.abort(), config.timeout) : null;

        try {
            const fetchConfig: RequestInit = {
                method: config.method,
                headers: config.headers,
                signal: controller.signal,
            };

            if (config.body && config.method !== 'GET') {
                fetchConfig.body = typeof config.body === 'string'
                    ? config.body
                    : JSON.stringify(config.body);
            }

            const response = await fetch(url, fetchConfig);

            if (timeoutId) clearTimeout(timeoutId);

            return response;
        } catch (error) {
            if (timeoutId) clearTimeout(timeoutId);
            throw error;
        }
    }

    private async parseResponse<T>(response: Response): Promise<APIResponse<T>> {
        const contentType = response.headers.get('Content-Type') || '';

        let data: any;
        if (contentType.includes('application/json')) {
            data = await response.json();
        } else {
            data = await response.text();
        }

        if (!response.ok) {
            throw new Error(`HTTP ${response.status}: ${response.statusText}`, {
                cause: { status: response.status, data }
            });
        }

        // Handle different response formats
        if (data && typeof data === 'object' && 'success' in data) {
            return data as APIResponse<T>;
        }

        return {
            success: true,
            data: data as T,
        };
    }

    private createAPIError(error: any): APIError {
        if (error.cause && typeof error.cause === 'object') {
            const { status, data } = error.cause;

            if (data && typeof data === 'object' && 'errors' in data) {
                return {
                    code: data.code || `HTTP_${status}`,
                    message: data.message || error.message,
                    details: data.details,
                };
            }
        }

        return {
            code: 'UNKNOWN_ERROR',
            message: error.message || 'An unknown error occurred',
            details: { originalError: error },
        };
    }
}

// Utility functions
export const createAPIClient = (config: APIClientConfig): APIClient => {
    return new APIClient(config);
};

export const isAPIError = (error: any): error is APIError => {
    return error && typeof error === 'object' && 'code' in error && 'message' in error;
};

export const handleAPIError = (error: any): APIError => {
    if (isAPIError(error)) return error;

    return {
        code: 'UNKNOWN_ERROR',
        message: error?.message || 'An unknown error occurred',
        details: { originalError: error },
    };
};

export const retryRequest = async <T>(
    requestFn: () => Promise<T>,
    maxRetries = 3,
    delay = 1000
): Promise<T> => {
    let lastError: Error;

    for (let attempt = 1; attempt <= maxRetries; attempt++) {
        try {
            return await requestFn();
        } catch (error) {
            lastError = error as Error;

            if (attempt === maxRetries) break;

            // Exponential backoff
            const backoffDelay = delay * Math.pow(2, attempt - 1);
            await new Promise(resolve => setTimeout(resolve, backoffDelay));
        }
    }

    throw lastError!;
};

export const withCache = <T>(
    requestFn: () => Promise<T>,
    cacheKey: string,
    ttl = 300000 // 5 minutes
): Promise<T> => {
    const cache = new Map<string, { data: T; expires: number }>();

    return (async (): Promise<T> => {
        const cached = cache.get(cacheKey);

        if (cached && cached.expires > Date.now()) {
            return cached.data;
        }

        const data = await requestFn();
        cache.set(cacheKey, { data, expires: Date.now() + ttl });

        return data;
    })();
};

export const batchRequests = async <T>(
    requests: (() => Promise<T>)[],
    batchSize = 5,
    delay = 100
): Promise<T[]> => {
    const results: T[] = [];

    for (let i = 0; i < requests.length; i += batchSize) {
        const batch = requests.slice(i, i + batchSize);
        const batchResults = await Promise.all(batch.map(request => request()));
        results.push(...batchResults);

        // Add delay between batches
        if (i + batchSize < requests.length && delay > 0) {
            await new Promise(resolve => setTimeout(resolve, delay));
        }
    }

    return results;
};

export const uploadFile = async (
    client: APIClient,
    endpoint: string,
    file: File,
    options: {
        onProgress?: (progress: number) => void;
        abortSignal?: AbortSignal;
        additionalData?: Record<string, any>;
    } = {}
): Promise<APIResponse<any>> => {
    const formData = new FormData();
    formData.append('file', file);

    if (options.additionalData) {
        for (const [key, value] of Object.entries(options.additionalData)) {
            formData.append(key, String(value));
        }
    }

    return new Promise((resolve, reject) => {
        const xhr = new XMLHttpRequest();

        if (options.onProgress) {
            xhr.upload.addEventListener('progress', (event) => {
                if (event.lengthComputable) {
                    const progress = (event.loaded / event.total) * 100;
                    options.onProgress!(progress);
                }
            });
        }

        if (options.abortSignal) {
            options.abortSignal.addEventListener('abort', () => {
                xhr.abort();
                reject(new Error('Upload aborted'));
            });
        }

        xhr.addEventListener('load', async () => {
            try {
                const response = JSON.parse(xhr.responseText);
                if (xhr.status >= 200 && xhr.status < 300) {
                    resolve(response);
                } else {
                    reject(new Error(`Upload failed: ${response.message || xhr.statusText}`));
                }
            } catch (error) {
                reject(new Error('Failed to parse upload response'));
            }
        });

        xhr.addEventListener('error', () => {
            reject(new Error('Upload failed'));
        });

        xhr.open('POST', `${client['config'].baseUrl}${endpoint}`);

        // Add headers (except Content-Type, let browser set it for FormData)
        const headers = client['buildRequestConfig']({}).headers || {};
        for (const [key, value] of Object.entries(headers)) {
            if (key.toLowerCase() !== 'content-type') {
                xhr.setRequestHeader(key, value);
            }
        }

        xhr.send(formData);
    });
};

export const downloadFile = async (
    client: APIClient,
    endpoint: string,
    filename?: string,
    options: {
        onProgress?: (progress: number) => void;
        abortSignal?: AbortSignal;
    } = {}
): Promise<void> => {
    const response = await fetch(`${client['config'].baseUrl}${endpoint}`, {
        headers: client['buildRequestConfig']({}).headers,
        signal: options.abortSignal,
    });

    if (!response.ok) {
        throw new Error(`Download failed: ${response.statusText}`);
    }

    const blob = await response.blob();
    const url = window.URL.createObjectURL(blob);

    const a = document.createElement('a');
    a.style.display = 'none';
    a.href = url;
    a.download = filename || 'download';

    document.body.appendChild(a);
    a.click();

    window.URL.revokeObjectURL(url);
    document.body.removeChild(a);
};

// WebSocket utilities
export class APIWebSocket {
    private ws: WebSocket | null = null;
    private reconnectAttempts = 0;
    private maxReconnectAttempts = 5;
    private reconnectDelay = 1000;
    private messageQueue: any[] = [];
    private eventHandlers: Map<string, Set<(data: any) => void>> = new Map();

    constructor(
        private url: string,
        private config: {
            token?: string;
            organizationId?: XID;
            autoReconnect?: boolean;
        } = {}
    ) {}

    connect(): Promise<void> {
        return new Promise((resolve, reject) => {
            try {
                const wsUrl = new URL(this.url);

                if (this.config.token) {
                    wsUrl.searchParams.set('token', this.config.token);
                }

                if (this.config.organizationId) {
                    wsUrl.searchParams.set('organizationId', this.config.organizationId);
                }

                this.ws = new WebSocket(wsUrl.toString());

                this.ws.onopen = () => {
                    this.reconnectAttempts = 0;

                    // Send queued messages
                    while (this.messageQueue.length > 0) {
                        const message = this.messageQueue.shift();
                        this.ws!.send(JSON.stringify(message));
                    }

                    resolve();
                };

                this.ws.onmessage = (event) => {
                    try {
                        const data = JSON.parse(event.data);
                        this.handleMessage(data);
                    } catch (error) {
                        console.error('Failed to parse WebSocket message:', error);
                    }
                };

                this.ws.onclose = () => {
                    this.ws = null;

                    if (this.config.autoReconnect !== false &&
                        this.reconnectAttempts < this.maxReconnectAttempts) {
                        setTimeout(() => {
                            this.reconnectAttempts++;
                            this.connect();
                        }, this.reconnectDelay * Math.pow(2, this.reconnectAttempts));
                    }
                };

                this.ws.onerror = (error) => {
                    reject(error);
                };

            } catch (error) {
                reject(error);
            }
        });
    }

    disconnect(): void {
        if (this.ws) {
            this.ws.close();
            this.ws = null;
        }
    }

    send(message: any): void {
        if (this.ws && this.ws.readyState === WebSocket.OPEN) {
            this.ws.send(JSON.stringify(message));
        } else {
            this.messageQueue.push(message);
        }
    }

    on(event: string, handler: (data: any) => void): () => void {
        if (!this.eventHandlers.has(event)) {
            this.eventHandlers.set(event, new Set());
        }

        this.eventHandlers.get(event)!.add(handler);

        return () => {
            this.eventHandlers.get(event)?.delete(handler);
        };
    }

    private handleMessage(data: any): void {
        const { type, payload } = data;

        if (this.eventHandlers.has(type)) {
            for (const handler of this.eventHandlers.get(type)!) {
                handler(payload);
            }
        }
    }
}