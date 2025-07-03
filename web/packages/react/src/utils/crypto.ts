// Cryptographic utilities for Frank Auth React library
// These are client-side utilities for non-sensitive operations

// Base64 utilities
export const base64Encode = (data: string): string => {
    if (typeof btoa !== 'undefined') {
        return btoa(data);
    }

    // Fallback for environments without btoa
    return Buffer.from(data, 'utf-8').toString('base64');
};

export const base64Decode = (encoded: string): string => {
    if (typeof atob !== 'undefined') {
        return atob(encoded);
    }

    // Fallback for environments without atob
    return Buffer.from(encoded, 'base64').toString('utf-8');
};

export const base64UrlEncode = (data: string): string => {
    return base64Encode(data)
        .replace(/\+/g, '-')
        .replace(/\//g, '_')
        .replace(/=/g, '');
};

export const base64UrlDecode = (encoded: string): string => {
    // Add padding if needed
    let padded = encoded;
    while (padded.length % 4) {
        padded += '=';
    }

    return base64Decode(
        padded
            .replace(/-/g, '+')
            .replace(/_/g, '/')
    );
};

// Random generation utilities
export const generateRandomBytes = (length: number): Uint8Array => {
    if (typeof crypto !== 'undefined' && crypto.getRandomValues) {
        return crypto.getRandomValues(new Uint8Array(length));
    }

    // Fallback for environments without crypto.getRandomValues
    const array = new Uint8Array(length);
    for (let i = 0; i < length; i++) {
        array[i] = Math.floor(Math.random() * 256);
    }
    return array;
};

export const generateRandomString = (length: number, charset?: string): string => {
    const defaultCharset = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
    const chars = charset || defaultCharset;
    const randomBytes = generateRandomBytes(length);

    let result = '';
    for (let i = 0; i < length; i++) {
        result += chars[randomBytes[i] % chars.length];
    }

    return result;
};

export const generateSecureId = (): string => {
    const timestamp = Date.now().toString(36);
    const randomPart = generateRandomString(8);
    return `${timestamp}${randomPart}`;
};

export const generateNonce = (): string => {
    return generateRandomString(32);
};

export const generateState = (): string => {
    return generateRandomString(32);
};

export const generateCodeVerifier = (): string => {
    return generateRandomString(128, 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~');
};

// PKCE (Proof Key for Code Exchange) utilities
export const generateCodeChallenge = async (verifier: string): Promise<string> => {
    if (typeof crypto !== 'undefined' && crypto.subtle) {
        const encoder = new TextEncoder();
        const data = encoder.encode(verifier);
        const digest = await crypto.subtle.digest('SHA-256', data);
        const array = new Uint8Array(digest);

        return base64UrlEncode(String.fromCharCode(...array));
    }

    // Fallback: return verifier as-is (not recommended for production)
    console.warn('WebCrypto API not available, using plain code verifier');
    return verifier;
};

export const generatePKCEPair = async (): Promise<{
    codeVerifier: string;
    codeChallenge: string;
    codeChallengeMethod: 'S256' | 'plain';
}> => {
    const codeVerifier = generateCodeVerifier();

    if (typeof crypto !== 'undefined' && crypto.subtle) {
        const codeChallenge = await generateCodeChallenge(codeVerifier);
        return {
            codeVerifier,
            codeChallenge,
            codeChallengeMethod: 'S256',
        };
    }

    return {
        codeVerifier,
        codeChallenge: codeVerifier,
        codeChallengeMethod: 'plain',
    };
};

// Hash utilities
export const sha256 = async (data: string): Promise<string> => {
    if (typeof crypto !== 'undefined' && crypto.subtle) {
        const encoder = new TextEncoder();
        const dataBuffer = encoder.encode(data);
        const hashBuffer = await crypto.subtle.digest('SHA-256', dataBuffer);
        const hashArray = new Uint8Array(hashBuffer);

        return Array.from(hashArray)
            .map(b => b.toString(16).padStart(2, '0'))
            .join('');
    }

    // Fallback: simple hash (not cryptographically secure)
    let hash = 0;
    for (let i = 0; i < data.length; i++) {
        const char = data.charCodeAt(i);
        hash = ((hash << 5) - hash) + char;
        hash = hash & hash; // Convert to 32-bit integer
    }

    return Math.abs(hash).toString(16);
};

export const md5 = (data: string): string => {
    // Simple MD5 implementation (not cryptographically secure, for compatibility only)
    // In production, you should use a proper crypto library
    let hash = 0;
    for (let i = 0; i < data.length; i++) {
        const char = data.charCodeAt(i);
        hash = ((hash << 5) - hash) + char;
        hash = hash & hash;
    }
    return Math.abs(hash).toString(16);
};

// Simple encryption/decryption (for client-side storage only)
// NOTE: This is NOT secure encryption and should only be used for obfuscation
export const simpleEncrypt = (data: string, key: string): string => {
    let encrypted = '';
    for (let i = 0; i < data.length; i++) {
        const dataChar = data.charCodeAt(i);
        const keyChar = key.charCodeAt(i % key.length);
        encrypted += String.fromCharCode(dataChar ^ keyChar);
    }
    return base64Encode(encrypted);
};

export const simpleDecrypt = (encrypted: string, key: string): string => {
    try {
        const data = base64Decode(encrypted);
        let decrypted = '';
        for (let i = 0; i < data.length; i++) {
            const dataChar = data.charCodeAt(i);
            const keyChar = key.charCodeAt(i % key.length);
            decrypted += String.fromCharCode(dataChar ^ keyChar);
        }
        return decrypted;
    } catch {
        return '';
    }
};

// JWT utilities (for parsing only, NOT for verification)
export interface JWTHeader {
    alg: string;
    typ: string;
    kid?: string;
}

export interface JWTPayload {
    [key: string]: any;
    iss?: string;
    sub?: string;
    aud?: string | string[];
    exp?: number;
    nbf?: number;
    iat?: number;
    jti?: string;
}

export const parseJWT = (token: string): {
    header: JWTHeader;
    payload: JWTPayload;
    signature: string;
} | null => {
    try {
        const parts = token.split('.');
        if (parts.length !== 3) return null;

        const header = JSON.parse(base64UrlDecode(parts[0]));
        const payload = JSON.parse(base64UrlDecode(parts[1]));
        const signature = parts[2];

        return { header, payload, signature };
    } catch {
        return null;
    }
};

export const isJWTExpired = (token: string): boolean => {
    const parsed = parseJWT(token);
    if (!parsed || !parsed.payload.exp) return true;

    const now = Math.floor(Date.now() / 1000);
    return parsed.payload.exp < now;
};

export const getJWTExpiration = (token: string): Date | null => {
    const parsed = parseJWT(token);
    if (!parsed || !parsed.payload.exp) return null;

    return new Date(parsed.payload.exp * 1000);
};

// WebAuthn/Passkey utilities
export const arrayBufferToBase64 = (buffer: ArrayBuffer): string => {
    const bytes = new Uint8Array(buffer);
    let binary = '';
    for (let i = 0; i < bytes.byteLength; i++) {
        binary += String.fromCharCode(bytes[i]);
    }
    return base64Encode(binary);
};

export const base64ToArrayBuffer = (base64: string): ArrayBuffer => {
    const binary = base64Decode(base64);
    const buffer = new ArrayBuffer(binary.length);
    const view = new Uint8Array(buffer);
    for (let i = 0; i < binary.length; i++) {
        view[i] = binary.charCodeAt(i);
    }
    return buffer;
};

export const uint8ArrayToBase64 = (array: Uint8Array): string => {
    return arrayBufferToBase64(array.buffer);
};

export const base64ToUint8Array = (base64: string): Uint8Array => {
    return new Uint8Array(base64ToArrayBuffer(base64));
};

// Convert WebAuthn credential for transport
export const credentialToJSON = (credential: PublicKeyCredential): any => {
    return {
        id: credential.id,
        rawId: arrayBufferToBase64(credential.rawId),
        type: credential.type,
        response: {
            clientDataJSON: arrayBufferToBase64(credential.response.clientDataJSON),
            attestationObject: credential.response instanceof AuthenticatorAttestationResponse
                ? arrayBufferToBase64(credential.response.attestationObject)
                : undefined,
            authenticatorData: credential.response instanceof AuthenticatorAssertionResponse
                ? arrayBufferToBase64(credential.response.authenticatorData)
                : undefined,
            signature: credential.response instanceof AuthenticatorAssertionResponse
                ? arrayBufferToBase64(credential.response.signature)
                : undefined,
            userHandle: credential.response instanceof AuthenticatorAssertionResponse && credential.response.userHandle
                ? arrayBufferToBase64(credential.response.userHandle)
                : undefined,
        },
    };
};

// Convert JSON back to WebAuthn credential format for processing
export const jsonToCredentialCreationOptions = (options: any): PublicKeyCredentialCreationOptions => {
    return {
        ...options,
        challenge: base64ToArrayBuffer(options.challenge),
        user: {
            ...options.user,
            id: base64ToArrayBuffer(options.user.id),
        },
        excludeCredentials: options.excludeCredentials?.map((cred: any) => ({
            ...cred,
            id: base64ToArrayBuffer(cred.id),
        })),
    };
};

export const jsonToCredentialRequestOptions = (options: any): PublicKeyCredentialRequestOptions => {
    return {
        ...options,
        challenge: base64ToArrayBuffer(options.challenge),
        allowCredentials: options.allowCredentials?.map((cred: any) => ({
            ...cred,
            id: base64ToArrayBuffer(cred.id),
        })),
    };
};

// Password hashing utilities (client-side, for display purposes only)
export const hashPassword = async (password: string, salt: string): Promise<string> => {
    // This is for client-side display only, NOT for security
    const combined = password + salt;
    return await sha256(combined);
};

export const generateSalt = (): string => {
    return generateRandomString(16);
};

// Device fingerprinting utilities
export const generateDeviceFingerprintPromise = async (): Promise<string> => {
    const components = [
        navigator.userAgent,
        navigator.language,
        screen.width + 'x' + screen.height,
        screen.colorDepth,
        new Date().getTimezoneOffset(),
        navigator.hardwareConcurrency || 0,
        navigator.deviceMemory || 0,
        navigator.cookieEnabled,
    ];

    // Add canvas fingerprint
    try {
        const canvas = document.createElement('canvas');
        const ctx = canvas.getContext('2d');
        if (ctx) {
            ctx.textBaseline = 'top';
            ctx.font = '14px Arial';
            ctx.fillText('Frank Auth fingerprint', 2, 2);
            components.push(canvas.toDataURL());
        }
    } catch {
        // Canvas fingerprinting failed, skip
    }

    const fingerprint = components.join('|');
    return await sha256(fingerprint);
};


export const generateDeviceFingerprint = (): string => {
    const canvas = document.createElement('canvas');
    const ctx = canvas.getContext('2d');
    ctx?.fillText('fingerprint', 0, 0);

    const fingerprint = [
        navigator.userAgent,
        navigator.language,
        screen.width + 'x' + screen.height,
        new Date().getTimezoneOffset(),
        canvas.toDataURL(),
        navigator.hardwareConcurrency,
        navigator.deviceMemory,
    ].join('|');

    // Simple hash function
    let hash = 0;
    for (let i = 0; i < fingerprint.length; i++) {
        const char = fingerprint.charCodeAt(i);
        hash = ((hash << 5) - hash) + char;
        hash = hash & hash; // Convert to 32-bit integer
    }

    return Math.abs(hash).toString(36);
};

// Secure random utilities
export const generateSecureToken = (length = 32): string => {
    const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
    return generateRandomString(length, chars);
};

export const generateApiKey = (): string => {
    const prefix = 'pk_';
    const env = 'test_';
    const randomPart = generateRandomString(32);
    return `${prefix}${env}${randomPart}`;
};

// Validation utilities
export const isValidBase64 = (str: string): boolean => {
    try {
        return base64Encode(base64Decode(str)) === str;
    } catch {
        return false;
    }
};

export const isValidJWT = (token: string): boolean => {
    return parseJWT(token) !== null;
};

// Time-based utilities
export const generateTOTPSecret = (): string => {
    // Generate a 32-character base32 secret for TOTP
    const base32Chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
    return generateRandomString(32, base32Chars);
};

export const generateBackupCodes = (count = 10): string[] => {
    const codes: string[] = [];
    for (let i = 0; i < count; i++) {
        codes.push(generateRandomString(8, '0123456789ABCDEF'));
    }
    return codes;
};

// URL safe encoding
export const urlSafeEncode = (data: string): string => {
    return base64UrlEncode(data);
};

export const urlSafeDecode = (encoded: string): string => {
    return base64UrlDecode(encoded);
};

// Checksum utilities
export const calculateChecksum = (data: string): string => {
    let checksum = 0;
    for (let i = 0; i < data.length; i++) {
        checksum += data.charCodeAt(i);
    }
    return checksum.toString(16);
};

export const verifyChecksum = (data: string, expectedChecksum: string): boolean => {
    return calculateChecksum(data) === expectedChecksum;
};

// Key derivation utilities (for client-side use only)
export const deriveKey = async (password: string, salt: string, iterations = 1000): Promise<string> => {
    if (typeof crypto !== 'undefined' && crypto.subtle) {
        const encoder = new TextEncoder();
        const keyMaterial = await crypto.subtle.importKey(
            'raw',
            encoder.encode(password),
            { name: 'PBKDF2' },
            false,
            ['deriveBits']
        );

        const derivedBits = await crypto.subtle.deriveBits(
            {
                name: 'PBKDF2',
                salt: encoder.encode(salt),
                iterations,
                hash: 'SHA-256',
            },
            keyMaterial,
            256
        );

        const array = new Uint8Array(derivedBits);
        return Array.from(array)
            .map(b => b.toString(16).padStart(2, '0'))
            .join('');
    }

    // Fallback: simple hash-based derivation
    let derived = password + salt;
    for (let i = 0; i < iterations; i++) {
        derived = await sha256(derived);
    }
    return derived;
};

// Export utilities for use in other modules
export const CryptoUtils = {
    // Encoding
    base64Encode,
    base64Decode,
    base64UrlEncode,
    base64UrlDecode,
    urlSafeEncode,
    urlSafeDecode,

    // Random generation
    generateRandomBytes,
    generateRandomString,
    generateSecureId,
    generateNonce,
    generateState,
    generateSecureToken,

    // Hashing
    sha256,
    md5,
    calculateChecksum,
    verifyChecksum,

    // JWT
    parseJWT,
    isJWTExpired,
    getJWTExpiration,
    isValidJWT,

    // WebAuthn
    arrayBufferToBase64,
    base64ToArrayBuffer,
    uint8ArrayToBase64,
    base64ToUint8Array,
    credentialToJSON,
    jsonToCredentialCreationOptions,
    jsonToCredentialRequestOptions,

    // PKCE
    generateCodeVerifier,
    generateCodeChallenge,
    generatePKCEPair,

    // Device fingerprinting
    generateDeviceFingerprint,

    // Authentication codes
    generateTOTPSecret,
    generateBackupCodes,

    // Key derivation
    deriveKey,

    // Simple encryption (for obfuscation only)
    simpleEncrypt,
    simpleDecrypt,

    // Validation
    isValidBase64,
};