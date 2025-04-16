import { TokenData } from "../types";
import { getItem, removeItem, setItem } from "./storage";

const TOKEN_KEY = "token";
const REFRESH_TOKEN_KEY = "refresh_token";
const EXPIRES_AT_KEY = "expires_at";

export const getToken = (): string | null => {
	return getItem(TOKEN_KEY);
};

export const getRefreshToken = (): string | null => {
	return getItem(REFRESH_TOKEN_KEY);
};

export const getExpiresAt = (): number => {
	const expiresAt = getItem(EXPIRES_AT_KEY);
	return expiresAt ? parseInt(expiresAt, 10) : 0;
};

export const setTokenData = (data: TokenData): void => {
	setItem(TOKEN_KEY, data.token);
	setItem(REFRESH_TOKEN_KEY, data.refreshToken);
	setItem(EXPIRES_AT_KEY, data.expiresAt.toString());
};

export const clearTokenData = (): void => {
	removeItem(TOKEN_KEY);
	removeItem(REFRESH_TOKEN_KEY);
	removeItem(EXPIRES_AT_KEY);
};

export const isTokenExpired = (): boolean => {
	const expiresAt = getExpiresAt();
	if (!expiresAt) return true;

	// Add a 60-second buffer to ensure the token is considered expired
	// slightly before its actual expiration time
	return Date.now() >= expiresAt * 1000 - 60000;
};

export const getTokenData = (): TokenData | null => {
	const token = getToken();
	const refreshToken = getRefreshToken();
	const expiresAt = getExpiresAt();

	if (!token || !refreshToken || !expiresAt) {
		return null;
	}

	return {
		token,
		refreshToken,
		expiresAt,
	};
};
