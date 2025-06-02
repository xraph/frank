import {TokenData} from "../types";
import * as cookieParser from "cookie";
import {getItem, removeItem, setItem} from "./storage";
import {getConfig} from "../config";
import {CookieHandler} from "@/utils/cookie";

const TOKEN_KEY = "token";
const REFRESH_TOKEN_KEY = "refresh_token";
const EXPIRES_AT_KEY = "expires_at";
const SESSION_COOKIE_NAME = "frank_session";

export const getToken = (cookie?: string): string | null => {
	return getItem(TOKEN_KEY, cookie);
};

export const getRefreshToken = (cookie?: string): string | null => {
	return getItem(REFRESH_TOKEN_KEY, cookie);
};

export const getExpiresAt = (cookie?: string): number => {
	const expiresAt = getItem(EXPIRES_AT_KEY, cookie);
	return expiresAt ? parseInt(expiresAt, 10) : 0;
};

export const setTokenData = (
	data: TokenData,
	cookieHandler?: CookieHandler,
): void => {
	setItem(TOKEN_KEY, data.token, cookieHandler);
	setItem(REFRESH_TOKEN_KEY, data.refreshToken, cookieHandler);
	setItem(EXPIRES_AT_KEY, data.expiresAt.toString(), cookieHandler);

	// If cookies are enabled, also set a session cookie for server-side auth
	if (
		getConfig().tokenStorageType === "cookie" &&
		typeof document !== "undefined"
	) {
		const secure = window.location.protocol === "https:";
		document.cookie = `${SESSION_COOKIE_NAME}=${data.token};path=/;${secure ? "secure;" : ""}samesite=strict;max-age=${Math.floor((data.expiresAt * 1000 - Date.now()) / 1000)}`;
	}
};

export const clearTokenData = (cookieHandler?: CookieHandler): void => {
	removeItem(TOKEN_KEY, cookieHandler);
	removeItem(REFRESH_TOKEN_KEY, cookieHandler);
	removeItem(EXPIRES_AT_KEY, cookieHandler);

	// Clear session cookie if it exists
	if (typeof document !== "undefined") {
		document.cookie = `${SESSION_COOKIE_NAME}=;path=/;expires=Thu, 01 Jan 1970 00:00:00 GMT;`;
	}
};

export const isTokenExpired = (
	cookie?: string,
	response?: Response,
): boolean => {
	const expiresAt = getExpiresAt(cookie);
	if (!expiresAt) return true;

	// Add a 60-second buffer to ensure the token is considered expired
	// slightly before its actual expiration time
	return Date.now() >= expiresAt * 1000 - 60000;
};

export const getTokenData = (cookie?: string): TokenData | null => {
	const token = getToken(cookie);
	const refreshToken = getRefreshToken(cookie);
	const expiresAt = getExpiresAt(cookie);

	if (!token || !refreshToken || !expiresAt) {
		return null;
	}

	return {
		token,
		refreshToken,
		expiresAt,
	};
};

// Get token from session cookie (for server-side use)
export const getSessionTokenFromCookie = (
	cookieString: string,
): string | null => {
	if (!cookieString) return null;

	// Match the session cookie name
	const cookieName = getConfig().cookieName || SESSION_COOKIE_NAME;
	const cookies = cookieParser.parse(cookieString);
	// @ts-ignore
	return cookies[cookieName] ?? null;
};

// Check if token from cookie is valid and not expired
export const isAuthenticatedFromCookie = (cookieString: string): boolean => {
	const token = getSessionTokenFromCookie(cookieString);
	return !!token;
};

// Get token from session cookie (for server-side use)
export const getRemoteSessionTokenFromCookie = (
	cookieString: string,
	cookieName?: string,
): string | null => {
	if (!cookieString) return null;

	// Match the session cookie name
	const cn = cookieName ?? "frank_session";
	const cookies = cookieParser.parse(cookieString);
	// @ts-ignore
	return cookies[cn] ?? null;
};

// Check if token from cookie is valid and not expired
export const isRemoteAuthenticatedFromCookie = (
	cookieString: string,
	cookieName?: string,
): boolean => {
	const token = getRemoteSessionTokenFromCookie(cookieString, cookieName);
	return !!token;
};
