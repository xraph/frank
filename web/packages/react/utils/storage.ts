// src/utils/storage.ts
import { getConfig } from "../config";
import { CookieHandler } from "@/utils/cookie";

type StorageType = "localStorage" | "sessionStorage" | "cookie" | "memory";

// In-memory fallback
const memoryStorage: Record<string, string> = {};

export const getStorageType = (): StorageType => {
	return getConfig().tokenStorageType || "localStorage";
};

export const getStoragePrefix = (): string => {
	return getConfig().storagePrefix || "frank_auth_";
};

export const getItem = (key: string, cookie?: string): string | null => {
	const prefixedKey = `${getStoragePrefix()}${key}`;
	const storageType = getStorageType();

	switch (storageType) {
		case "localStorage":
			if (typeof window !== "undefined") {
				return window.localStorage.getItem(prefixedKey);
			}
			return null;
		case "sessionStorage":
			if (typeof window !== "undefined") {
				return window.sessionStorage.getItem(prefixedKey);
			}
			return null;
		case "cookie":
			if (cookie) {
				const match = cookie.match(new RegExp(`(^| )${prefixedKey}=([^;]+)`));
				return match ? decodeURIComponent(match[2]) : null;
			}

			if (typeof document !== "undefined") {
				const match = document.cookie.match(
					new RegExp(`(^| )${prefixedKey}=([^;]+)`),
				);
				return match ? decodeURIComponent(match[2]) : null;
			}
			return null;
		case "memory":
			return memoryStorage[prefixedKey] || null;
		default:
			return null;
	}
};

export const setItem = (
	key: string,
	value: string,
	cookieHandler?: CookieHandler,
): void => {
	const prefixedKey = `${getStoragePrefix()}${key}`;
	const storageType = getStorageType();

	switch (storageType) {
		case "localStorage":
			if (typeof window !== "undefined") {
				window.localStorage.setItem(prefixedKey, value);
			}
			break;
		case "sessionStorage":
			if (typeof window !== "undefined") {
				window.sessionStorage.setItem(prefixedKey, value);
			}
			break;
		case "cookie":
			if (cookieHandler) {
				cookieHandler.setCookie(prefixedKey, value);
				break;
			}
			if (typeof document !== "undefined") {
				// Set cookie to expire in 30 days
				const expiryDate = new Date();
				expiryDate.setDate(expiryDate.getDate() + 30);
				const secure = window.location.protocol === "https:";
				document.cookie = `${prefixedKey}=${encodeURIComponent(value)};expires=${expiryDate.toUTCString()};path=/;${secure ? "secure;" : ""}samesite=strict`;
			}
			break;
		case "memory":
			memoryStorage[prefixedKey] = value;
			break;
	}
};

export const removeItem = (
	key: string,
	cookieHandler?: CookieHandler,
): void => {
	const prefixedKey = `${getStoragePrefix()}${key}`;
	const storageType = getStorageType();

	switch (storageType) {
		case "localStorage":
			if (typeof window !== "undefined") {
				window.localStorage.removeItem(prefixedKey);
			}
			break;
		case "sessionStorage":
			if (typeof window !== "undefined") {
				window.sessionStorage.removeItem(prefixedKey);
			}
			break;
		case "cookie":
			if (cookieHandler) {
				cookieHandler.deleteCookie(prefixedKey);
				break;
			}
			if (typeof document !== "undefined") {
				document.cookie = `${prefixedKey}=;expires=Thu, 01 Jan 1970 00:00:00 GMT;path=/;`;
			}
			break;
		case "memory":
			delete memoryStorage[prefixedKey];
			break;
	}
};

export const clearStorage = (cookieHandler?: CookieHandler): void => {
	const prefix = getStoragePrefix();
	const storageType = getStorageType();

	switch (storageType) {
		case "localStorage":
			if (typeof window !== "undefined") {
				Object.keys(window.localStorage)
					.filter((key) => key.startsWith(prefix))
					.forEach((key) => window.localStorage.removeItem(key));
			}
			break;
		case "sessionStorage":
			if (typeof window !== "undefined") {
				Object.keys(window.sessionStorage)
					.filter((key) => key.startsWith(prefix))
					.forEach((key) => window.sessionStorage.removeItem(key));
			}
			break;
		case "cookie":
			if (cookieHandler) {
			}
			if (typeof document !== "undefined") {
				document.cookie
					.split(";")
					.map((cookie) => cookie.trim())
					.filter((cookie) => cookie.startsWith(prefix))
					.forEach((cookie) => {
						const name = cookie.split("=")[0];
						document.cookie = `${name}=;expires=Thu, 01 Jan 1970 00:00:00 GMT;path=/;`;
					});
			}
			break;
		case "memory":
			Object.keys(memoryStorage)
				.filter((key) => key.startsWith(prefix))
				.forEach((key) => delete memoryStorage[key]);
			break;
	}
};

// Parse cookies from a cookie string (for server-side)
export const parseCookies = (cookieString: string): Record<string, string> => {
	const cookies: Record<string, string> = {};
	if (!cookieString) return cookies;

	cookieString.split(";").forEach((cookie) => {
		const parts = cookie.trim().split("=");
		if (parts.length >= 2) {
			const name = parts[0];
			const value = parts.slice(1).join("=");
			cookies[name] = decodeURIComponent(value);
		}
	});

	return cookies;
};
