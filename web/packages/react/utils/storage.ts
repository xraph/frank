import { getConfig } from "../config";

type StorageType = "localStorage" | "sessionStorage" | "cookie" | "memory";

// In-memory fallback
const memoryStorage: Record<string, string> = {};

export const getStorageType = (): StorageType => {
	return getConfig().tokenStorageType || "localStorage";
};

export const getStoragePrefix = (): string => {
	return getConfig().storagePrefix || "frank_auth_";
};

export const getItem = (key: string): string | null => {
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

export const setItem = (key: string, value: string): void => {
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
			if (typeof document !== "undefined") {
				// Set cookie to expire in 30 days
				const expiryDate = new Date();
				expiryDate.setDate(expiryDate.getDate() + 30);
				document.cookie = `${prefixedKey}=${encodeURIComponent(value)};expires=${expiryDate.toUTCString()};path=/;SameSite=Strict`;
			}
			break;
		case "memory":
			memoryStorage[prefixedKey] = value;
			break;
	}
};

export const removeItem = (key: string): void => {
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
			if (typeof document !== "undefined") {
				document.cookie = `${prefixedKey}=;expires=Thu, 01 Jan 1970 00:00:00 GMT;path=/;SameSite=Strict`;
			}
			break;
		case "memory":
			delete memoryStorage[prefixedKey];
			break;
	}
};

export const clearStorage = (): void => {
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
			if (typeof document !== "undefined") {
				document.cookie
					.split(";")
					.map((cookie) => cookie.trim())
					.filter((cookie) => cookie.startsWith(prefix))
					.forEach((cookie) => {
						const name = cookie.split("=")[0];
						document.cookie = `${name}=;expires=Thu, 01 Jan 1970 00:00:00 GMT;path=/;SameSite=Strict`;
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
