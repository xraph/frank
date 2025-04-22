import { AuthConfig } from "../types";

let config: AuthConfig = {
	baseUrl: process.env.NEXT_PUBLIC_FRANK_ENDPOINT ?? "",
	storagePrefix: "frank_auth_",
	tokenStorageType: "localStorage",
	cookieName: "_frank_sid",
};

export const setConfig = (newConfig: Partial<AuthConfig>): void => {
	config = { ...config, ...newConfig };
};

export const getConfig = (): AuthConfig => {
	return { ...config };
};
