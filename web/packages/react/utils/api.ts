import {
	authRefreshToken,
	client as fclient,
	type Client,
} from "@frank-auth/sdk";
import { getConfig } from "../config";
import {
	clearTokenData,
	getTokenData,
	isTokenExpired,
	setTokenData,
} from "./token";
import { TokenData } from "../types";
import { CookieHandler } from "@/utils/cookie";

// type Client = () => typeof fclient;

// Create a base API client
export const createApiClient = (): Client => {
	const config = getConfig();

	fclient.setConfig({
		baseUrl: config.baseUrl,
		headers: {},
	});

	return fclient;
};

// Create an authenticated API client with token handling
export const createAuthenticatedClient = (cookie?: string): Client => {
	const config = getConfig();
	const tokenData = getTokenData(cookie);

	fclient.setConfig({
		baseUrl: config.baseUrl,
		headers: tokenData
			? {
					Authorization: `Bearer ${tokenData.token}`,
				}
			: {},
	});

	// Add organization ID to headers if provided
	if (config.organizationId) {
		fclient.setConfig({
			...fclient.getConfig(),
			headers: {
				...fclient.getConfig().headers,
				"X-Organization-ID": config.organizationId,
			},
		});
	}

	return fclient;
};

// Function to refresh the token
export const refreshAuthToken = async (
	cookie?: string,
	cookieHandler?: CookieHandler,
): Promise<TokenData | null> => {
	const tokenData = getTokenData(cookie);
	if (!tokenData) return null;

	try {
		const client = createApiClient();
		const { data } = await authRefreshToken({
			body: {
				refresh_token: tokenData.refreshToken,
			},
			throwOnError: true,
			client,
		});

		const newTokenData: TokenData = {
			token: data.token,
			refreshToken: data.refresh_token,
			expiresAt: Number(data.expires_at),
		};

		setTokenData(newTokenData, cookieHandler);
		return newTokenData;
	} catch (error) {
		clearTokenData();
		return null;
	}
};

// Get authorized client with automatic token refresh
export const getAuthClient = async (): Promise<Client> => {
	if (isTokenExpired() && getTokenData()) {
		await refreshAuthToken();
	}

	return createAuthenticatedClient() as any;
};
//
// // Function to refresh the token
// export const refreshAuthToken = async (): Promise<TokenData | null> => {
//     const tokenData = getTokenData();
//     if (!tokenData) return null;
//
//     try {
//         const client = createApiClient();
//         const { data } = await authRefreshToken({
//             client,
//             body: {
//                 refresh_token: tokenData.refreshToken
//             },
//             throwOnError: true
//         });
//
//         const newTokenData: TokenData = {
//             token: data.token,
//             refreshToken: data.refresh_token,
//             expiresAt: Number(data.expires_at),
//         };
//
//         setTokenData(newTokenData);
//         return newTokenData;
//     } catch (error) {
//         clearTokenData();
//         return null;
//     }
// };
