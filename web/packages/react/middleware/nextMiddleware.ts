import {NextRequest, NextResponse} from "next/server";
import {getTokenData, isRemoteAuthenticatedFromCookie, isTokenExpired,} from "../utils/token";
import {getConfig} from "../config";
import {createAuthenticatedClient, refreshAuthToken} from "@/utils/api";
import {authMe, User} from "@frank-auth/sdk";
import {NextServerCookieHandler} from "../utils/cookie-next-ssr";

export interface NextAuthMiddlewareOptions {
	authPages?: string[]; // Pages related to auth (login, register, etc.)
	publicPages?: string[]; // Pages accessible without authentication
	loginPage?: string; // Page to redirect to when auth fails
	cookieName?: string; // Override default session cookie name
	orgRequired?: boolean; // Whether organization context is required
	beforeAuth?: (
		request: NextRequest,
		response: NextResponse,
	) => Promise<NextResponse | null>; // Before auth hook
	afterAuth?: (
		request: NextRequest,
		response: NextResponse,
		isAuthenticated: boolean,
		user?: User,
	) => Promise<NextResponse | null>; // After auth hook
	onAuthSuccess?: (
		request: NextRequest,
		response: NextResponse,
		user: User,
	) => Promise<NextResponse | null>; // Called when auth succeeds
	onAuthFailure?: (
		request: NextRequest,
		response: NextResponse,
	) => Promise<NextResponse | null>; // Called when auth fails
}

const defaultOptions: NextAuthMiddlewareOptions = {
	authPages: ["/login", "/register", "/forgot-password", "/reset-password"],
	publicPages: ["/", "/about", "/contact"],
	loginPage: "/login",
	orgRequired: false,
	cookieName: "frank_session",
};

// Helper to match path patterns
const matchPath = (path: string, patterns: string[]): boolean => {
	return patterns.some((pattern) => {
		if (pattern.endsWith("*")) {
			return path.startsWith(pattern.slice(0, -1));
		}
		return path === pattern;
	});
};

// Validate session with API call
const validateSession = async (
	cookie: string,
): Promise<{ isValid: boolean; user?: any }> => {
	try {
		const client = createAuthenticatedClient(cookie);
		client.setConfig({
			...client.getConfig(),
			credentials: "include",
			throwOnError: true,
		});

		// Use the default authMe function or a custom endpoint
		const { data } = await authMe({
			client,
			headers: {
				Cookie: cookie,
			},
			credentials: "include",
		});

		return { isValid: true, user: data };
	} catch (error) {
		return { isValid: false };
	}
};

export function createNextAuthMiddleware(
	customOptions: NextAuthMiddlewareOptions = {},
) {
	const options = { ...defaultOptions, ...customOptions };

	return async function middleware(request: NextRequest) {
		const { pathname } = request.nextUrl;

		// Set cookie name in config if specified
		if (options.cookieName) {
			getConfig().cookieName = options.cookieName;
		}

		// Initialize with config from cookies if available
		const baseUrl = request.cookies.get("frank_auth_baseUrl")?.value;
		if (baseUrl) {
			getConfig().baseUrl = baseUrl;
		}

		// Skip middleware for public assets
		if (
			pathname.startsWith("/_next") ||
			pathname.startsWith("/api") ||
			pathname.startsWith("/static") ||
			pathname.includes(".")
		) {
			return NextResponse.next();
		}

		// First check session cookie (server-side)
		const cookieHeader = request.cookies.toString();

		const requestHeaders = new Headers(request.headers);
		requestHeaders.set("x-pathname", request.nextUrl.pathname);
		requestHeaders.set("x-search", request.nextUrl.search);
		requestHeaders.set("x-hash", request.nextUrl.hash);
		requestHeaders.set("x-origin", request.nextUrl.origin);
		requestHeaders.set("x-host", request.nextUrl.host);
		requestHeaders.set("x-hostname", request.nextUrl.hostname);
		requestHeaders.set("x-port", request.nextUrl.port);
		requestHeaders.set("x-protocol", request.nextUrl.protocol);
		requestHeaders.set("x-href", request.nextUrl.href);

		// Create a single response object to be modified throughout
		const response = NextResponse.next({
			headers: requestHeaders,
		});
		const cookieHandler = new NextServerCookieHandler(request, response);

		// Execute beforeAuth hook if provided
		if (options.beforeAuth) {
			const resp = await options.beforeAuth(request, response);
			if (resp) return resp;
		}

		// Check if the page is public or an auth page
		if (matchPath(pathname, options.publicPages || [])) {
			return response;
		}

		// Check authentication - first try cookie, then fallback to token
		let isAuthenticated = false;
		let user = null;
		let token = null;

		if (isRemoteAuthenticatedFromCookie(cookieHeader, options.cookieName)) {
			const validation = await validateSession(cookieHeader);
			isAuthenticated = validation.isValid;
			user = validation.user;
		}

		// If no session cookie, check token storage
		if (!isAuthenticated) {
			const tokenData = getTokenData(cookieHeader);
			isAuthenticated = !!tokenData && !isTokenExpired(cookieHeader);
			if (isTokenExpired(cookieHeader)) {
				const newTokenData = await refreshAuthToken(
					cookieHeader,
					cookieHandler,
				);
				if (!newTokenData) {
					// clearTokenData(cookieHandler)
				}

				token = newTokenData?.token;
				if (token) {
					isAuthenticated = true;
				}
			}
			const validation = await validateSession(cookieHeader);
			user = validation.user;
		}

		// Execute afterAuth hook if provided
		if (options.afterAuth) {
			const rsp = await options.afterAuth(
				request,
				response,
				isAuthenticated,
				user,
			);
			if (rsp) return rsp;
		}

		// Check if the page is an auth page
		if (!isAuthenticated && matchPath(pathname, options.authPages || [])) {
			return response;
		}

		// If on a protected page and not authenticated, redirect to login
		if (!isAuthenticated) {
			if (options.onAuthFailure) {
				const rsp = await options.onAuthFailure(request, response);
				if (rsp) return rsp;
			}
			const loginUrl = new URL(options.loginPage || "/login", request.url);
			loginUrl.searchParams.set("redirect", pathname);

			// Create a redirect response by cloning and modifying our response
			const redirectResponse = NextResponse.redirect(loginUrl);
			// Copy cookies and headers from our original response
			await cookieHandler.copyTo(
				new NextServerCookieHandler(request, redirectResponse),
			);
			return redirectResponse;
		}

		if (options.onAuthSuccess) {
			const rsp = await options.onAuthSuccess(request, response, user);
			rsp?.headers.set("Cache-Control", "no-store");
			if (rsp) return rsp;
		}

		// If on an auth page and already authenticated, redirect to dashboard
		if (isAuthenticated && matchPath(pathname, options.authPages || [])) {
			// Create a redirect response by cloning and modifying our response
			const redirectResponse = NextResponse.redirect(
				new URL("/dashboard", request.url),
				{
					headers: requestHeaders,
				},
			);
			// Copy cookies and headers from our original response
			await cookieHandler.copyTo(
				new NextServerCookieHandler(request, redirectResponse),
			);
			return redirectResponse;
		}

		// Check organization context if required
		if (options.orgRequired && isAuthenticated) {
			const orgId = request.cookies.get("frank_oid")?.value;
			if (!orgId && !pathname.includes("/organization-select")) {
				const redirectResponse = NextResponse.redirect(
					new URL("/organization-select", request.url),
					{
						headers: requestHeaders,
					},
				);
				await cookieHandler.copyTo(
					new NextServerCookieHandler(request, redirectResponse),
				);
				return redirectResponse;
			}
		}

		// Continue to the requested page
		return response;
	};
}