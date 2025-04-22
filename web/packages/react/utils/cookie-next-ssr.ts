import { NextRequest, NextResponse } from "next/server";
import { CookieHandler, Options } from "./cookie";
import { cookies } from "next/headers";
import {
	deleteCookie,
	getCookie,
	getCookies,
	hasCookie,
	setCookie,
} from "cookies-next/server";

export class NextServerCookieHandler implements CookieHandler {
	constructor(
		private req: NextRequest,
		private res: NextResponse,
	) {}

	async setCookie(
		name: string,
		value: string,
		opts: Options = {},
	): Promise<void> {
		await setCookie(name, value, { ...opts, req: this.req, res: this.res });
	}
	async getCookie(name: string): Promise<string | undefined> {
		return await getCookie(name, { req: this.req, res: this.res });
	}
	async deleteCookie(name: string): Promise<void> {
		await deleteCookie(name, { req: this.req, res: this.res });
	}
	async getCookies(): Promise<
		{ [key: string]: string } | Partial<{ [key: string]: string }>
	> {
		return await getCookies({ req: this.req, res: this.res });
	}
	hasCookie(name: string): Promise<boolean> {
		return hasCookie(name, { req: this.req, res: this.res });
	}

	async copyTo(targetHandler: NextServerCookieHandler) {
		const cookiesToCopy = await this.getCookies();

		for (const [key, value] of Object.entries(cookiesToCopy)) {
			await targetHandler.setCookie(key, value as any);
		}

		// Copy any relevant headers
		const headers = this.res.headers;
		headers.forEach((value, key) => {
			targetHandler.res.headers.set(key, value);
		});
	}
}

export class NextServerActionCookieHandler implements CookieHandler {
	async setCookie(
		name: string,
		value: string,
		opts: Options = {},
	): Promise<void> {
		await setCookie(name, value, { ...opts, cookies });
	}
	async getCookie(name: string): Promise<string | undefined> {
		return await getCookie(name, { cookies });
	}
	async deleteCookie(name: string): Promise<void> {
		await deleteCookie(name, { cookies });
	}
	async getCookies(): Promise<
		{ [key: string]: string } | Partial<{ [key: string]: string }>
	> {
		return await getCookies({ cookies });
	}
	hasCookie(name: string): Promise<boolean> {
		return hasCookie(name, { cookies });
	}

	copyTo(targetHandler: CookieHandler): void {
		throw new Error("Method not implemented.");
	}
}
