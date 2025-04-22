'use client'

import {CookieHandler, Options} from "./cookie";
import {deleteCookie, getCookie, getCookies, hasCookie, setCookie} from 'cookies-next/client';

export class NextClientCookieHandler implements CookieHandler {
    copyTo(targetHandler: CookieHandler): void {
        throw new Error("Method not implemented.");
    }
    setCookie(name: string, value: string, opts: Options = {}): void {
        return setCookie(name, value, {...opts});
    }
    getCookie(name: string): string | undefined {
       return getCookie(name)
    }
     deleteCookie(name: string): void {
         return deleteCookie(name);
    }
    getCookies(): { [key: string]: string } | Partial<{ [key: string]: string }> | undefined {
        return getCookies()
    }
    hasCookie(name: string): boolean {
        return hasCookie(name)
    }

}