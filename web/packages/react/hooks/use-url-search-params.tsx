'use client'

import {useEffect, useState} from "react";

/**
 * A cross-platform hook to access URL search parameters in React
 * Works in any React environment including:
 * - Next.js (both client and server components)
 * - React Router
 * - Plain React apps
 * - React Native (web)
 */
export function useUrlSearchParams() {
    // Initialize with empty URLSearchParams object
    const [searchParams, setSearchParams] = useState<URLSearchParams>(
        typeof window !== "undefined"
            ? new URLSearchParams(window.location.search)
            : new URLSearchParams()
    );

    useEffect(() => {
        // Function to update search params when URL changes
        const updateSearchParams = () => {
            setSearchParams(new URLSearchParams(window.location.search));
        };

        // Listen for URL changes
        window.addEventListener("popstate", updateSearchParams);

        // Cleanup listener
        return () => {
            window.removeEventListener("popstate", updateSearchParams);
        };
    }, []);

    // Custom getter method that matches Next.js useSearchParams API
    const get = (key: string): string | null => {
        return searchParams.get(key);
    };

    // Custom has method
    const has = (key: string): boolean => {
        return searchParams.has(key);
    };

    // Get all values for a key
    const getAll = (key: string): string[] => {
        return searchParams.getAll(key);
    };

    // Get all entries as [key, value] pairs
    const entries = (): [string, string][] => {
        return Array.from(searchParams.entries());
    };

    // Get all keys
    const keys = (): string[] => {
        return Array.from(searchParams.keys());
    };

    // Get search params as object
    const asObject = (): Record<string, string> => {
        const result: Record<string, string> = {};
        for (const [key, value] of searchParams.entries()) {
            result[key] = value;
        }
        return result;
    };

    // Return an API similar to Next.js useSearchParams but with additional helpers
    return {
        get,
        has,
        getAll,
        entries,
        keys,
        asObject,
        toString: () => searchParams.toString(),
        // Also expose the raw URLSearchParams object for advanced use cases
        params: searchParams
    };
}