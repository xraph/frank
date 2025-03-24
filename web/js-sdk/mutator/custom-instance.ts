import 'isomorphic-fetch';

import {BaseURL} from "../constants";

export const customInstance = async <T>(
    url: string | Request | URL,
    init?: (RequestInit & {signal?: any}) | undefined,
): Promise<T> => {
    try {
        let newUrl = url;
        if (!BaseURL) {
           console.log('FRANK_ENDPOINT is not defined');
            // throw new Error('FRANK_ENDPOINT is not defined');
        } else {
            newUrl = `${BaseURL}${url}`
        }

        const response = await fetch(newUrl, {
            credentials: 'include',
            ...(init ?? {}),
        });

        const data = await response.json();
        return {
            data: data as any,
            status: response.status,
            statusText: response.statusText,
        } as T;
    } catch (error) {
        throw error;
    }
};

export default customInstance;