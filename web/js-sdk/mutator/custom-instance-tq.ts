import * as process from "node:process";

const baseURL = process.env.FRANK_ENDPOINT; // use your own URL here or environment variable

export const customInstance = async <T>(
    url: string | Request | URL,
    init?: (RequestInit & {signal?: any}) | undefined,
): Promise<T> => {
    if (!baseURL) {
        throw new Error('FRANK_ENDPOINT is not defined');
    }

    const response = await fetch(url, {
        credentials: 'include',
        ...init,
    });

    // if (!response.ok) {
    //     throw new Error(response.statusText);
    // }

    return response.json();
};

export default customInstance;