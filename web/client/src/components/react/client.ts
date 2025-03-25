import {QueryClient} from "@tanstack/react-query";

import {client} from "frank-sdk";

client.setConfig({
    baseUrl: import.meta.env.PUBLIC_FRANK_ENDPOINT,
    credentials: "include",
})


export const queryClient = new QueryClient({
    defaultOptions: {
        queries: {
            retry: 0,
        },
    },
})