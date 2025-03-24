import {QueryClient} from "frank-sdk/react";

export const queryClient = new QueryClient({
    defaultOptions: {
        queries: {
            retry: 0,
        },
    },
})