import { QueryClient } from "@tanstack/react-query";

import { client } from "@frank-auth/sdk";

client.setConfig({
	baseUrl: process.env.PUBLIC_FRANK_ENDPOINT,
	credentials: "include",
});

export const queryClient = new QueryClient({
	defaultOptions: {
		queries: {
			retry: 0,
		},
	},
});
