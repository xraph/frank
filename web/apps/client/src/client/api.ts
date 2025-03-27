import { client } from "@frank-auth/sdk";

export const isLocal = import.meta.env.PUBLIC_MODE === "local";

client.setConfig({
	baseUrl: import.meta.env.PUBLIC_FRANK_ENDPOINT,
	credentials: "include",
});

const frankApi = client;

export { frankApi };
