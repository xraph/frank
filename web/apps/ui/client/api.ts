import { client } from "@frank-auth/sdk";

export const isLocal = process.env.PUBLIC_MODE === "local";

client.setConfig({
	baseUrl: process.env.PUBLIC_FRANK_ENDPOINT,
	credentials: "include",
});

const frankApi = client;

export { frankApi };
