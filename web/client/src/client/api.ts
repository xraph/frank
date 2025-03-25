import {client} from "sdk";

client.setConfig({
    baseUrl: import.meta.env.PUBLIC_FRANK_ENDPOINT,
    credentials: "include",
})

const frankApi = client;


export { frankApi };
