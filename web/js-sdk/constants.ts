import process from "node:process";

let BaseURL = process?.env?.FRANK_ENDPOINT ?? '';

function setBaseURL(url: string) {
    BaseURL = url;
}

export { BaseURL, setBaseURL };