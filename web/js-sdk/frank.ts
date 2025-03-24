import * as rbac from "./vanilla/rbac/rbac";
import * as auth from "./vanilla/auth/auth";
import * as organizations from "./vanilla/organizations/organizations";
import * as sso from "./vanilla/sso/sso";
import * as oauthClient from "./vanilla/oauth-client/oauth-client";
import {setBaseURL} from "./constants";

export class FrankAPI {
    rbac = rbac;
    auth = auth;
    organizations = organizations;
    sso = sso;
    oauthClient = oauthClient;

    constructor(baseURL: string) {
        setBaseURL(baseURL);
    }
}