/* tslint:disable */
/* eslint-disable */
/**
 * Frank Authentication API
 * Multi-tenant authentication SaaS platform API with Clerk.js compatibility
 *
 * The version of the OpenAPI document: 1.0.0
 * Contact: support@frankauth.com
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */

import { mapValues } from '../runtime';
/**
 * 
 * @export
 * @interface CreateOAuthClientRequest
 */
export interface CreateOAuthClientRequest {
    [key: string]: any | any;
    /**
     * A URL to the JSON Schema for this object.
     * @type {string}
     * @memberof CreateOAuthClientRequest
     */
    readonly $schema?: string;
    /**
     * Allowed CORS origins
     * @type {Array<string>}
     * @memberof CreateOAuthClientRequest
     */
    allowedCorsOrigins?: Array<string>;
    /**
     * Allowed grant types
     * @type {Array<string>}
     * @memberof CreateOAuthClientRequest
     */
    allowedGrantTypes?: Array<string>;
    /**
     * Auth code expiry seconds
     * @type {number}
     * @memberof CreateOAuthClientRequest
     */
    authCodeExpirySeconds?: number;
    /**
     * Client description
     * @type {string}
     * @memberof CreateOAuthClientRequest
     */
    clientDescription?: string;
    /**
     * Client application name
     * @type {string}
     * @memberof CreateOAuthClientRequest
     */
    clientName: string;
    /**
     * Client website URL
     * @type {string}
     * @memberof CreateOAuthClientRequest
     */
    clientUri?: string;
    /**
     * Client logo URL
     * @type {string}
     * @memberof CreateOAuthClientRequest
     */
    logoUri?: string;
    /**
     * Post-logout redirect URIs
     * @type {Array<string>}
     * @memberof CreateOAuthClientRequest
     */
    postLogoutRedirectUris?: Array<string>;
    /**
     * Whether client is public
     * @type {boolean}
     * @memberof CreateOAuthClientRequest
     */
    _public: boolean;
    /**
     * Redirect URIs
     * @type {Array<string>}
     * @memberof CreateOAuthClientRequest
     */
    redirectUris: Array<string>;
    /**
     * Refresh token expiry seconds
     * @type {number}
     * @memberof CreateOAuthClientRequest
     */
    refreshTokenExpirySeconds?: number;
    /**
     * Require user consent
     * @type {boolean}
     * @memberof CreateOAuthClientRequest
     */
    requiresConsent: boolean;
    /**
     * Require PKCE
     * @type {boolean}
     * @memberof CreateOAuthClientRequest
     */
    requiresPkce: boolean;
    /**
     * Initial scopes
     * @type {Array<string>}
     * @memberof CreateOAuthClientRequest
     */
    scopeNames?: Array<string>;
    /**
     * Token expiry seconds
     * @type {number}
     * @memberof CreateOAuthClientRequest
     */
    tokenExpirySeconds?: number;
}

/**
 * Check if a given object implements the CreateOAuthClientRequest interface.
 */
export function instanceOfCreateOAuthClientRequest(value: object): value is CreateOAuthClientRequest {
    if (!('clientName' in value) || value['clientName'] === undefined) return false;
    if (!('_public' in value) || value['_public'] === undefined) return false;
    if (!('redirectUris' in value) || value['redirectUris'] === undefined) return false;
    if (!('requiresConsent' in value) || value['requiresConsent'] === undefined) return false;
    if (!('requiresPkce' in value) || value['requiresPkce'] === undefined) return false;
    return true;
}

export function CreateOAuthClientRequestFromJSON(json: any): CreateOAuthClientRequest {
    return CreateOAuthClientRequestFromJSONTyped(json, false);
}

export function CreateOAuthClientRequestFromJSONTyped(json: any, ignoreDiscriminator: boolean): CreateOAuthClientRequest {
    if (json == null) {
        return json;
    }
    return {
        
            ...json,
        '$schema': json['$schema'] == null ? undefined : json['$schema'],
        'allowedCorsOrigins': json['allowedCorsOrigins'] == null ? undefined : json['allowedCorsOrigins'],
        'allowedGrantTypes': json['allowedGrantTypes'] == null ? undefined : json['allowedGrantTypes'],
        'authCodeExpirySeconds': json['authCodeExpirySeconds'] == null ? undefined : json['authCodeExpirySeconds'],
        'clientDescription': json['clientDescription'] == null ? undefined : json['clientDescription'],
        'clientName': json['clientName'],
        'clientUri': json['clientUri'] == null ? undefined : json['clientUri'],
        'logoUri': json['logoUri'] == null ? undefined : json['logoUri'],
        'postLogoutRedirectUris': json['postLogoutRedirectUris'] == null ? undefined : json['postLogoutRedirectUris'],
        '_public': json['public'],
        'redirectUris': json['redirectUris'],
        'refreshTokenExpirySeconds': json['refreshTokenExpirySeconds'] == null ? undefined : json['refreshTokenExpirySeconds'],
        'requiresConsent': json['requiresConsent'],
        'requiresPkce': json['requiresPkce'],
        'scopeNames': json['scopeNames'] == null ? undefined : json['scopeNames'],
        'tokenExpirySeconds': json['tokenExpirySeconds'] == null ? undefined : json['tokenExpirySeconds'],
    };
}

export function CreateOAuthClientRequestToJSON(json: any): CreateOAuthClientRequest {
    return CreateOAuthClientRequestToJSONTyped(json, false);
}

export function CreateOAuthClientRequestToJSONTyped(value?: Omit<CreateOAuthClientRequest, '$schema'> | null, ignoreDiscriminator = false): any {
    if (value == null) {
        return value;
    }

    return {
        
            ...value,
        'allowedCorsOrigins': value['allowedCorsOrigins'],
        'allowedGrantTypes': value['allowedGrantTypes'],
        'authCodeExpirySeconds': value['authCodeExpirySeconds'],
        'clientDescription': value['clientDescription'],
        'clientName': value['clientName'],
        'clientUri': value['clientUri'],
        'logoUri': value['logoUri'],
        'postLogoutRedirectUris': value['postLogoutRedirectUris'],
        'public': value['_public'],
        'redirectUris': value['redirectUris'],
        'refreshTokenExpirySeconds': value['refreshTokenExpirySeconds'],
        'requiresConsent': value['requiresConsent'],
        'requiresPkce': value['requiresPkce'],
        'scopeNames': value['scopeNames'],
        'tokenExpirySeconds': value['tokenExpirySeconds'],
    };
}

