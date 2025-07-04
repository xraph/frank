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
import type { OAuthClient } from './OAuthClient';
import {
    OAuthClientFromJSON,
    OAuthClientFromJSONTyped,
    OAuthClientToJSON,
    OAuthClientToJSONTyped,
} from './OAuthClient';

/**
 * 
 * @export
 * @interface CreateOAuthClientResponse
 */
export interface CreateOAuthClientResponse {
    /**
     * A URL to the JSON Schema for this object.
     * @type {string}
     * @memberof CreateOAuthClientResponse
     */
    readonly $schema?: string;
    /**
     * Created OAuth client
     * @type {OAuthClient}
     * @memberof CreateOAuthClientResponse
     */
    client: OAuthClient;
    /**
     * Generated client secret
     * @type {string}
     * @memberof CreateOAuthClientResponse
     */
    clientSecret: string;
}

/**
 * Check if a given object implements the CreateOAuthClientResponse interface.
 */
export function instanceOfCreateOAuthClientResponse(value: object): value is CreateOAuthClientResponse {
    if (!('client' in value) || value['client'] === undefined) return false;
    if (!('clientSecret' in value) || value['clientSecret'] === undefined) return false;
    return true;
}

export function CreateOAuthClientResponseFromJSON(json: any): CreateOAuthClientResponse {
    return CreateOAuthClientResponseFromJSONTyped(json, false);
}

export function CreateOAuthClientResponseFromJSONTyped(json: any, ignoreDiscriminator: boolean): CreateOAuthClientResponse {
    if (json == null) {
        return json;
    }
    return {
        
        '$schema': json['$schema'] == null ? undefined : json['$schema'],
        'client': OAuthClientFromJSON(json['client']),
        'clientSecret': json['clientSecret'],
    };
}

export function CreateOAuthClientResponseToJSON(json: any): CreateOAuthClientResponse {
    return CreateOAuthClientResponseToJSONTyped(json, false);
}

export function CreateOAuthClientResponseToJSONTyped(value?: Omit<CreateOAuthClientResponse, '$schema'> | null, ignoreDiscriminator = false): any {
    if (value == null) {
        return value;
    }

    return {
        
        'client': OAuthClientToJSON(value['client']),
        'clientSecret': value['clientSecret'],
    };
}

