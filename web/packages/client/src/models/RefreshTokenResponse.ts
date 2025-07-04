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
 * @interface RefreshTokenResponse
 */
export interface RefreshTokenResponse {
    /**
     * A URL to the JSON Schema for this object.
     * @type {string}
     * @memberof RefreshTokenResponse
     */
    readonly $schema?: string;
    /**
     * New JWT access token
     * @type {string}
     * @memberof RefreshTokenResponse
     */
    accessToken: string;
    /**
     * Token expiration timestamp
     * @type {Date}
     * @memberof RefreshTokenResponse
     */
    expiresAt: Date;
    /**
     * Token expiration in seconds
     * @type {number}
     * @memberof RefreshTokenResponse
     */
    expiresIn: number;
    /**
     * New refresh token (if rotation enabled)
     * @type {string}
     * @memberof RefreshTokenResponse
     */
    refreshToken?: string;
    /**
     * Token type
     * @type {string}
     * @memberof RefreshTokenResponse
     */
    tokenType: string;
}

/**
 * Check if a given object implements the RefreshTokenResponse interface.
 */
export function instanceOfRefreshTokenResponse(value: object): value is RefreshTokenResponse {
    if (!('accessToken' in value) || value['accessToken'] === undefined) return false;
    if (!('expiresAt' in value) || value['expiresAt'] === undefined) return false;
    if (!('expiresIn' in value) || value['expiresIn'] === undefined) return false;
    if (!('tokenType' in value) || value['tokenType'] === undefined) return false;
    return true;
}

export function RefreshTokenResponseFromJSON(json: any): RefreshTokenResponse {
    return RefreshTokenResponseFromJSONTyped(json, false);
}

export function RefreshTokenResponseFromJSONTyped(json: any, ignoreDiscriminator: boolean): RefreshTokenResponse {
    if (json == null) {
        return json;
    }
    return {
        
        '$schema': json['$schema'] == null ? undefined : json['$schema'],
        'accessToken': json['accessToken'],
        'expiresAt': (new Date(json['expiresAt'])),
        'expiresIn': json['expiresIn'],
        'refreshToken': json['refreshToken'] == null ? undefined : json['refreshToken'],
        'tokenType': json['tokenType'],
    };
}

export function RefreshTokenResponseToJSON(json: any): RefreshTokenResponse {
    return RefreshTokenResponseToJSONTyped(json, false);
}

export function RefreshTokenResponseToJSONTyped(value?: Omit<RefreshTokenResponse, '$schema'> | null, ignoreDiscriminator = false): any {
    if (value == null) {
        return value;
    }

    return {
        
        'accessToken': value['accessToken'],
        'expiresAt': ((value['expiresAt']).toISOString()),
        'expiresIn': value['expiresIn'],
        'refreshToken': value['refreshToken'],
        'tokenType': value['tokenType'],
    };
}

