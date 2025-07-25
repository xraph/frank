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
 * @interface PasswordResetRequest
 */
export interface PasswordResetRequest {
    /**
     * A URL to the JSON Schema for this object.
     * @type {string}
     * @memberof PasswordResetRequest
     */
    readonly $schema?: string;
    /**
     * User email address
     * @type {string}
     * @memberof PasswordResetRequest
     */
    email: string;
    /**
     * URL to redirect to after reset
     * @type {string}
     * @memberof PasswordResetRequest
     */
    redirectUrl?: string;
}

/**
 * Check if a given object implements the PasswordResetRequest interface.
 */
export function instanceOfPasswordResetRequest(value: object): value is PasswordResetRequest {
    if (!('email' in value) || value['email'] === undefined) return false;
    return true;
}

export function PasswordResetRequestFromJSON(json: any): PasswordResetRequest {
    return PasswordResetRequestFromJSONTyped(json, false);
}

export function PasswordResetRequestFromJSONTyped(json: any, ignoreDiscriminator: boolean): PasswordResetRequest {
    if (json == null) {
        return json;
    }
    return {
        
        '$schema': json['$schema'] == null ? undefined : json['$schema'],
        'email': json['email'],
        'redirectUrl': json['redirectUrl'] == null ? undefined : json['redirectUrl'],
    };
}

export function PasswordResetRequestToJSON(json: any): PasswordResetRequest {
    return PasswordResetRequestToJSONTyped(json, false);
}

export function PasswordResetRequestToJSONTyped(value?: Omit<PasswordResetRequest, '$schema'> | null, ignoreDiscriminator = false): any {
    if (value == null) {
        return value;
    }

    return {
        
        'email': value['email'],
        'redirectUrl': value['redirectUrl'],
    };
}

