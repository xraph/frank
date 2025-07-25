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
 * @interface VerifyEmailRequestBody
 */
export interface VerifyEmailRequestBody {
    /**
     * A URL to the JSON Schema for this object.
     * @type {string}
     * @memberof VerifyEmailRequestBody
     */
    readonly $schema?: string;
    /**
     * Email verification code
     * @type {string}
     * @memberof VerifyEmailRequestBody
     */
    code: string;
    /**
     * MFA method ID
     * @type {string}
     * @memberof VerifyEmailRequestBody
     */
    methodId: string;
}

/**
 * Check if a given object implements the VerifyEmailRequestBody interface.
 */
export function instanceOfVerifyEmailRequestBody(value: object): value is VerifyEmailRequestBody {
    if (!('code' in value) || value['code'] === undefined) return false;
    if (!('methodId' in value) || value['methodId'] === undefined) return false;
    return true;
}

export function VerifyEmailRequestBodyFromJSON(json: any): VerifyEmailRequestBody {
    return VerifyEmailRequestBodyFromJSONTyped(json, false);
}

export function VerifyEmailRequestBodyFromJSONTyped(json: any, ignoreDiscriminator: boolean): VerifyEmailRequestBody {
    if (json == null) {
        return json;
    }
    return {
        
        '$schema': json['$schema'] == null ? undefined : json['$schema'],
        'code': json['code'],
        'methodId': json['methodId'],
    };
}

export function VerifyEmailRequestBodyToJSON(json: any): VerifyEmailRequestBody {
    return VerifyEmailRequestBodyToJSONTyped(json, false);
}

export function VerifyEmailRequestBodyToJSONTyped(value?: Omit<VerifyEmailRequestBody, '$schema'> | null, ignoreDiscriminator = false): any {
    if (value == null) {
        return value;
    }

    return {
        
        'code': value['code'],
        'methodId': value['methodId'],
    };
}

