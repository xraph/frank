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
 * @interface ResendMFACodeResponse
 */
export interface ResendMFACodeResponse {
    [key: string]: any | any;
    /**
     * A URL to the JSON Schema for this object.
     * @type {string}
     * @memberof ResendMFACodeResponse
     */
    readonly $schema?: string;
    /**
     * Code expiration
     * @type {Date}
     * @memberof ResendMFACodeResponse
     */
    expiresAt: Date;
    /**
     * Response message
     * @type {string}
     * @memberof ResendMFACodeResponse
     */
    message: string;
    /**
     * Whether code was sent
     * @type {boolean}
     * @memberof ResendMFACodeResponse
     */
    success: boolean;
}

/**
 * Check if a given object implements the ResendMFACodeResponse interface.
 */
export function instanceOfResendMFACodeResponse(value: object): value is ResendMFACodeResponse {
    if (!('expiresAt' in value) || value['expiresAt'] === undefined) return false;
    if (!('message' in value) || value['message'] === undefined) return false;
    if (!('success' in value) || value['success'] === undefined) return false;
    return true;
}

export function ResendMFACodeResponseFromJSON(json: any): ResendMFACodeResponse {
    return ResendMFACodeResponseFromJSONTyped(json, false);
}

export function ResendMFACodeResponseFromJSONTyped(json: any, ignoreDiscriminator: boolean): ResendMFACodeResponse {
    if (json == null) {
        return json;
    }
    return {
        
            ...json,
        '$schema': json['$schema'] == null ? undefined : json['$schema'],
        'expiresAt': (new Date(json['expiresAt'])),
        'message': json['message'],
        'success': json['success'],
    };
}

export function ResendMFACodeResponseToJSON(json: any): ResendMFACodeResponse {
    return ResendMFACodeResponseToJSONTyped(json, false);
}

export function ResendMFACodeResponseToJSONTyped(value?: Omit<ResendMFACodeResponse, '$schema'> | null, ignoreDiscriminator = false): any {
    if (value == null) {
        return value;
    }

    return {
        
            ...value,
        'expiresAt': ((value['expiresAt']).toISOString()),
        'message': value['message'],
        'success': value['success'],
    };
}

