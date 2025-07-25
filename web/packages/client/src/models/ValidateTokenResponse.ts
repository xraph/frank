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
 * @interface ValidateTokenResponse
 */
export interface ValidateTokenResponse {
    [key: string]: any | any;
    /**
     * A URL to the JSON Schema for this object.
     * @type {string}
     * @memberof ValidateTokenResponse
     */
    readonly $schema?: string;
    /**
     * Response message
     * @type {string}
     * @memberof ValidateTokenResponse
     */
    message: string;
    /**
     * Whether token is valid
     * @type {boolean}
     * @memberof ValidateTokenResponse
     */
    valid: boolean;
}

/**
 * Check if a given object implements the ValidateTokenResponse interface.
 */
export function instanceOfValidateTokenResponse(value: object): value is ValidateTokenResponse {
    if (!('message' in value) || value['message'] === undefined) return false;
    if (!('valid' in value) || value['valid'] === undefined) return false;
    return true;
}

export function ValidateTokenResponseFromJSON(json: any): ValidateTokenResponse {
    return ValidateTokenResponseFromJSONTyped(json, false);
}

export function ValidateTokenResponseFromJSONTyped(json: any, ignoreDiscriminator: boolean): ValidateTokenResponse {
    if (json == null) {
        return json;
    }
    return {
        
            ...json,
        '$schema': json['$schema'] == null ? undefined : json['$schema'],
        'message': json['message'],
        'valid': json['valid'],
    };
}

export function ValidateTokenResponseToJSON(json: any): ValidateTokenResponse {
    return ValidateTokenResponseToJSONTyped(json, false);
}

export function ValidateTokenResponseToJSONTyped(value?: Omit<ValidateTokenResponse, '$schema'> | null, ignoreDiscriminator = false): any {
    if (value == null) {
        return value;
    }

    return {
        
            ...value,
        'message': value['message'],
        'valid': value['valid'],
    };
}

