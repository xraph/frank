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
 * @interface ModelError
 */
export interface ModelError {
    [key: string]: any | any;
    /**
     * A URL to the JSON Schema for this object.
     * @type {string}
     * @memberof ModelError
     */
    readonly $schema?: string;
    /**
     * 
     * @type {string}
     * @memberof ModelError
     */
    code: string;
    /**
     * 
     * @type {Array<string>}
     * @memberof ModelError
     */
    details?: Array<string> | null;
    /**
     * 
     * @type {any}
     * @memberof ModelError
     */
    error?: any | null;
    /**
     * 
     * @type {string}
     * @memberof ModelError
     */
    id?: string;
    /**
     * 
     * @type {string}
     * @memberof ModelError
     */
    message: string;
    /**
     * 
     * @type {object}
     * @memberof ModelError
     */
    metadata: object;
    /**
     * 
     * @type {number}
     * @memberof ModelError
     */
    statusCode: number;
}

/**
 * Check if a given object implements the ModelError interface.
 */
export function instanceOfModelError(value: object): value is ModelError {
    if (!('code' in value) || value['code'] === undefined) return false;
    if (!('message' in value) || value['message'] === undefined) return false;
    if (!('metadata' in value) || value['metadata'] === undefined) return false;
    if (!('statusCode' in value) || value['statusCode'] === undefined) return false;
    return true;
}

export function ModelErrorFromJSON(json: any): ModelError {
    return ModelErrorFromJSONTyped(json, false);
}

export function ModelErrorFromJSONTyped(json: any, ignoreDiscriminator: boolean): ModelError {
    if (json == null) {
        return json;
    }
    return {
        
            ...json,
        '$schema': json['$schema'] == null ? undefined : json['$schema'],
        'code': json['code'],
        'details': json['details'] == null ? undefined : json['details'],
        'error': json['error'] == null ? undefined : json['error'],
        'id': json['id'] == null ? undefined : json['id'],
        'message': json['message'],
        'metadata': json['metadata'],
        'statusCode': json['status_code'],
    };
}

export function ModelErrorToJSON(json: any): ModelError {
    return ModelErrorToJSONTyped(json, false);
}

export function ModelErrorToJSONTyped(value?: Omit<ModelError, '$schema'> | null, ignoreDiscriminator = false): any {
    if (value == null) {
        return value;
    }

    return {
        
            ...value,
        'code': value['code'],
        'details': value['details'],
        'error': value['error'],
        'id': value['id'],
        'message': value['message'],
        'metadata': value['metadata'],
        'status_code': value['statusCode'],
    };
}

