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
 * @interface ResolveViolationRequest
 */
export interface ResolveViolationRequest {
    /**
     * A URL to the JSON Schema for this object.
     * @type {string}
     * @memberof ResolveViolationRequest
     */
    readonly $schema?: string;
    /**
     * Resolution description
     * @type {string}
     * @memberof ResolveViolationRequest
     */
    resolution: string;
}

/**
 * Check if a given object implements the ResolveViolationRequest interface.
 */
export function instanceOfResolveViolationRequest(value: object): value is ResolveViolationRequest {
    if (!('resolution' in value) || value['resolution'] === undefined) return false;
    return true;
}

export function ResolveViolationRequestFromJSON(json: any): ResolveViolationRequest {
    return ResolveViolationRequestFromJSONTyped(json, false);
}

export function ResolveViolationRequestFromJSONTyped(json: any, ignoreDiscriminator: boolean): ResolveViolationRequest {
    if (json == null) {
        return json;
    }
    return {
        
        '$schema': json['$schema'] == null ? undefined : json['$schema'],
        'resolution': json['resolution'],
    };
}

export function ResolveViolationRequestToJSON(json: any): ResolveViolationRequest {
    return ResolveViolationRequestToJSONTyped(json, false);
}

export function ResolveViolationRequestToJSONTyped(value?: Omit<ResolveViolationRequest, '$schema'> | null, ignoreDiscriminator = false): any {
    if (value == null) {
        return value;
    }

    return {
        
        'resolution': value['resolution'],
    };
}

