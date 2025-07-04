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
 * @interface RevokeUserSessionsRequest
 */
export interface RevokeUserSessionsRequest {
    /**
     * A URL to the JSON Schema for this object.
     * @type {string}
     * @memberof RevokeUserSessionsRequest
     */
    readonly $schema?: string;
    /**
     * 
     * @type {boolean}
     * @memberof RevokeUserSessionsRequest
     */
    notifyUser: boolean;
    /**
     * 
     * @type {string}
     * @memberof RevokeUserSessionsRequest
     */
    reason: string;
}

/**
 * Check if a given object implements the RevokeUserSessionsRequest interface.
 */
export function instanceOfRevokeUserSessionsRequest(value: object): value is RevokeUserSessionsRequest {
    if (!('notifyUser' in value) || value['notifyUser'] === undefined) return false;
    if (!('reason' in value) || value['reason'] === undefined) return false;
    return true;
}

export function RevokeUserSessionsRequestFromJSON(json: any): RevokeUserSessionsRequest {
    return RevokeUserSessionsRequestFromJSONTyped(json, false);
}

export function RevokeUserSessionsRequestFromJSONTyped(json: any, ignoreDiscriminator: boolean): RevokeUserSessionsRequest {
    if (json == null) {
        return json;
    }
    return {
        
        '$schema': json['$schema'] == null ? undefined : json['$schema'],
        'notifyUser': json['notify_user'],
        'reason': json['reason'],
    };
}

export function RevokeUserSessionsRequestToJSON(json: any): RevokeUserSessionsRequest {
    return RevokeUserSessionsRequestToJSONTyped(json, false);
}

export function RevokeUserSessionsRequestToJSONTyped(value?: Omit<RevokeUserSessionsRequest, '$schema'> | null, ignoreDiscriminator = false): any {
    if (value == null) {
        return value;
    }

    return {
        
        'notify_user': value['notifyUser'],
        'reason': value['reason'],
    };
}

