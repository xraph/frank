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
 * @interface SyncRolePermissionsRequest
 */
export interface SyncRolePermissionsRequest {
    /**
     * A URL to the JSON Schema for this object.
     * @type {string}
     * @memberof SyncRolePermissionsRequest
     */
    readonly $schema?: string;
    /**
     * Permission IDs to sync
     * @type {Array<string>}
     * @memberof SyncRolePermissionsRequest
     */
    permissionIds: Array<string> | null;
}

/**
 * Check if a given object implements the SyncRolePermissionsRequest interface.
 */
export function instanceOfSyncRolePermissionsRequest(value: object): value is SyncRolePermissionsRequest {
    if (!('permissionIds' in value) || value['permissionIds'] === undefined) return false;
    return true;
}

export function SyncRolePermissionsRequestFromJSON(json: any): SyncRolePermissionsRequest {
    return SyncRolePermissionsRequestFromJSONTyped(json, false);
}

export function SyncRolePermissionsRequestFromJSONTyped(json: any, ignoreDiscriminator: boolean): SyncRolePermissionsRequest {
    if (json == null) {
        return json;
    }
    return {
        
        '$schema': json['$schema'] == null ? undefined : json['$schema'],
        'permissionIds': json['permissionIds'] == null ? null : json['permissionIds'],
    };
}

export function SyncRolePermissionsRequestToJSON(json: any): SyncRolePermissionsRequest {
    return SyncRolePermissionsRequestToJSONTyped(json, false);
}

export function SyncRolePermissionsRequestToJSONTyped(value?: Omit<SyncRolePermissionsRequest, '$schema'> | null, ignoreDiscriminator = false): any {
    if (value == null) {
        return value;
    }

    return {
        
        'permissionIds': value['permissionIds'],
    };
}

