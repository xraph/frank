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
 * @interface UpdateMemberRoleInputBody
 */
export interface UpdateMemberRoleInputBody {
    /**
     * A URL to the JSON Schema for this object.
     * @type {string}
     * @memberof UpdateMemberRoleInputBody
     */
    readonly $schema?: string;
    /**
     * Reason for role change
     * @type {string}
     * @memberof UpdateMemberRoleInputBody
     */
    reason?: string;
    /**
     * New role ID
     * @type {string}
     * @memberof UpdateMemberRoleInputBody
     */
    roleId: string;
}

/**
 * Check if a given object implements the UpdateMemberRoleInputBody interface.
 */
export function instanceOfUpdateMemberRoleInputBody(value: object): value is UpdateMemberRoleInputBody {
    if (!('roleId' in value) || value['roleId'] === undefined) return false;
    return true;
}

export function UpdateMemberRoleInputBodyFromJSON(json: any): UpdateMemberRoleInputBody {
    return UpdateMemberRoleInputBodyFromJSONTyped(json, false);
}

export function UpdateMemberRoleInputBodyFromJSONTyped(json: any, ignoreDiscriminator: boolean): UpdateMemberRoleInputBody {
    if (json == null) {
        return json;
    }
    return {
        
        '$schema': json['$schema'] == null ? undefined : json['$schema'],
        'reason': json['reason'] == null ? undefined : json['reason'],
        'roleId': json['roleId'],
    };
}

export function UpdateMemberRoleInputBodyToJSON(json: any): UpdateMemberRoleInputBody {
    return UpdateMemberRoleInputBodyToJSONTyped(json, false);
}

export function UpdateMemberRoleInputBodyToJSONTyped(value?: Omit<UpdateMemberRoleInputBody, '$schema'> | null, ignoreDiscriminator = false): any {
    if (value == null) {
        return value;
    }

    return {
        
        'reason': value['reason'],
        'roleId': value['roleId'],
    };
}

