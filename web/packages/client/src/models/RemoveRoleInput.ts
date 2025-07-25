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
import type { ContextType } from './ContextType';
import {
    ContextTypeFromJSON,
    ContextTypeFromJSONTyped,
    ContextTypeToJSON,
    ContextTypeToJSONTyped,
} from './ContextType';

/**
 * 
 * @export
 * @interface RemoveRoleInput
 */
export interface RemoveRoleInput {
    /**
     * A URL to the JSON Schema for this object.
     * @type {string}
     * @memberof RemoveRoleInput
     */
    readonly $schema?: string;
    /**
     * 
     * @type {string}
     * @memberof RemoveRoleInput
     */
    contextId?: string;
    /**
     * 
     * @type {ContextType}
     * @memberof RemoveRoleInput
     */
    contextType: ContextType;
    /**
     * 
     * @type {string}
     * @memberof RemoveRoleInput
     */
    roleId: string;
    /**
     * 
     * @type {string}
     * @memberof RemoveRoleInput
     */
    userId: string;
}



/**
 * Check if a given object implements the RemoveRoleInput interface.
 */
export function instanceOfRemoveRoleInput(value: object): value is RemoveRoleInput {
    if (!('contextType' in value) || value['contextType'] === undefined) return false;
    if (!('roleId' in value) || value['roleId'] === undefined) return false;
    if (!('userId' in value) || value['userId'] === undefined) return false;
    return true;
}

export function RemoveRoleInputFromJSON(json: any): RemoveRoleInput {
    return RemoveRoleInputFromJSONTyped(json, false);
}

export function RemoveRoleInputFromJSONTyped(json: any, ignoreDiscriminator: boolean): RemoveRoleInput {
    if (json == null) {
        return json;
    }
    return {
        
        '$schema': json['$schema'] == null ? undefined : json['$schema'],
        'contextId': json['context_id'] == null ? undefined : json['context_id'],
        'contextType': ContextTypeFromJSON(json['context_type']),
        'roleId': json['role_id'],
        'userId': json['user_id'],
    };
}

export function RemoveRoleInputToJSON(json: any): RemoveRoleInput {
    return RemoveRoleInputToJSONTyped(json, false);
}

export function RemoveRoleInputToJSONTyped(value?: Omit<RemoveRoleInput, '$schema'> | null, ignoreDiscriminator = false): any {
    if (value == null) {
        return value;
    }

    return {
        
        'context_id': value['contextId'],
        'context_type': ContextTypeToJSON(value['contextType']),
        'role_id': value['roleId'],
        'user_id': value['userId'],
    };
}

