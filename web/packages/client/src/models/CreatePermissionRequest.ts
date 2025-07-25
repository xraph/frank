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
import type { PermissionCategory } from './PermissionCategory';
import {
    PermissionCategoryFromJSON,
    PermissionCategoryFromJSONTyped,
    PermissionCategoryToJSON,
    PermissionCategoryToJSONTyped,
} from './PermissionCategory';
import type { UserType } from './UserType';
import {
    UserTypeFromJSON,
    UserTypeFromJSONTyped,
    UserTypeToJSON,
    UserTypeToJSONTyped,
} from './UserType';

/**
 * 
 * @export
 * @interface CreatePermissionRequest
 */
export interface CreatePermissionRequest {
    /**
     * A URL to the JSON Schema for this object.
     * @type {string}
     * @memberof CreatePermissionRequest
     */
    readonly $schema?: string;
    /**
     * Action name
     * @type {string}
     * @memberof CreatePermissionRequest
     */
    action: string;
    /**
     * Applicable contexts
     * @type {Array<ContextType>}
     * @memberof CreatePermissionRequest
     */
    applicableContexts: Array<ContextType> | null;
    /**
     * Applicable user types
     * @type {Array<UserType>}
     * @memberof CreatePermissionRequest
     */
    applicableUserTypes: Array<UserType> | null;
    /**
     * Permission category
     * @type {PermissionCategory}
     * @memberof CreatePermissionRequest
     */
    category: PermissionCategory;
    /**
     * Conditional rules
     * @type {string}
     * @memberof CreatePermissionRequest
     */
    conditions?: string;
    /**
     * 
     * @type {string}
     * @memberof CreatePermissionRequest
     */
    createdBy?: string;
    /**
     * Whether permission is dangerous
     * @type {boolean}
     * @memberof CreatePermissionRequest
     */
    dangerous: boolean;
    /**
     * Permission description
     * @type {string}
     * @memberof CreatePermissionRequest
     */
    description: string;
    /**
     * Display name
     * @type {string}
     * @memberof CreatePermissionRequest
     */
    displayName?: string;
    /**
     * Permission identifier
     * @type {string}
     * @memberof CreatePermissionRequest
     */
    name: string;
    /**
     * Permission group
     * @type {string}
     * @memberof CreatePermissionRequest
     */
    permissionGroup?: string;
    /**
     * Resource name
     * @type {string}
     * @memberof CreatePermissionRequest
     */
    resource: string;
    /**
     * Risk level (1-5)
     * @type {number}
     * @memberof CreatePermissionRequest
     */
    riskLevel: number;
    /**
     * 
     * @type {boolean}
     * @memberof CreatePermissionRequest
     */
    system: boolean;
}



/**
 * Check if a given object implements the CreatePermissionRequest interface.
 */
export function instanceOfCreatePermissionRequest(value: object): value is CreatePermissionRequest {
    if (!('action' in value) || value['action'] === undefined) return false;
    if (!('applicableContexts' in value) || value['applicableContexts'] === undefined) return false;
    if (!('applicableUserTypes' in value) || value['applicableUserTypes'] === undefined) return false;
    if (!('category' in value) || value['category'] === undefined) return false;
    if (!('dangerous' in value) || value['dangerous'] === undefined) return false;
    if (!('description' in value) || value['description'] === undefined) return false;
    if (!('name' in value) || value['name'] === undefined) return false;
    if (!('resource' in value) || value['resource'] === undefined) return false;
    if (!('riskLevel' in value) || value['riskLevel'] === undefined) return false;
    if (!('system' in value) || value['system'] === undefined) return false;
    return true;
}

export function CreatePermissionRequestFromJSON(json: any): CreatePermissionRequest {
    return CreatePermissionRequestFromJSONTyped(json, false);
}

export function CreatePermissionRequestFromJSONTyped(json: any, ignoreDiscriminator: boolean): CreatePermissionRequest {
    if (json == null) {
        return json;
    }
    return {
        
        '$schema': json['$schema'] == null ? undefined : json['$schema'],
        'action': json['action'],
        'applicableContexts': (json['applicableContexts'] == null ? null : (json['applicableContexts'] as Array<any>).map(ContextTypeFromJSON)),
        'applicableUserTypes': (json['applicableUserTypes'] == null ? null : (json['applicableUserTypes'] as Array<any>).map(UserTypeFromJSON)),
        'category': PermissionCategoryFromJSON(json['category']),
        'conditions': json['conditions'] == null ? undefined : json['conditions'],
        'createdBy': json['createdBy'] == null ? undefined : json['createdBy'],
        'dangerous': json['dangerous'],
        'description': json['description'],
        'displayName': json['displayName'] == null ? undefined : json['displayName'],
        'name': json['name'],
        'permissionGroup': json['permissionGroup'] == null ? undefined : json['permissionGroup'],
        'resource': json['resource'],
        'riskLevel': json['riskLevel'],
        'system': json['system'],
    };
}

export function CreatePermissionRequestToJSON(json: any): CreatePermissionRequest {
    return CreatePermissionRequestToJSONTyped(json, false);
}

export function CreatePermissionRequestToJSONTyped(value?: Omit<CreatePermissionRequest, '$schema'> | null, ignoreDiscriminator = false): any {
    if (value == null) {
        return value;
    }

    return {
        
        'action': value['action'],
        'applicableContexts': (value['applicableContexts'] == null ? null : (value['applicableContexts'] as Array<any>).map(ContextTypeToJSON)),
        'applicableUserTypes': (value['applicableUserTypes'] == null ? null : (value['applicableUserTypes'] as Array<any>).map(UserTypeToJSON)),
        'category': PermissionCategoryToJSON(value['category']),
        'conditions': value['conditions'],
        'createdBy': value['createdBy'],
        'dangerous': value['dangerous'],
        'description': value['description'],
        'displayName': value['displayName'],
        'name': value['name'],
        'permissionGroup': value['permissionGroup'],
        'resource': value['resource'],
        'riskLevel': value['riskLevel'],
        'system': value['system'],
    };
}

