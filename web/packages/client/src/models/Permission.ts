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
import type { RoleSummary } from './RoleSummary';
import {
    RoleSummaryFromJSON,
    RoleSummaryFromJSONTyped,
    RoleSummaryToJSON,
    RoleSummaryToJSONTyped,
} from './RoleSummary';
import type { PermissionDependency } from './PermissionDependency';
import {
    PermissionDependencyFromJSON,
    PermissionDependencyFromJSONTyped,
    PermissionDependencyToJSON,
    PermissionDependencyToJSONTyped,
} from './PermissionDependency';

/**
 * 
 * @export
 * @interface Permission
 */
export interface Permission {
    /**
     * A URL to the JSON Schema for this object.
     * @type {string}
     * @memberof Permission
     */
    readonly $schema?: string;
    /**
     * Action this permission allows
     * @type {string}
     * @memberof Permission
     */
    action: string;
    /**
     * Whether permission is active
     * @type {boolean}
     * @memberof Permission
     */
    active: boolean;
    /**
     * Contexts where permission is valid
     * @type {Array<ContextType>}
     * @memberof Permission
     */
    applicableContexts: Array<ContextType> | null;
    /**
     * User types this permission applies to
     * @type {Array<UserType>}
     * @memberof Permission
     */
    applicableUserTypes: Array<UserType> | null;
    /**
     * Permission category
     * @type {PermissionCategory}
     * @memberof Permission
     */
    category: PermissionCategory;
    /**
     * Conditional access rules
     * @type {string}
     * @memberof Permission
     */
    conditions?: string;
    /**
     * 
     * @type {Date}
     * @memberof Permission
     */
    createdAt: Date;
    /**
     * 
     * @type {string}
     * @memberof Permission
     */
    createdBy: string;
    /**
     * Whether permission is dangerous
     * @type {boolean}
     * @memberof Permission
     */
    dangerous: boolean;
    /**
     * Permission dependencies
     * @type {Array<PermissionDependency>}
     * @memberof Permission
     */
    dependencies?: Array<PermissionDependency> | null;
    /**
     * Permission description
     * @type {string}
     * @memberof Permission
     */
    description: string;
    /**
     * Human-readable permission name
     * @type {string}
     * @memberof Permission
     */
    displayName?: string;
    /**
     * 
     * @type {string}
     * @memberof Permission
     */
    id: string;
    /**
     * Permission identifier
     * @type {string}
     * @memberof Permission
     */
    name: string;
    /**
     * Permission group
     * @type {string}
     * @memberof Permission
     */
    permissionGroup?: string;
    /**
     * Resource this permission applies to
     * @type {string}
     * @memberof Permission
     */
    resource: string;
    /**
     * Risk level (1-5)
     * @type {number}
     * @memberof Permission
     */
    riskLevel: number;
    /**
     * Roles that have this permission
     * @type {Array<RoleSummary>}
     * @memberof Permission
     */
    roles?: Array<RoleSummary> | null;
    /**
     * Whether permission is system-managed
     * @type {boolean}
     * @memberof Permission
     */
    system: boolean;
    /**
     * 
     * @type {Date}
     * @memberof Permission
     */
    updatedAt: Date;
    /**
     * 
     * @type {string}
     * @memberof Permission
     */
    updatedBy: string;
}



/**
 * Check if a given object implements the Permission interface.
 */
export function instanceOfPermission(value: object): value is Permission {
    if (!('action' in value) || value['action'] === undefined) return false;
    if (!('active' in value) || value['active'] === undefined) return false;
    if (!('applicableContexts' in value) || value['applicableContexts'] === undefined) return false;
    if (!('applicableUserTypes' in value) || value['applicableUserTypes'] === undefined) return false;
    if (!('category' in value) || value['category'] === undefined) return false;
    if (!('createdAt' in value) || value['createdAt'] === undefined) return false;
    if (!('createdBy' in value) || value['createdBy'] === undefined) return false;
    if (!('dangerous' in value) || value['dangerous'] === undefined) return false;
    if (!('description' in value) || value['description'] === undefined) return false;
    if (!('id' in value) || value['id'] === undefined) return false;
    if (!('name' in value) || value['name'] === undefined) return false;
    if (!('resource' in value) || value['resource'] === undefined) return false;
    if (!('riskLevel' in value) || value['riskLevel'] === undefined) return false;
    if (!('system' in value) || value['system'] === undefined) return false;
    if (!('updatedAt' in value) || value['updatedAt'] === undefined) return false;
    if (!('updatedBy' in value) || value['updatedBy'] === undefined) return false;
    return true;
}

export function PermissionFromJSON(json: any): Permission {
    return PermissionFromJSONTyped(json, false);
}

export function PermissionFromJSONTyped(json: any, ignoreDiscriminator: boolean): Permission {
    if (json == null) {
        return json;
    }
    return {
        
        '$schema': json['$schema'] == null ? undefined : json['$schema'],
        'action': json['action'],
        'active': json['active'],
        'applicableContexts': (json['applicableContexts'] == null ? null : (json['applicableContexts'] as Array<any>).map(ContextTypeFromJSON)),
        'applicableUserTypes': (json['applicableUserTypes'] == null ? null : (json['applicableUserTypes'] as Array<any>).map(UserTypeFromJSON)),
        'category': PermissionCategoryFromJSON(json['category']),
        'conditions': json['conditions'] == null ? undefined : json['conditions'],
        'createdAt': (new Date(json['createdAt'])),
        'createdBy': json['createdBy'],
        'dangerous': json['dangerous'],
        'dependencies': json['dependencies'] == null ? undefined : ((json['dependencies'] as Array<any>).map(PermissionDependencyFromJSON)),
        'description': json['description'],
        'displayName': json['displayName'] == null ? undefined : json['displayName'],
        'id': json['id'],
        'name': json['name'],
        'permissionGroup': json['permissionGroup'] == null ? undefined : json['permissionGroup'],
        'resource': json['resource'],
        'riskLevel': json['riskLevel'],
        'roles': json['roles'] == null ? undefined : ((json['roles'] as Array<any>).map(RoleSummaryFromJSON)),
        'system': json['system'],
        'updatedAt': (new Date(json['updatedAt'])),
        'updatedBy': json['updatedBy'],
    };
}

export function PermissionToJSON(json: any): Permission {
    return PermissionToJSONTyped(json, false);
}

export function PermissionToJSONTyped(value?: Omit<Permission, '$schema'> | null, ignoreDiscriminator = false): any {
    if (value == null) {
        return value;
    }

    return {
        
        'action': value['action'],
        'active': value['active'],
        'applicableContexts': (value['applicableContexts'] == null ? null : (value['applicableContexts'] as Array<any>).map(ContextTypeToJSON)),
        'applicableUserTypes': (value['applicableUserTypes'] == null ? null : (value['applicableUserTypes'] as Array<any>).map(UserTypeToJSON)),
        'category': PermissionCategoryToJSON(value['category']),
        'conditions': value['conditions'],
        'createdAt': ((value['createdAt']).toISOString()),
        'createdBy': value['createdBy'],
        'dangerous': value['dangerous'],
        'dependencies': value['dependencies'] == null ? undefined : ((value['dependencies'] as Array<any>).map(PermissionDependencyToJSON)),
        'description': value['description'],
        'displayName': value['displayName'],
        'id': value['id'],
        'name': value['name'],
        'permissionGroup': value['permissionGroup'],
        'resource': value['resource'],
        'riskLevel': value['riskLevel'],
        'roles': value['roles'] == null ? undefined : ((value['roles'] as Array<any>).map(RoleSummaryToJSON)),
        'system': value['system'],
        'updatedAt': ((value['updatedAt']).toISOString()),
        'updatedBy': value['updatedBy'],
    };
}

