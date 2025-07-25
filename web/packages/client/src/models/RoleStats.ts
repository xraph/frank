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
 * @interface RoleStats
 */
export interface RoleStats {
    /**
     * A URL to the JSON Schema for this object.
     * @type {string}
     * @memberof RoleStats
     */
    readonly $schema?: string;
    /**
     * 
     * @type {number}
     * @memberof RoleStats
     */
    activeRoles: number;
    /**
     * 
     * @type {number}
     * @memberof RoleStats
     */
    applicationRoles: number;
    /**
     * 
     * @type {number}
     * @memberof RoleStats
     */
    createdThisMonth: number;
    /**
     * 
     * @type {number}
     * @memberof RoleStats
     */
    defaultRoles: number;
    /**
     * 
     * @type {number}
     * @memberof RoleStats
     */
    hierarchyDepth: number;
    /**
     * 
     * @type {number}
     * @memberof RoleStats
     */
    modifiedThisWeek: number;
    /**
     * 
     * @type {number}
     * @memberof RoleStats
     */
    organizationRoles: number;
    /**
     * 
     * @type {{ [key: string]: number; }}
     * @memberof RoleStats
     */
    permissionCount: { [key: string]: number; };
    /**
     * 
     * @type {{ [key: string]: number; }}
     * @memberof RoleStats
     */
    rolesByPriority: { [key: string]: number; };
    /**
     * 
     * @type {{ [key: string]: number; }}
     * @memberof RoleStats
     */
    rolesByUserType: { [key: string]: number; };
    /**
     * 
     * @type {number}
     * @memberof RoleStats
     */
    systemRoles: number;
    /**
     * 
     * @type {number}
     * @memberof RoleStats
     */
    totalRoles: number;
    /**
     * 
     * @type {number}
     * @memberof RoleStats
     */
    unusedRoles: number;
    /**
     * 
     * @type {{ [key: string]: number; }}
     * @memberof RoleStats
     */
    userAssignments: { [key: string]: number; };
}

/**
 * Check if a given object implements the RoleStats interface.
 */
export function instanceOfRoleStats(value: object): value is RoleStats {
    if (!('activeRoles' in value) || value['activeRoles'] === undefined) return false;
    if (!('applicationRoles' in value) || value['applicationRoles'] === undefined) return false;
    if (!('createdThisMonth' in value) || value['createdThisMonth'] === undefined) return false;
    if (!('defaultRoles' in value) || value['defaultRoles'] === undefined) return false;
    if (!('hierarchyDepth' in value) || value['hierarchyDepth'] === undefined) return false;
    if (!('modifiedThisWeek' in value) || value['modifiedThisWeek'] === undefined) return false;
    if (!('organizationRoles' in value) || value['organizationRoles'] === undefined) return false;
    if (!('permissionCount' in value) || value['permissionCount'] === undefined) return false;
    if (!('rolesByPriority' in value) || value['rolesByPriority'] === undefined) return false;
    if (!('rolesByUserType' in value) || value['rolesByUserType'] === undefined) return false;
    if (!('systemRoles' in value) || value['systemRoles'] === undefined) return false;
    if (!('totalRoles' in value) || value['totalRoles'] === undefined) return false;
    if (!('unusedRoles' in value) || value['unusedRoles'] === undefined) return false;
    if (!('userAssignments' in value) || value['userAssignments'] === undefined) return false;
    return true;
}

export function RoleStatsFromJSON(json: any): RoleStats {
    return RoleStatsFromJSONTyped(json, false);
}

export function RoleStatsFromJSONTyped(json: any, ignoreDiscriminator: boolean): RoleStats {
    if (json == null) {
        return json;
    }
    return {
        
        '$schema': json['$schema'] == null ? undefined : json['$schema'],
        'activeRoles': json['activeRoles'],
        'applicationRoles': json['applicationRoles'],
        'createdThisMonth': json['createdThisMonth'],
        'defaultRoles': json['defaultRoles'],
        'hierarchyDepth': json['hierarchyDepth'],
        'modifiedThisWeek': json['modifiedThisWeek'],
        'organizationRoles': json['organizationRoles'],
        'permissionCount': json['permissionCount'],
        'rolesByPriority': json['rolesByPriority'],
        'rolesByUserType': json['rolesByUserType'],
        'systemRoles': json['systemRoles'],
        'totalRoles': json['totalRoles'],
        'unusedRoles': json['unusedRoles'],
        'userAssignments': json['userAssignments'],
    };
}

export function RoleStatsToJSON(json: any): RoleStats {
    return RoleStatsToJSONTyped(json, false);
}

export function RoleStatsToJSONTyped(value?: Omit<RoleStats, '$schema'> | null, ignoreDiscriminator = false): any {
    if (value == null) {
        return value;
    }

    return {
        
        'activeRoles': value['activeRoles'],
        'applicationRoles': value['applicationRoles'],
        'createdThisMonth': value['createdThisMonth'],
        'defaultRoles': value['defaultRoles'],
        'hierarchyDepth': value['hierarchyDepth'],
        'modifiedThisWeek': value['modifiedThisWeek'],
        'organizationRoles': value['organizationRoles'],
        'permissionCount': value['permissionCount'],
        'rolesByPriority': value['rolesByPriority'],
        'rolesByUserType': value['rolesByUserType'],
        'systemRoles': value['systemRoles'],
        'totalRoles': value['totalRoles'],
        'unusedRoles': value['unusedRoles'],
        'userAssignments': value['userAssignments'],
    };
}

