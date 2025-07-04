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
 * @interface SSSProviderStats
 */
export interface SSSProviderStats {
    /**
     * A URL to the JSON Schema for this object.
     * @type {string}
     * @memberof SSSProviderStats
     */
    readonly $schema?: string;
    /**
     * Auto-provisioned users
     * @type {number}
     * @memberof SSSProviderStats
     */
    autoProvisionedUsers: number;
    /**
     * Average login time in seconds
     * @type {number}
     * @memberof SSSProviderStats
     */
    averageLoginTime: number;
    /**
     * Failed logins
     * @type {number}
     * @memberof SSSProviderStats
     */
    failedLogins: number;
    /**
     * Last usage timestamp
     * @type {Date}
     * @memberof SSSProviderStats
     */
    lastUsed?: Date;
    /**
     * Logins this month
     * @type {number}
     * @memberof SSSProviderStats
     */
    loginsMonth: number;
    /**
     * Logins today
     * @type {number}
     * @memberof SSSProviderStats
     */
    loginsToday: number;
    /**
     * Logins this week
     * @type {number}
     * @memberof SSSProviderStats
     */
    loginsWeek: number;
    /**
     * Provider ID
     * @type {string}
     * @memberof SSSProviderStats
     */
    providerId: string;
    /**
     * Login success rate percentage
     * @type {number}
     * @memberof SSSProviderStats
     */
    successRate: number;
    /**
     * Successful logins
     * @type {number}
     * @memberof SSSProviderStats
     */
    successfulLogins: number;
    /**
     * Total logins
     * @type {number}
     * @memberof SSSProviderStats
     */
    totalLogins: number;
    /**
     * Unique users
     * @type {number}
     * @memberof SSSProviderStats
     */
    uniqueUsers: number;
}

/**
 * Check if a given object implements the SSSProviderStats interface.
 */
export function instanceOfSSSProviderStats(value: object): value is SSSProviderStats {
    if (!('autoProvisionedUsers' in value) || value['autoProvisionedUsers'] === undefined) return false;
    if (!('averageLoginTime' in value) || value['averageLoginTime'] === undefined) return false;
    if (!('failedLogins' in value) || value['failedLogins'] === undefined) return false;
    if (!('loginsMonth' in value) || value['loginsMonth'] === undefined) return false;
    if (!('loginsToday' in value) || value['loginsToday'] === undefined) return false;
    if (!('loginsWeek' in value) || value['loginsWeek'] === undefined) return false;
    if (!('providerId' in value) || value['providerId'] === undefined) return false;
    if (!('successRate' in value) || value['successRate'] === undefined) return false;
    if (!('successfulLogins' in value) || value['successfulLogins'] === undefined) return false;
    if (!('totalLogins' in value) || value['totalLogins'] === undefined) return false;
    if (!('uniqueUsers' in value) || value['uniqueUsers'] === undefined) return false;
    return true;
}

export function SSSProviderStatsFromJSON(json: any): SSSProviderStats {
    return SSSProviderStatsFromJSONTyped(json, false);
}

export function SSSProviderStatsFromJSONTyped(json: any, ignoreDiscriminator: boolean): SSSProviderStats {
    if (json == null) {
        return json;
    }
    return {
        
        '$schema': json['$schema'] == null ? undefined : json['$schema'],
        'autoProvisionedUsers': json['autoProvisionedUsers'],
        'averageLoginTime': json['averageLoginTime'],
        'failedLogins': json['failedLogins'],
        'lastUsed': json['lastUsed'] == null ? undefined : (new Date(json['lastUsed'])),
        'loginsMonth': json['loginsMonth'],
        'loginsToday': json['loginsToday'],
        'loginsWeek': json['loginsWeek'],
        'providerId': json['providerId'],
        'successRate': json['successRate'],
        'successfulLogins': json['successfulLogins'],
        'totalLogins': json['totalLogins'],
        'uniqueUsers': json['uniqueUsers'],
    };
}

export function SSSProviderStatsToJSON(json: any): SSSProviderStats {
    return SSSProviderStatsToJSONTyped(json, false);
}

export function SSSProviderStatsToJSONTyped(value?: Omit<SSSProviderStats, '$schema'> | null, ignoreDiscriminator = false): any {
    if (value == null) {
        return value;
    }

    return {
        
        'autoProvisionedUsers': value['autoProvisionedUsers'],
        'averageLoginTime': value['averageLoginTime'],
        'failedLogins': value['failedLogins'],
        'lastUsed': value['lastUsed'] == null ? undefined : ((value['lastUsed']).toISOString()),
        'loginsMonth': value['loginsMonth'],
        'loginsToday': value['loginsToday'],
        'loginsWeek': value['loginsWeek'],
        'providerId': value['providerId'],
        'successRate': value['successRate'],
        'successfulLogins': value['successfulLogins'],
        'totalLogins': value['totalLogins'],
        'uniqueUsers': value['uniqueUsers'],
    };
}

