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
import type { EndpointUsage } from './EndpointUsage';
import {
    EndpointUsageFromJSON,
    EndpointUsageFromJSONTyped,
    EndpointUsageToJSON,
    EndpointUsageToJSONTyped,
} from './EndpointUsage';

/**
 * 
 * @export
 * @interface APIKeyStats
 */
export interface APIKeyStats {
    /**
     * A URL to the JSON Schema for this object.
     * @type {string}
     * @memberof APIKeyStats
     */
    readonly $schema?: string;
    /**
     * Active API keys
     * @type {number}
     * @memberof APIKeyStats
     */
    activeKeys: number;
    /**
     * Average success rate
     * @type {number}
     * @memberof APIKeyStats
     */
    averageSuccessRate: number;
    /**
     * Error rate percentage
     * @type {number}
     * @memberof APIKeyStats
     */
    errorRate: number;
    /**
     * Expired API keys
     * @type {number}
     * @memberof APIKeyStats
     */
    expiredKeys: number;
    /**
     * Keys by environment
     * @type {{ [key: string]: number; }}
     * @memberof APIKeyStats
     */
    keysByEnvironment: { [key: string]: number; };
    /**
     * Keys by type
     * @type {{ [key: string]: number; }}
     * @memberof APIKeyStats
     */
    keysByType: { [key: string]: number; };
    /**
     * Keys created this month
     * @type {number}
     * @memberof APIKeyStats
     */
    keysCreatedMonth: number;
    /**
     * Keys created this week
     * @type {number}
     * @memberof APIKeyStats
     */
    keysCreatedWeek: number;
    /**
     * Requests this month
     * @type {number}
     * @memberof APIKeyStats
     */
    requestsMonth: number;
    /**
     * Requests today
     * @type {number}
     * @memberof APIKeyStats
     */
    requestsToday: number;
    /**
     * Requests this week
     * @type {number}
     * @memberof APIKeyStats
     */
    requestsWeek: number;
    /**
     * Most used endpoints
     * @type {Array<EndpointUsage>}
     * @memberof APIKeyStats
     */
    topEndpoints: Array<EndpointUsage> | null;
    /**
     * Total API keys
     * @type {number}
     * @memberof APIKeyStats
     */
    totalKeys: number;
    /**
     * Total API requests
     * @type {number}
     * @memberof APIKeyStats
     */
    totalRequests: number;
    /**
     * Unique users with API keys
     * @type {number}
     * @memberof APIKeyStats
     */
    uniqueUsers: number;
}

/**
 * Check if a given object implements the APIKeyStats interface.
 */
export function instanceOfAPIKeyStats(value: object): value is APIKeyStats {
    if (!('activeKeys' in value) || value['activeKeys'] === undefined) return false;
    if (!('averageSuccessRate' in value) || value['averageSuccessRate'] === undefined) return false;
    if (!('errorRate' in value) || value['errorRate'] === undefined) return false;
    if (!('expiredKeys' in value) || value['expiredKeys'] === undefined) return false;
    if (!('keysByEnvironment' in value) || value['keysByEnvironment'] === undefined) return false;
    if (!('keysByType' in value) || value['keysByType'] === undefined) return false;
    if (!('keysCreatedMonth' in value) || value['keysCreatedMonth'] === undefined) return false;
    if (!('keysCreatedWeek' in value) || value['keysCreatedWeek'] === undefined) return false;
    if (!('requestsMonth' in value) || value['requestsMonth'] === undefined) return false;
    if (!('requestsToday' in value) || value['requestsToday'] === undefined) return false;
    if (!('requestsWeek' in value) || value['requestsWeek'] === undefined) return false;
    if (!('topEndpoints' in value) || value['topEndpoints'] === undefined) return false;
    if (!('totalKeys' in value) || value['totalKeys'] === undefined) return false;
    if (!('totalRequests' in value) || value['totalRequests'] === undefined) return false;
    if (!('uniqueUsers' in value) || value['uniqueUsers'] === undefined) return false;
    return true;
}

export function APIKeyStatsFromJSON(json: any): APIKeyStats {
    return APIKeyStatsFromJSONTyped(json, false);
}

export function APIKeyStatsFromJSONTyped(json: any, ignoreDiscriminator: boolean): APIKeyStats {
    if (json == null) {
        return json;
    }
    return {
        
        '$schema': json['$schema'] == null ? undefined : json['$schema'],
        'activeKeys': json['activeKeys'],
        'averageSuccessRate': json['averageSuccessRate'],
        'errorRate': json['errorRate'],
        'expiredKeys': json['expiredKeys'],
        'keysByEnvironment': json['keysByEnvironment'],
        'keysByType': json['keysByType'],
        'keysCreatedMonth': json['keysCreatedMonth'],
        'keysCreatedWeek': json['keysCreatedWeek'],
        'requestsMonth': json['requestsMonth'],
        'requestsToday': json['requestsToday'],
        'requestsWeek': json['requestsWeek'],
        'topEndpoints': (json['topEndpoints'] == null ? null : (json['topEndpoints'] as Array<any>).map(EndpointUsageFromJSON)),
        'totalKeys': json['totalKeys'],
        'totalRequests': json['totalRequests'],
        'uniqueUsers': json['uniqueUsers'],
    };
}

export function APIKeyStatsToJSON(json: any): APIKeyStats {
    return APIKeyStatsToJSONTyped(json, false);
}

export function APIKeyStatsToJSONTyped(value?: Omit<APIKeyStats, '$schema'> | null, ignoreDiscriminator = false): any {
    if (value == null) {
        return value;
    }

    return {
        
        'activeKeys': value['activeKeys'],
        'averageSuccessRate': value['averageSuccessRate'],
        'errorRate': value['errorRate'],
        'expiredKeys': value['expiredKeys'],
        'keysByEnvironment': value['keysByEnvironment'],
        'keysByType': value['keysByType'],
        'keysCreatedMonth': value['keysCreatedMonth'],
        'keysCreatedWeek': value['keysCreatedWeek'],
        'requestsMonth': value['requestsMonth'],
        'requestsToday': value['requestsToday'],
        'requestsWeek': value['requestsWeek'],
        'topEndpoints': (value['topEndpoints'] == null ? null : (value['topEndpoints'] as Array<any>).map(EndpointUsageToJSON)),
        'totalKeys': value['totalKeys'],
        'totalRequests': value['totalRequests'],
        'uniqueUsers': value['uniqueUsers'],
    };
}

