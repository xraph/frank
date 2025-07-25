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
import type { EndpointStats } from './EndpointStats';
import {
    EndpointStatsFromJSON,
    EndpointStatsFromJSONTyped,
    EndpointStatsToJSON,
    EndpointStatsToJSONTyped,
} from './EndpointStats';

/**
 * 
 * @export
 * @interface UsageMetrics
 */
export interface UsageMetrics {
    /**
     * A URL to the JSON Schema for this object.
     * @type {string}
     * @memberof UsageMetrics
     */
    readonly $schema?: string;
    /**
     * 
     * @type {number}
     * @memberof UsageMetrics
     */
    avgResponseTime: number;
    /**
     * 
     * @type {{ [key: string]: number; }}
     * @memberof UsageMetrics
     */
    deviceBreakdown: { [key: string]: number; };
    /**
     * 
     * @type {Date}
     * @memberof UsageMetrics
     */
    endDate: Date;
    /**
     * 
     * @type {number}
     * @memberof UsageMetrics
     */
    errorRate: number;
    /**
     * 
     * @type {Date}
     * @memberof UsageMetrics
     */
    generatedAt: Date;
    /**
     * 
     * @type {{ [key: string]: number; }}
     * @memberof UsageMetrics
     */
    geographicBreakdown: { [key: string]: number; };
    /**
     * 
     * @type {string}
     * @memberof UsageMetrics
     */
    period: string;
    /**
     * 
     * @type {{ [key: string]: number; }}
     * @memberof UsageMetrics
     */
    popularActions: { [key: string]: number; };
    /**
     * 
     * @type {Array<EndpointStats>}
     * @memberof UsageMetrics
     */
    popularEndpoints: Array<EndpointStats> | null;
    /**
     * 
     * @type {{ [key: string]: number; }}
     * @memberof UsageMetrics
     */
    requestsByDay: { [key: string]: number; };
    /**
     * 
     * @type {{ [key: string]: number; }}
     * @memberof UsageMetrics
     */
    responseTimeByDay: { [key: string]: number; };
    /**
     * 
     * @type {Date}
     * @memberof UsageMetrics
     */
    startDate: Date;
    /**
     * 
     * @type {number}
     * @memberof UsageMetrics
     */
    successRate: number;
    /**
     * 
     * @type {number}
     * @memberof UsageMetrics
     */
    totalRequests: number;
    /**
     * 
     * @type {number}
     * @memberof UsageMetrics
     */
    uniqueUsers: number;
    /**
     * 
     * @type {{ [key: string]: number; }}
     * @memberof UsageMetrics
     */
    usersByDay: { [key: string]: number; };
}

/**
 * Check if a given object implements the UsageMetrics interface.
 */
export function instanceOfUsageMetrics(value: object): value is UsageMetrics {
    if (!('avgResponseTime' in value) || value['avgResponseTime'] === undefined) return false;
    if (!('deviceBreakdown' in value) || value['deviceBreakdown'] === undefined) return false;
    if (!('endDate' in value) || value['endDate'] === undefined) return false;
    if (!('errorRate' in value) || value['errorRate'] === undefined) return false;
    if (!('generatedAt' in value) || value['generatedAt'] === undefined) return false;
    if (!('geographicBreakdown' in value) || value['geographicBreakdown'] === undefined) return false;
    if (!('period' in value) || value['period'] === undefined) return false;
    if (!('popularActions' in value) || value['popularActions'] === undefined) return false;
    if (!('popularEndpoints' in value) || value['popularEndpoints'] === undefined) return false;
    if (!('requestsByDay' in value) || value['requestsByDay'] === undefined) return false;
    if (!('responseTimeByDay' in value) || value['responseTimeByDay'] === undefined) return false;
    if (!('startDate' in value) || value['startDate'] === undefined) return false;
    if (!('successRate' in value) || value['successRate'] === undefined) return false;
    if (!('totalRequests' in value) || value['totalRequests'] === undefined) return false;
    if (!('uniqueUsers' in value) || value['uniqueUsers'] === undefined) return false;
    if (!('usersByDay' in value) || value['usersByDay'] === undefined) return false;
    return true;
}

export function UsageMetricsFromJSON(json: any): UsageMetrics {
    return UsageMetricsFromJSONTyped(json, false);
}

export function UsageMetricsFromJSONTyped(json: any, ignoreDiscriminator: boolean): UsageMetrics {
    if (json == null) {
        return json;
    }
    return {
        
        '$schema': json['$schema'] == null ? undefined : json['$schema'],
        'avgResponseTime': json['avgResponseTime'],
        'deviceBreakdown': json['deviceBreakdown'],
        'endDate': (new Date(json['endDate'])),
        'errorRate': json['errorRate'],
        'generatedAt': (new Date(json['generatedAt'])),
        'geographicBreakdown': json['geographicBreakdown'],
        'period': json['period'],
        'popularActions': json['popularActions'],
        'popularEndpoints': (json['popularEndpoints'] == null ? null : (json['popularEndpoints'] as Array<any>).map(EndpointStatsFromJSON)),
        'requestsByDay': json['requestsByDay'],
        'responseTimeByDay': json['responseTimeByDay'],
        'startDate': (new Date(json['startDate'])),
        'successRate': json['successRate'],
        'totalRequests': json['totalRequests'],
        'uniqueUsers': json['uniqueUsers'],
        'usersByDay': json['usersByDay'],
    };
}

export function UsageMetricsToJSON(json: any): UsageMetrics {
    return UsageMetricsToJSONTyped(json, false);
}

export function UsageMetricsToJSONTyped(value?: Omit<UsageMetrics, '$schema'> | null, ignoreDiscriminator = false): any {
    if (value == null) {
        return value;
    }

    return {
        
        'avgResponseTime': value['avgResponseTime'],
        'deviceBreakdown': value['deviceBreakdown'],
        'endDate': ((value['endDate']).toISOString()),
        'errorRate': value['errorRate'],
        'generatedAt': ((value['generatedAt']).toISOString()),
        'geographicBreakdown': value['geographicBreakdown'],
        'period': value['period'],
        'popularActions': value['popularActions'],
        'popularEndpoints': (value['popularEndpoints'] == null ? null : (value['popularEndpoints'] as Array<any>).map(EndpointStatsToJSON)),
        'requestsByDay': value['requestsByDay'],
        'responseTimeByDay': value['responseTimeByDay'],
        'startDate': ((value['startDate']).toISOString()),
        'successRate': value['successRate'],
        'totalRequests': value['totalRequests'],
        'uniqueUsers': value['uniqueUsers'],
        'usersByDay': value['usersByDay'],
    };
}

