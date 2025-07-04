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
import type { ActionSummary } from './ActionSummary';
import {
    ActionSummaryFromJSON,
    ActionSummaryFromJSONTyped,
    ActionSummaryToJSON,
    ActionSummaryToJSONTyped,
} from './ActionSummary';
import type { UserActivitySummary } from './UserActivitySummary';
import {
    UserActivitySummaryFromJSON,
    UserActivitySummaryFromJSONTyped,
    UserActivitySummaryToJSON,
    UserActivitySummaryToJSONTyped,
} from './UserActivitySummary';

/**
 * 
 * @export
 * @interface OrganizationActivity
 */
export interface OrganizationActivity {
    /**
     * A URL to the JSON Schema for this object.
     * @type {string}
     * @memberof OrganizationActivity
     */
    readonly $schema?: string;
    /**
     * Daily event counts
     * @type {{ [key: string]: number; }}
     * @memberof OrganizationActivity
     */
    eventsByDay: { [key: string]: number; };
    /**
     * Events grouped by type
     * @type {{ [key: string]: number; }}
     * @memberof OrganizationActivity
     */
    eventsByType: { [key: string]: number; };
    /**
     * Report generation time
     * @type {Date}
     * @memberof OrganizationActivity
     */
    generatedAt: Date;
    /**
     * Growth trend (increasing, decreasing, stable)
     * @type {string}
     * @memberof OrganizationActivity
     */
    growthTrend: string;
    /**
     * Activity period
     * @type {string}
     * @memberof OrganizationActivity
     */
    period: string;
    /**
     * Most common actions
     * @type {Array<ActionSummary>}
     * @memberof OrganizationActivity
     */
    topActions: Array<ActionSummary> | null;
    /**
     * Most active users
     * @type {Array<UserActivitySummary>}
     * @memberof OrganizationActivity
     */
    topUsers: Array<UserActivitySummary> | null;
    /**
     * Total events in period
     * @type {number}
     * @memberof OrganizationActivity
     */
    totalEvents: number;
}

/**
 * Check if a given object implements the OrganizationActivity interface.
 */
export function instanceOfOrganizationActivity(value: object): value is OrganizationActivity {
    if (!('eventsByDay' in value) || value['eventsByDay'] === undefined) return false;
    if (!('eventsByType' in value) || value['eventsByType'] === undefined) return false;
    if (!('generatedAt' in value) || value['generatedAt'] === undefined) return false;
    if (!('growthTrend' in value) || value['growthTrend'] === undefined) return false;
    if (!('period' in value) || value['period'] === undefined) return false;
    if (!('topActions' in value) || value['topActions'] === undefined) return false;
    if (!('topUsers' in value) || value['topUsers'] === undefined) return false;
    if (!('totalEvents' in value) || value['totalEvents'] === undefined) return false;
    return true;
}

export function OrganizationActivityFromJSON(json: any): OrganizationActivity {
    return OrganizationActivityFromJSONTyped(json, false);
}

export function OrganizationActivityFromJSONTyped(json: any, ignoreDiscriminator: boolean): OrganizationActivity {
    if (json == null) {
        return json;
    }
    return {
        
        '$schema': json['$schema'] == null ? undefined : json['$schema'],
        'eventsByDay': json['eventsByDay'],
        'eventsByType': json['eventsByType'],
        'generatedAt': (new Date(json['generatedAt'])),
        'growthTrend': json['growthTrend'],
        'period': json['period'],
        'topActions': (json['topActions'] == null ? null : (json['topActions'] as Array<any>).map(ActionSummaryFromJSON)),
        'topUsers': (json['topUsers'] == null ? null : (json['topUsers'] as Array<any>).map(UserActivitySummaryFromJSON)),
        'totalEvents': json['totalEvents'],
    };
}

export function OrganizationActivityToJSON(json: any): OrganizationActivity {
    return OrganizationActivityToJSONTyped(json, false);
}

export function OrganizationActivityToJSONTyped(value?: Omit<OrganizationActivity, '$schema'> | null, ignoreDiscriminator = false): any {
    if (value == null) {
        return value;
    }

    return {
        
        'eventsByDay': value['eventsByDay'],
        'eventsByType': value['eventsByType'],
        'generatedAt': ((value['generatedAt']).toISOString()),
        'growthTrend': value['growthTrend'],
        'period': value['period'],
        'topActions': (value['topActions'] == null ? null : (value['topActions'] as Array<any>).map(ActionSummaryToJSON)),
        'topUsers': (value['topUsers'] == null ? null : (value['topUsers'] as Array<any>).map(UserActivitySummaryToJSON)),
        'totalEvents': value['totalEvents'],
    };
}

