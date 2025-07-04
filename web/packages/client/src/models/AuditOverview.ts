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
 * @interface AuditOverview
 */
export interface AuditOverview {
    /**
     * 
     * @type {number}
     * @memberof AuditOverview
     */
    changePercent: number;
    /**
     * 
     * @type {number}
     * @memberof AuditOverview
     */
    failureRatePercent: number;
    /**
     * 
     * @type {number}
     * @memberof AuditOverview
     */
    highRiskEvents: number;
    /**
     * 
     * @type {number}
     * @memberof AuditOverview
     */
    totalEvents: number;
    /**
     * 
     * @type {number}
     * @memberof AuditOverview
     */
    uniqueUsers: number;
}

/**
 * Check if a given object implements the AuditOverview interface.
 */
export function instanceOfAuditOverview(value: object): value is AuditOverview {
    if (!('changePercent' in value) || value['changePercent'] === undefined) return false;
    if (!('failureRatePercent' in value) || value['failureRatePercent'] === undefined) return false;
    if (!('highRiskEvents' in value) || value['highRiskEvents'] === undefined) return false;
    if (!('totalEvents' in value) || value['totalEvents'] === undefined) return false;
    if (!('uniqueUsers' in value) || value['uniqueUsers'] === undefined) return false;
    return true;
}

export function AuditOverviewFromJSON(json: any): AuditOverview {
    return AuditOverviewFromJSONTyped(json, false);
}

export function AuditOverviewFromJSONTyped(json: any, ignoreDiscriminator: boolean): AuditOverview {
    if (json == null) {
        return json;
    }
    return {
        
        'changePercent': json['change_percent'],
        'failureRatePercent': json['failure_rate_percent'],
        'highRiskEvents': json['high_risk_events'],
        'totalEvents': json['total_events'],
        'uniqueUsers': json['unique_users'],
    };
}

export function AuditOverviewToJSON(json: any): AuditOverview {
    return AuditOverviewToJSONTyped(json, false);
}

export function AuditOverviewToJSONTyped(value?: AuditOverview | null, ignoreDiscriminator = false): any {
    if (value == null) {
        return value;
    }

    return {
        
        'change_percent': value['changePercent'],
        'failure_rate_percent': value['failureRatePercent'],
        'high_risk_events': value['highRiskEvents'],
        'total_events': value['totalEvents'],
        'unique_users': value['uniqueUsers'],
    };
}

