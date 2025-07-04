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
import type { SystemAlert } from './SystemAlert';
import {
    SystemAlertFromJSON,
    SystemAlertFromJSONTyped,
    SystemAlertToJSON,
    SystemAlertToJSONTyped,
} from './SystemAlert';
import type { BillingSnapshotOverview } from './BillingSnapshotOverview';
import {
    BillingSnapshotOverviewFromJSON,
    BillingSnapshotOverviewFromJSONTyped,
    BillingSnapshotOverviewToJSON,
    BillingSnapshotOverviewToJSONTyped,
} from './BillingSnapshotOverview';
import type { ResourceUsageOverview } from './ResourceUsageOverview';
import {
    ResourceUsageOverviewFromJSON,
    ResourceUsageOverviewFromJSONTyped,
    ResourceUsageOverviewToJSON,
    ResourceUsageOverviewToJSONTyped,
} from './ResourceUsageOverview';
import type { ServiceStatus } from './ServiceStatus';
import {
    ServiceStatusFromJSON,
    ServiceStatusFromJSONTyped,
    ServiceStatusToJSON,
    ServiceStatusToJSONTyped,
} from './ServiceStatus';

/**
 * 
 * @export
 * @interface PlatformOverview
 */
export interface PlatformOverview {
    /**
     * A URL to the JSON Schema for this object.
     * @type {string}
     * @memberof PlatformOverview
     */
    readonly $schema?: string;
    /**
     * Active organizations (last 30 days)
     * @type {number}
     * @memberof PlatformOverview
     */
    activeOrganizations: number;
    /**
     * Active users (last 30 days)
     * @type {number}
     * @memberof PlatformOverview
     */
    activeUsers: number;
    /**
     * Platform billing overview
     * @type {BillingSnapshotOverview}
     * @memberof PlatformOverview
     */
    billingStatus: BillingSnapshotOverview;
    /**
     * Monthly growth rate percentage
     * @type {number}
     * @memberof PlatformOverview
     */
    monthlyGrowth: number;
    /**
     * Recent system alerts
     * @type {Array<SystemAlert>}
     * @memberof PlatformOverview
     */
    recentAlerts: Array<SystemAlert> | null;
    /**
     * System resource usage overview
     * @type {ResourceUsageOverview}
     * @memberof PlatformOverview
     */
    resourceUsage: ResourceUsageOverview;
    /**
     * Status of core services
     * @type {{ [key: string]: ServiceStatus; }}
     * @memberof PlatformOverview
     */
    serviceStatus: { [key: string]: ServiceStatus; };
    /**
     * Overall system health status
     * @type {string}
     * @memberof PlatformOverview
     */
    systemHealth: string;
    /**
     * Overview generation timestamp
     * @type {Date}
     * @memberof PlatformOverview
     */
    timestamp: Date;
    /**
     * Total number of organizations
     * @type {number}
     * @memberof PlatformOverview
     */
    totalOrganizations: number;
    /**
     * Total active sessions
     * @type {number}
     * @memberof PlatformOverview
     */
    totalSessions: number;
    /**
     * Total number of users across all types
     * @type {number}
     * @memberof PlatformOverview
     */
    totalUsers: number;
}

/**
 * Check if a given object implements the PlatformOverview interface.
 */
export function instanceOfPlatformOverview(value: object): value is PlatformOverview {
    if (!('activeOrganizations' in value) || value['activeOrganizations'] === undefined) return false;
    if (!('activeUsers' in value) || value['activeUsers'] === undefined) return false;
    if (!('billingStatus' in value) || value['billingStatus'] === undefined) return false;
    if (!('monthlyGrowth' in value) || value['monthlyGrowth'] === undefined) return false;
    if (!('recentAlerts' in value) || value['recentAlerts'] === undefined) return false;
    if (!('resourceUsage' in value) || value['resourceUsage'] === undefined) return false;
    if (!('serviceStatus' in value) || value['serviceStatus'] === undefined) return false;
    if (!('systemHealth' in value) || value['systemHealth'] === undefined) return false;
    if (!('timestamp' in value) || value['timestamp'] === undefined) return false;
    if (!('totalOrganizations' in value) || value['totalOrganizations'] === undefined) return false;
    if (!('totalSessions' in value) || value['totalSessions'] === undefined) return false;
    if (!('totalUsers' in value) || value['totalUsers'] === undefined) return false;
    return true;
}

export function PlatformOverviewFromJSON(json: any): PlatformOverview {
    return PlatformOverviewFromJSONTyped(json, false);
}

export function PlatformOverviewFromJSONTyped(json: any, ignoreDiscriminator: boolean): PlatformOverview {
    if (json == null) {
        return json;
    }
    return {
        
        '$schema': json['$schema'] == null ? undefined : json['$schema'],
        'activeOrganizations': json['activeOrganizations'],
        'activeUsers': json['activeUsers'],
        'billingStatus': BillingSnapshotOverviewFromJSON(json['billingStatus']),
        'monthlyGrowth': json['monthlyGrowth'],
        'recentAlerts': (json['recentAlerts'] == null ? null : (json['recentAlerts'] as Array<any>).map(SystemAlertFromJSON)),
        'resourceUsage': ResourceUsageOverviewFromJSON(json['resourceUsage']),
        'serviceStatus': (mapValues(json['serviceStatus'], ServiceStatusFromJSON)),
        'systemHealth': json['systemHealth'],
        'timestamp': (new Date(json['timestamp'])),
        'totalOrganizations': json['totalOrganizations'],
        'totalSessions': json['totalSessions'],
        'totalUsers': json['totalUsers'],
    };
}

export function PlatformOverviewToJSON(json: any): PlatformOverview {
    return PlatformOverviewToJSONTyped(json, false);
}

export function PlatformOverviewToJSONTyped(value?: Omit<PlatformOverview, '$schema'> | null, ignoreDiscriminator = false): any {
    if (value == null) {
        return value;
    }

    return {
        
        'activeOrganizations': value['activeOrganizations'],
        'activeUsers': value['activeUsers'],
        'billingStatus': BillingSnapshotOverviewToJSON(value['billingStatus']),
        'monthlyGrowth': value['monthlyGrowth'],
        'recentAlerts': (value['recentAlerts'] == null ? null : (value['recentAlerts'] as Array<any>).map(SystemAlertToJSON)),
        'resourceUsage': ResourceUsageOverviewToJSON(value['resourceUsage']),
        'serviceStatus': (mapValues(value['serviceStatus'], ServiceStatusToJSON)),
        'systemHealth': value['systemHealth'],
        'timestamp': ((value['timestamp']).toISOString()),
        'totalOrganizations': value['totalOrganizations'],
        'totalSessions': value['totalSessions'],
        'totalUsers': value['totalUsers'],
    };
}

