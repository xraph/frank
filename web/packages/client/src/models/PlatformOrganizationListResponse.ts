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
import type { PlatformOrganizationSummary } from './PlatformOrganizationSummary';
import {
    PlatformOrganizationSummaryFromJSON,
    PlatformOrganizationSummaryFromJSONTyped,
    PlatformOrganizationSummaryToJSON,
    PlatformOrganizationSummaryToJSONTyped,
} from './PlatformOrganizationSummary';
import type { Pagination } from './Pagination';
import {
    PaginationFromJSON,
    PaginationFromJSONTyped,
    PaginationToJSON,
    PaginationToJSONTyped,
} from './Pagination';
import type { OrganizationSummaryStats } from './OrganizationSummaryStats';
import {
    OrganizationSummaryStatsFromJSON,
    OrganizationSummaryStatsFromJSONTyped,
    OrganizationSummaryStatsToJSON,
    OrganizationSummaryStatsToJSONTyped,
} from './OrganizationSummaryStats';

/**
 * 
 * @export
 * @interface PlatformOrganizationListResponse
 */
export interface PlatformOrganizationListResponse {
    /**
     * A URL to the JSON Schema for this object.
     * @type {string}
     * @memberof PlatformOrganizationListResponse
     */
    readonly $schema?: string;
    /**
     * 
     * @type {Array<PlatformOrganizationSummary>}
     * @memberof PlatformOrganizationListResponse
     */
    data: Array<PlatformOrganizationSummary> | null;
    /**
     * 
     * @type {Pagination}
     * @memberof PlatformOrganizationListResponse
     */
    pagination: Pagination;
    /**
     * 
     * @type {OrganizationSummaryStats}
     * @memberof PlatformOrganizationListResponse
     */
    summary: OrganizationSummaryStats;
}

/**
 * Check if a given object implements the PlatformOrganizationListResponse interface.
 */
export function instanceOfPlatformOrganizationListResponse(value: object): value is PlatformOrganizationListResponse {
    if (!('data' in value) || value['data'] === undefined) return false;
    if (!('pagination' in value) || value['pagination'] === undefined) return false;
    if (!('summary' in value) || value['summary'] === undefined) return false;
    return true;
}

export function PlatformOrganizationListResponseFromJSON(json: any): PlatformOrganizationListResponse {
    return PlatformOrganizationListResponseFromJSONTyped(json, false);
}

export function PlatformOrganizationListResponseFromJSONTyped(json: any, ignoreDiscriminator: boolean): PlatformOrganizationListResponse {
    if (json == null) {
        return json;
    }
    return {
        
        '$schema': json['$schema'] == null ? undefined : json['$schema'],
        'data': (json['data'] == null ? null : (json['data'] as Array<any>).map(PlatformOrganizationSummaryFromJSON)),
        'pagination': PaginationFromJSON(json['pagination']),
        'summary': OrganizationSummaryStatsFromJSON(json['summary']),
    };
}

export function PlatformOrganizationListResponseToJSON(json: any): PlatformOrganizationListResponse {
    return PlatformOrganizationListResponseToJSONTyped(json, false);
}

export function PlatformOrganizationListResponseToJSONTyped(value?: Omit<PlatformOrganizationListResponse, '$schema'> | null, ignoreDiscriminator = false): any {
    if (value == null) {
        return value;
    }

    return {
        
        'data': (value['data'] == null ? null : (value['data'] as Array<any>).map(PlatformOrganizationSummaryToJSON)),
        'pagination': PaginationToJSON(value['pagination']),
        'summary': OrganizationSummaryStatsToJSON(value['summary']),
    };
}

