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
import type { Pagination } from './Pagination';
import {
    PaginationFromJSON,
    PaginationFromJSONTyped,
    PaginationToJSON,
    PaginationToJSONTyped,
} from './Pagination';
import type { MemberSummary } from './MemberSummary';
import {
    MemberSummaryFromJSON,
    MemberSummaryFromJSONTyped,
    MemberSummaryToJSON,
    MemberSummaryToJSONTyped,
} from './MemberSummary';

/**
 * 
 * @export
 * @interface PaginatedOutputMemberSummary
 */
export interface PaginatedOutputMemberSummary {
    /**
     * A URL to the JSON Schema for this object.
     * @type {string}
     * @memberof PaginatedOutputMemberSummary
     */
    readonly $schema?: string;
    /**
     * 
     * @type {Array<MemberSummary>}
     * @memberof PaginatedOutputMemberSummary
     */
    data: Array<MemberSummary> | null;
    /**
     * 
     * @type {Pagination}
     * @memberof PaginatedOutputMemberSummary
     */
    pagination: Pagination;
}

/**
 * Check if a given object implements the PaginatedOutputMemberSummary interface.
 */
export function instanceOfPaginatedOutputMemberSummary(value: object): value is PaginatedOutputMemberSummary {
    if (!('data' in value) || value['data'] === undefined) return false;
    if (!('pagination' in value) || value['pagination'] === undefined) return false;
    return true;
}

export function PaginatedOutputMemberSummaryFromJSON(json: any): PaginatedOutputMemberSummary {
    return PaginatedOutputMemberSummaryFromJSONTyped(json, false);
}

export function PaginatedOutputMemberSummaryFromJSONTyped(json: any, ignoreDiscriminator: boolean): PaginatedOutputMemberSummary {
    if (json == null) {
        return json;
    }
    return {
        
        '$schema': json['$schema'] == null ? undefined : json['$schema'],
        'data': (json['data'] == null ? null : (json['data'] as Array<any>).map(MemberSummaryFromJSON)),
        'pagination': PaginationFromJSON(json['pagination']),
    };
}

export function PaginatedOutputMemberSummaryToJSON(json: any): PaginatedOutputMemberSummary {
    return PaginatedOutputMemberSummaryToJSONTyped(json, false);
}

export function PaginatedOutputMemberSummaryToJSONTyped(value?: Omit<PaginatedOutputMemberSummary, '$schema'> | null, ignoreDiscriminator = false): any {
    if (value == null) {
        return value;
    }

    return {
        
        'data': (value['data'] == null ? null : (value['data'] as Array<any>).map(MemberSummaryToJSON)),
        'pagination': PaginationToJSON(value['pagination']),
    };
}

