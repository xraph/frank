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
import type { MFAActivity } from './MFAActivity';
import {
    MFAActivityFromJSON,
    MFAActivityFromJSONTyped,
    MFAActivityToJSON,
    MFAActivityToJSONTyped,
} from './MFAActivity';

/**
 * 
 * @export
 * @interface PaginatedOutputMFAActivity
 */
export interface PaginatedOutputMFAActivity {
    /**
     * A URL to the JSON Schema for this object.
     * @type {string}
     * @memberof PaginatedOutputMFAActivity
     */
    readonly $schema?: string;
    /**
     * 
     * @type {Array<MFAActivity>}
     * @memberof PaginatedOutputMFAActivity
     */
    data: Array<MFAActivity> | null;
    /**
     * 
     * @type {Pagination}
     * @memberof PaginatedOutputMFAActivity
     */
    pagination: Pagination;
}

/**
 * Check if a given object implements the PaginatedOutputMFAActivity interface.
 */
export function instanceOfPaginatedOutputMFAActivity(value: object): value is PaginatedOutputMFAActivity {
    if (!('data' in value) || value['data'] === undefined) return false;
    if (!('pagination' in value) || value['pagination'] === undefined) return false;
    return true;
}

export function PaginatedOutputMFAActivityFromJSON(json: any): PaginatedOutputMFAActivity {
    return PaginatedOutputMFAActivityFromJSONTyped(json, false);
}

export function PaginatedOutputMFAActivityFromJSONTyped(json: any, ignoreDiscriminator: boolean): PaginatedOutputMFAActivity {
    if (json == null) {
        return json;
    }
    return {
        
        '$schema': json['$schema'] == null ? undefined : json['$schema'],
        'data': (json['data'] == null ? null : (json['data'] as Array<any>).map(MFAActivityFromJSON)),
        'pagination': PaginationFromJSON(json['pagination']),
    };
}

export function PaginatedOutputMFAActivityToJSON(json: any): PaginatedOutputMFAActivity {
    return PaginatedOutputMFAActivityToJSONTyped(json, false);
}

export function PaginatedOutputMFAActivityToJSONTyped(value?: Omit<PaginatedOutputMFAActivity, '$schema'> | null, ignoreDiscriminator = false): any {
    if (value == null) {
        return value;
    }

    return {
        
        'data': (value['data'] == null ? null : (value['data'] as Array<any>).map(MFAActivityToJSON)),
        'pagination': PaginationToJSON(value['pagination']),
    };
}

