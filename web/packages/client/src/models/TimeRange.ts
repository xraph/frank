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
 * @interface TimeRange
 */
export interface TimeRange {
    /**
     * End time
     * @type {Date}
     * @memberof TimeRange
     */
    end: Date;
    /**
     * Start time
     * @type {Date}
     * @memberof TimeRange
     */
    start: Date;
}

/**
 * Check if a given object implements the TimeRange interface.
 */
export function instanceOfTimeRange(value: object): value is TimeRange {
    if (!('end' in value) || value['end'] === undefined) return false;
    if (!('start' in value) || value['start'] === undefined) return false;
    return true;
}

export function TimeRangeFromJSON(json: any): TimeRange {
    return TimeRangeFromJSONTyped(json, false);
}

export function TimeRangeFromJSONTyped(json: any, ignoreDiscriminator: boolean): TimeRange {
    if (json == null) {
        return json;
    }
    return {
        
        'end': (new Date(json['end'])),
        'start': (new Date(json['start'])),
    };
}

export function TimeRangeToJSON(json: any): TimeRange {
    return TimeRangeToJSONTyped(json, false);
}

export function TimeRangeToJSONTyped(value?: TimeRange | null, ignoreDiscriminator = false): any {
    if (value == null) {
        return value;
    }

    return {
        
        'end': ((value['end']).toISOString()),
        'start': ((value['start']).toISOString()),
    };
}

