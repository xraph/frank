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
 * @interface FeatureRollout
 */
export interface FeatureRollout {
    /**
     * 
     * @type {Array<string>}
     * @memberof FeatureRollout
     */
    orgIds?: Array<string> | null;
    /**
     * 
     * @type {number}
     * @memberof FeatureRollout
     */
    percentage?: number;
    /**
     * 
     * @type {string}
     * @memberof FeatureRollout
     */
    type: string;
    /**
     * 
     * @type {Array<string>}
     * @memberof FeatureRollout
     */
    userIds?: Array<string> | null;
}

/**
 * Check if a given object implements the FeatureRollout interface.
 */
export function instanceOfFeatureRollout(value: object): value is FeatureRollout {
    if (!('type' in value) || value['type'] === undefined) return false;
    return true;
}

export function FeatureRolloutFromJSON(json: any): FeatureRollout {
    return FeatureRolloutFromJSONTyped(json, false);
}

export function FeatureRolloutFromJSONTyped(json: any, ignoreDiscriminator: boolean): FeatureRollout {
    if (json == null) {
        return json;
    }
    return {
        
        'orgIds': json['org_ids'] == null ? undefined : json['org_ids'],
        'percentage': json['percentage'] == null ? undefined : json['percentage'],
        'type': json['type'],
        'userIds': json['userIds'] == null ? undefined : json['userIds'],
    };
}

export function FeatureRolloutToJSON(json: any): FeatureRollout {
    return FeatureRolloutToJSONTyped(json, false);
}

export function FeatureRolloutToJSONTyped(value?: FeatureRollout | null, ignoreDiscriminator = false): any {
    if (value == null) {
        return value;
    }

    return {
        
        'org_ids': value['orgIds'],
        'percentage': value['percentage'],
        'type': value['type'],
        'userIds': value['userIds'],
    };
}

