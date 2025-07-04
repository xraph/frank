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
 * @interface BillingUsage
 */
export interface BillingUsage {
    /**
     * 
     * @type {number}
     * @memberof BillingUsage
     */
    apiRequests: number;
    /**
     * 
     * @type {number}
     * @memberof BillingUsage
     */
    bandwidthUsedBytes: number;
    /**
     * 
     * @type {number}
     * @memberof BillingUsage
     */
    overageCharges: number;
    /**
     * 
     * @type {number}
     * @memberof BillingUsage
     */
    storageUsedBytes: number;
    /**
     * 
     * @type {number}
     * @memberof BillingUsage
     */
    usersProcessed: number;
}

/**
 * Check if a given object implements the BillingUsage interface.
 */
export function instanceOfBillingUsage(value: object): value is BillingUsage {
    if (!('apiRequests' in value) || value['apiRequests'] === undefined) return false;
    if (!('bandwidthUsedBytes' in value) || value['bandwidthUsedBytes'] === undefined) return false;
    if (!('overageCharges' in value) || value['overageCharges'] === undefined) return false;
    if (!('storageUsedBytes' in value) || value['storageUsedBytes'] === undefined) return false;
    if (!('usersProcessed' in value) || value['usersProcessed'] === undefined) return false;
    return true;
}

export function BillingUsageFromJSON(json: any): BillingUsage {
    return BillingUsageFromJSONTyped(json, false);
}

export function BillingUsageFromJSONTyped(json: any, ignoreDiscriminator: boolean): BillingUsage {
    if (json == null) {
        return json;
    }
    return {
        
        'apiRequests': json['api_requests'],
        'bandwidthUsedBytes': json['bandwidth_used_bytes'],
        'overageCharges': json['overage_charges'],
        'storageUsedBytes': json['storage_used_bytes'],
        'usersProcessed': json['users_processed'],
    };
}

export function BillingUsageToJSON(json: any): BillingUsage {
    return BillingUsageToJSONTyped(json, false);
}

export function BillingUsageToJSONTyped(value?: BillingUsage | null, ignoreDiscriminator = false): any {
    if (value == null) {
        return value;
    }

    return {
        
        'api_requests': value['apiRequests'],
        'bandwidth_used_bytes': value['bandwidthUsedBytes'],
        'overage_charges': value['overageCharges'],
        'storage_used_bytes': value['storageUsedBytes'],
        'users_processed': value['usersProcessed'],
    };
}

