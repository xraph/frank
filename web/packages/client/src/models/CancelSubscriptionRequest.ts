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
 * @interface CancelSubscriptionRequest
 */
export interface CancelSubscriptionRequest {
    /**
     * A URL to the JSON Schema for this object.
     * @type {string}
     * @memberof CancelSubscriptionRequest
     */
    readonly $schema?: string;
    /**
     * 
     * @type {Date}
     * @memberof CancelSubscriptionRequest
     */
    cancelAt?: Date;
    /**
     * 
     * @type {boolean}
     * @memberof CancelSubscriptionRequest
     */
    notifyUser: boolean;
    /**
     * 
     * @type {boolean}
     * @memberof CancelSubscriptionRequest
     */
    prorate: boolean;
    /**
     * 
     * @type {string}
     * @memberof CancelSubscriptionRequest
     */
    reason: string;
}

/**
 * Check if a given object implements the CancelSubscriptionRequest interface.
 */
export function instanceOfCancelSubscriptionRequest(value: object): value is CancelSubscriptionRequest {
    if (!('notifyUser' in value) || value['notifyUser'] === undefined) return false;
    if (!('prorate' in value) || value['prorate'] === undefined) return false;
    if (!('reason' in value) || value['reason'] === undefined) return false;
    return true;
}

export function CancelSubscriptionRequestFromJSON(json: any): CancelSubscriptionRequest {
    return CancelSubscriptionRequestFromJSONTyped(json, false);
}

export function CancelSubscriptionRequestFromJSONTyped(json: any, ignoreDiscriminator: boolean): CancelSubscriptionRequest {
    if (json == null) {
        return json;
    }
    return {
        
        '$schema': json['$schema'] == null ? undefined : json['$schema'],
        'cancelAt': json['cancel_at'] == null ? undefined : (new Date(json['cancel_at'])),
        'notifyUser': json['notify_user'],
        'prorate': json['prorate'],
        'reason': json['reason'],
    };
}

export function CancelSubscriptionRequestToJSON(json: any): CancelSubscriptionRequest {
    return CancelSubscriptionRequestToJSONTyped(json, false);
}

export function CancelSubscriptionRequestToJSONTyped(value?: Omit<CancelSubscriptionRequest, '$schema'> | null, ignoreDiscriminator = false): any {
    if (value == null) {
        return value;
    }

    return {
        
        'cancel_at': value['cancelAt'] == null ? undefined : ((value['cancelAt']).toISOString()),
        'notify_user': value['notifyUser'],
        'prorate': value['prorate'],
        'reason': value['reason'],
    };
}

