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
 * @interface PlatformNotificationResponse
 */
export interface PlatformNotificationResponse {
    /**
     * A URL to the JSON Schema for this object.
     * @type {string}
     * @memberof PlatformNotificationResponse
     */
    readonly $schema?: string;
    /**
     * 
     * @type {string}
     * @memberof PlatformNotificationResponse
     */
    notificationId: string;
    /**
     * 
     * @type {number}
     * @memberof PlatformNotificationResponse
     */
    recipients: number;
    /**
     * 
     * @type {Date}
     * @memberof PlatformNotificationResponse
     */
    scheduledFor?: Date;
    /**
     * 
     * @type {Date}
     * @memberof PlatformNotificationResponse
     */
    sentAt?: Date;
    /**
     * 
     * @type {string}
     * @memberof PlatformNotificationResponse
     */
    status: string;
}

/**
 * Check if a given object implements the PlatformNotificationResponse interface.
 */
export function instanceOfPlatformNotificationResponse(value: object): value is PlatformNotificationResponse {
    if (!('notificationId' in value) || value['notificationId'] === undefined) return false;
    if (!('recipients' in value) || value['recipients'] === undefined) return false;
    if (!('status' in value) || value['status'] === undefined) return false;
    return true;
}

export function PlatformNotificationResponseFromJSON(json: any): PlatformNotificationResponse {
    return PlatformNotificationResponseFromJSONTyped(json, false);
}

export function PlatformNotificationResponseFromJSONTyped(json: any, ignoreDiscriminator: boolean): PlatformNotificationResponse {
    if (json == null) {
        return json;
    }
    return {
        
        '$schema': json['$schema'] == null ? undefined : json['$schema'],
        'notificationId': json['notification_id'],
        'recipients': json['recipients'],
        'scheduledFor': json['scheduled_for'] == null ? undefined : (new Date(json['scheduled_for'])),
        'sentAt': json['sent_at'] == null ? undefined : (new Date(json['sent_at'])),
        'status': json['status'],
    };
}

export function PlatformNotificationResponseToJSON(json: any): PlatformNotificationResponse {
    return PlatformNotificationResponseToJSONTyped(json, false);
}

export function PlatformNotificationResponseToJSONTyped(value?: Omit<PlatformNotificationResponse, '$schema'> | null, ignoreDiscriminator = false): any {
    if (value == null) {
        return value;
    }

    return {
        
        'notification_id': value['notificationId'],
        'recipients': value['recipients'],
        'scheduled_for': value['scheduledFor'] == null ? undefined : ((value['scheduledFor']).toISOString()),
        'sent_at': value['sentAt'] == null ? undefined : ((value['sentAt']).toISOString()),
        'status': value['status'],
    };
}

