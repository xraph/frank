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
 * @interface MFAActivity
 */
export interface MFAActivity {
    [key: string]: any | any;
    /**
     * Action type (setup, verify, disable)
     * @type {string}
     * @memberof MFAActivity
     */
    action: string;
    /**
     * Whether backup code was used
     * @type {boolean}
     * @memberof MFAActivity
     */
    backupUsed: boolean;
    /**
     * Additional activity details
     * @type {object}
     * @memberof MFAActivity
     */
    details?: object;
    /**
     * Error message if failed
     * @type {string}
     * @memberof MFAActivity
     */
    error?: string;
    /**
     * Activity ID
     * @type {string}
     * @memberof MFAActivity
     */
    id: string;
    /**
     * IP address
     * @type {string}
     * @memberof MFAActivity
     */
    ipAddress?: string;
    /**
     * Location
     * @type {string}
     * @memberof MFAActivity
     */
    location?: string;
    /**
     * MFA method type
     * @type {string}
     * @memberof MFAActivity
     */
    method: string;
    /**
     * MFA method ID
     * @type {string}
     * @memberof MFAActivity
     */
    methodId?: string;
    /**
     * Whether action was successful
     * @type {boolean}
     * @memberof MFAActivity
     */
    success: boolean;
    /**
     * Activity timestamp
     * @type {Date}
     * @memberof MFAActivity
     */
    timestamp: Date;
    /**
     * User agent
     * @type {string}
     * @memberof MFAActivity
     */
    userAgent?: string;
    /**
     * User ID
     * @type {string}
     * @memberof MFAActivity
     */
    userId: string;
}

/**
 * Check if a given object implements the MFAActivity interface.
 */
export function instanceOfMFAActivity(value: object): value is MFAActivity {
    if (!('action' in value) || value['action'] === undefined) return false;
    if (!('backupUsed' in value) || value['backupUsed'] === undefined) return false;
    if (!('id' in value) || value['id'] === undefined) return false;
    if (!('method' in value) || value['method'] === undefined) return false;
    if (!('success' in value) || value['success'] === undefined) return false;
    if (!('timestamp' in value) || value['timestamp'] === undefined) return false;
    if (!('userId' in value) || value['userId'] === undefined) return false;
    return true;
}

export function MFAActivityFromJSON(json: any): MFAActivity {
    return MFAActivityFromJSONTyped(json, false);
}

export function MFAActivityFromJSONTyped(json: any, ignoreDiscriminator: boolean): MFAActivity {
    if (json == null) {
        return json;
    }
    return {
        
            ...json,
        'action': json['action'],
        'backupUsed': json['backupUsed'],
        'details': json['details'] == null ? undefined : json['details'],
        'error': json['error'] == null ? undefined : json['error'],
        'id': json['id'],
        'ipAddress': json['ipAddress'] == null ? undefined : json['ipAddress'],
        'location': json['location'] == null ? undefined : json['location'],
        'method': json['method'],
        'methodId': json['methodId'] == null ? undefined : json['methodId'],
        'success': json['success'],
        'timestamp': (new Date(json['timestamp'])),
        'userAgent': json['userAgent'] == null ? undefined : json['userAgent'],
        'userId': json['userId'],
    };
}

export function MFAActivityToJSON(json: any): MFAActivity {
    return MFAActivityToJSONTyped(json, false);
}

export function MFAActivityToJSONTyped(value?: MFAActivity | null, ignoreDiscriminator = false): any {
    if (value == null) {
        return value;
    }

    return {
        
            ...value,
        'action': value['action'],
        'backupUsed': value['backupUsed'],
        'details': value['details'],
        'error': value['error'],
        'id': value['id'],
        'ipAddress': value['ipAddress'],
        'location': value['location'],
        'method': value['method'],
        'methodId': value['methodId'],
        'success': value['success'],
        'timestamp': ((value['timestamp']).toISOString()),
        'userAgent': value['userAgent'],
        'userId': value['userId'],
    };
}

