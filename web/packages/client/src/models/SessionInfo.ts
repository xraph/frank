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
 * @interface SessionInfo
 */
export interface SessionInfo {
    [key: string]: any | any;
    /**
     * Whether session is active
     * @type {boolean}
     * @memberof SessionInfo
     */
    active: boolean;
    /**
     * Session creation time
     * @type {Date}
     * @memberof SessionInfo
     */
    createdAt: Date;
    /**
     * Device ID
     * @type {string}
     * @memberof SessionInfo
     */
    deviceId?: string;
    /**
     * Device type
     * @type {string}
     * @memberof SessionInfo
     */
    deviceType?: string;
    /**
     * Session expiration time
     * @type {Date}
     * @memberof SessionInfo
     */
    expiresAt: Date;
    /**
     * Session ID
     * @type {string}
     * @memberof SessionInfo
     */
    id: string;
    /**
     * IP address
     * @type {string}
     * @memberof SessionInfo
     */
    ipAddress?: string;
    /**
     * Last activity time
     * @type {Date}
     * @memberof SessionInfo
     */
    lastActiveAt: Date;
    /**
     * Location
     * @type {string}
     * @memberof SessionInfo
     */
    location?: string;
    /**
     * Whether session is suspicious
     * @type {boolean}
     * @memberof SessionInfo
     */
    suspicious: boolean;
    /**
     * User agent
     * @type {string}
     * @memberof SessionInfo
     */
    userAgent?: string;
    /**
     * User ID
     * @type {string}
     * @memberof SessionInfo
     */
    userId: string;
}

/**
 * Check if a given object implements the SessionInfo interface.
 */
export function instanceOfSessionInfo(value: object): value is SessionInfo {
    if (!('active' in value) || value['active'] === undefined) return false;
    if (!('createdAt' in value) || value['createdAt'] === undefined) return false;
    if (!('expiresAt' in value) || value['expiresAt'] === undefined) return false;
    if (!('id' in value) || value['id'] === undefined) return false;
    if (!('lastActiveAt' in value) || value['lastActiveAt'] === undefined) return false;
    if (!('suspicious' in value) || value['suspicious'] === undefined) return false;
    if (!('userId' in value) || value['userId'] === undefined) return false;
    return true;
}

export function SessionInfoFromJSON(json: any): SessionInfo {
    return SessionInfoFromJSONTyped(json, false);
}

export function SessionInfoFromJSONTyped(json: any, ignoreDiscriminator: boolean): SessionInfo {
    if (json == null) {
        return json;
    }
    return {
        
            ...json,
        'active': json['active'],
        'createdAt': (new Date(json['createdAt'])),
        'deviceId': json['deviceId'] == null ? undefined : json['deviceId'],
        'deviceType': json['deviceType'] == null ? undefined : json['deviceType'],
        'expiresAt': (new Date(json['expiresAt'])),
        'id': json['id'],
        'ipAddress': json['ipAddress'] == null ? undefined : json['ipAddress'],
        'lastActiveAt': (new Date(json['lastActiveAt'])),
        'location': json['location'] == null ? undefined : json['location'],
        'suspicious': json['suspicious'],
        'userAgent': json['userAgent'] == null ? undefined : json['userAgent'],
        'userId': json['userId'],
    };
}

export function SessionInfoToJSON(json: any): SessionInfo {
    return SessionInfoToJSONTyped(json, false);
}

export function SessionInfoToJSONTyped(value?: SessionInfo | null, ignoreDiscriminator = false): any {
    if (value == null) {
        return value;
    }

    return {
        
            ...value,
        'active': value['active'],
        'createdAt': ((value['createdAt']).toISOString()),
        'deviceId': value['deviceId'],
        'deviceType': value['deviceType'],
        'expiresAt': ((value['expiresAt']).toISOString()),
        'id': value['id'],
        'ipAddress': value['ipAddress'],
        'lastActiveAt': ((value['lastActiveAt']).toISOString()),
        'location': value['location'],
        'suspicious': value['suspicious'],
        'userAgent': value['userAgent'],
        'userId': value['userId'],
    };
}

