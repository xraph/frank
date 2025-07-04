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
 * @interface PasskeyDiscoveryResponse
 */
export interface PasskeyDiscoveryResponse {
    [key: string]: any | any;
    /**
     * A URL to the JSON Schema for this object.
     * @type {string}
     * @memberof PasskeyDiscoveryResponse
     */
    readonly $schema?: string;
    /**
     * Whether passkeys are available
     * @type {boolean}
     * @memberof PasskeyDiscoveryResponse
     */
    available: boolean;
    /**
     * Whether conditional UI is supported
     * @type {boolean}
     * @memberof PasskeyDiscoveryResponse
     */
    conditionalUI: boolean;
    /**
     * Number of available passkeys
     * @type {number}
     * @memberof PasskeyDiscoveryResponse
     */
    count: number;
    /**
     * Whether platform authenticator is supported
     * @type {boolean}
     * @memberof PasskeyDiscoveryResponse
     */
    platformSupport: boolean;
    /**
     * Whether roaming authenticator is supported
     * @type {boolean}
     * @memberof PasskeyDiscoveryResponse
     */
    roamingSupport: boolean;
    /**
     * Supported authenticator methods
     * @type {Array<string>}
     * @memberof PasskeyDiscoveryResponse
     */
    supportedMethods: Array<string>;
}

/**
 * Check if a given object implements the PasskeyDiscoveryResponse interface.
 */
export function instanceOfPasskeyDiscoveryResponse(value: object): value is PasskeyDiscoveryResponse {
    if (!('available' in value) || value['available'] === undefined) return false;
    if (!('conditionalUI' in value) || value['conditionalUI'] === undefined) return false;
    if (!('count' in value) || value['count'] === undefined) return false;
    if (!('platformSupport' in value) || value['platformSupport'] === undefined) return false;
    if (!('roamingSupport' in value) || value['roamingSupport'] === undefined) return false;
    if (!('supportedMethods' in value) || value['supportedMethods'] === undefined) return false;
    return true;
}

export function PasskeyDiscoveryResponseFromJSON(json: any): PasskeyDiscoveryResponse {
    return PasskeyDiscoveryResponseFromJSONTyped(json, false);
}

export function PasskeyDiscoveryResponseFromJSONTyped(json: any, ignoreDiscriminator: boolean): PasskeyDiscoveryResponse {
    if (json == null) {
        return json;
    }
    return {
        
            ...json,
        '$schema': json['$schema'] == null ? undefined : json['$schema'],
        'available': json['available'],
        'conditionalUI': json['conditionalUI'],
        'count': json['count'],
        'platformSupport': json['platformSupport'],
        'roamingSupport': json['roamingSupport'],
        'supportedMethods': json['supportedMethods'],
    };
}

export function PasskeyDiscoveryResponseToJSON(json: any): PasskeyDiscoveryResponse {
    return PasskeyDiscoveryResponseToJSONTyped(json, false);
}

export function PasskeyDiscoveryResponseToJSONTyped(value?: Omit<PasskeyDiscoveryResponse, '$schema'> | null, ignoreDiscriminator = false): any {
    if (value == null) {
        return value;
    }

    return {
        
            ...value,
        'available': value['available'],
        'conditionalUI': value['conditionalUI'],
        'count': value['count'],
        'platformSupport': value['platformSupport'],
        'roamingSupport': value['roamingSupport'],
        'supportedMethods': value['supportedMethods'],
    };
}

