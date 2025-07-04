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
 * @interface EndpointRateLimits
 */
export interface EndpointRateLimits {
    /**
     * 
     * @type {string}
     * @memberof EndpointRateLimits
     */
    endpoint: string;
    /**
     * 
     * @type {number}
     * @memberof EndpointRateLimits
     */
    limited: number;
    /**
     * 
     * @type {number}
     * @memberof EndpointRateLimits
     */
    limitedPercent: number;
    /**
     * 
     * @type {string}
     * @memberof EndpointRateLimits
     */
    method: string;
    /**
     * 
     * @type {number}
     * @memberof EndpointRateLimits
     */
    rateLimit: number;
    /**
     * 
     * @type {number}
     * @memberof EndpointRateLimits
     */
    requests: number;
}

/**
 * Check if a given object implements the EndpointRateLimits interface.
 */
export function instanceOfEndpointRateLimits(value: object): value is EndpointRateLimits {
    if (!('endpoint' in value) || value['endpoint'] === undefined) return false;
    if (!('limited' in value) || value['limited'] === undefined) return false;
    if (!('limitedPercent' in value) || value['limitedPercent'] === undefined) return false;
    if (!('method' in value) || value['method'] === undefined) return false;
    if (!('rateLimit' in value) || value['rateLimit'] === undefined) return false;
    if (!('requests' in value) || value['requests'] === undefined) return false;
    return true;
}

export function EndpointRateLimitsFromJSON(json: any): EndpointRateLimits {
    return EndpointRateLimitsFromJSONTyped(json, false);
}

export function EndpointRateLimitsFromJSONTyped(json: any, ignoreDiscriminator: boolean): EndpointRateLimits {
    if (json == null) {
        return json;
    }
    return {
        
        'endpoint': json['endpoint'],
        'limited': json['limited'],
        'limitedPercent': json['limited_percent'],
        'method': json['method'],
        'rateLimit': json['rate_limit'],
        'requests': json['requests'],
    };
}

export function EndpointRateLimitsToJSON(json: any): EndpointRateLimits {
    return EndpointRateLimitsToJSONTyped(json, false);
}

export function EndpointRateLimitsToJSONTyped(value?: EndpointRateLimits | null, ignoreDiscriminator = false): any {
    if (value == null) {
        return value;
    }

    return {
        
        'endpoint': value['endpoint'],
        'limited': value['limited'],
        'limited_percent': value['limitedPercent'],
        'method': value['method'],
        'rate_limit': value['rateLimit'],
        'requests': value['requests'],
    };
}

