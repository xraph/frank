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
 * @interface UserProfileUpdateRequest
 */
export interface UserProfileUpdateRequest {
    [key: string]: any | any;
    /**
     * A URL to the JSON Schema for this object.
     * @type {string}
     * @memberof UserProfileUpdateRequest
     */
    readonly $schema?: string;
    /**
     * Updated custom attributes
     * @type {object}
     * @memberof UserProfileUpdateRequest
     */
    customAttributes?: object;
    /**
     * Updated first name
     * @type {string}
     * @memberof UserProfileUpdateRequest
     */
    firstName?: string;
    /**
     * Updated last name
     * @type {string}
     * @memberof UserProfileUpdateRequest
     */
    lastName?: string;
    /**
     * Updated locale
     * @type {string}
     * @memberof UserProfileUpdateRequest
     */
    locale?: string;
    /**
     * Updated profile image URL
     * @type {string}
     * @memberof UserProfileUpdateRequest
     */
    profileImageUrl?: string;
    /**
     * Updated timezone
     * @type {string}
     * @memberof UserProfileUpdateRequest
     */
    timezone?: string;
    /**
     * Updated username
     * @type {string}
     * @memberof UserProfileUpdateRequest
     */
    username?: string;
}

/**
 * Check if a given object implements the UserProfileUpdateRequest interface.
 */
export function instanceOfUserProfileUpdateRequest(value: object): value is UserProfileUpdateRequest {
    return true;
}

export function UserProfileUpdateRequestFromJSON(json: any): UserProfileUpdateRequest {
    return UserProfileUpdateRequestFromJSONTyped(json, false);
}

export function UserProfileUpdateRequestFromJSONTyped(json: any, ignoreDiscriminator: boolean): UserProfileUpdateRequest {
    if (json == null) {
        return json;
    }
    return {
        
            ...json,
        '$schema': json['$schema'] == null ? undefined : json['$schema'],
        'customAttributes': json['customAttributes'] == null ? undefined : json['customAttributes'],
        'firstName': json['firstName'] == null ? undefined : json['firstName'],
        'lastName': json['lastName'] == null ? undefined : json['lastName'],
        'locale': json['locale'] == null ? undefined : json['locale'],
        'profileImageUrl': json['profileImageUrl'] == null ? undefined : json['profileImageUrl'],
        'timezone': json['timezone'] == null ? undefined : json['timezone'],
        'username': json['username'] == null ? undefined : json['username'],
    };
}

export function UserProfileUpdateRequestToJSON(json: any): UserProfileUpdateRequest {
    return UserProfileUpdateRequestToJSONTyped(json, false);
}

export function UserProfileUpdateRequestToJSONTyped(value?: Omit<UserProfileUpdateRequest, '$schema'> | null, ignoreDiscriminator = false): any {
    if (value == null) {
        return value;
    }

    return {
        
            ...value,
        'customAttributes': value['customAttributes'],
        'firstName': value['firstName'],
        'lastName': value['lastName'],
        'locale': value['locale'],
        'profileImageUrl': value['profileImageUrl'],
        'timezone': value['timezone'],
        'username': value['username'],
    };
}

