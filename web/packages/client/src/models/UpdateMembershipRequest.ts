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
 * @interface UpdateMembershipRequest
 */
export interface UpdateMembershipRequest {
    [key: string]: any | any;
    /**
     * A URL to the JSON Schema for this object.
     * @type {string}
     * @memberof UpdateMembershipRequest
     */
    readonly $schema?: string;
    /**
     * Updated expiration
     * @type {Date}
     * @memberof UpdateMembershipRequest
     */
    expiresAt?: Date;
    /**
     * Updated billing contact status
     * @type {boolean}
     * @memberof UpdateMembershipRequest
     */
    isBillingContact?: boolean;
    /**
     * Updated primary contact status
     * @type {boolean}
     * @memberof UpdateMembershipRequest
     */
    isPrimaryContact?: boolean;
    /**
     * Updated metadata
     * @type {object}
     * @memberof UpdateMembershipRequest
     */
    metadata?: object;
    /**
     * Updated role ID
     * @type {string}
     * @memberof UpdateMembershipRequest
     */
    roleId?: string;
    /**
     * Updated status
     * @type {string}
     * @memberof UpdateMembershipRequest
     */
    status?: string;
}

/**
 * Check if a given object implements the UpdateMembershipRequest interface.
 */
export function instanceOfUpdateMembershipRequest(value: object): value is UpdateMembershipRequest {
    return true;
}

export function UpdateMembershipRequestFromJSON(json: any): UpdateMembershipRequest {
    return UpdateMembershipRequestFromJSONTyped(json, false);
}

export function UpdateMembershipRequestFromJSONTyped(json: any, ignoreDiscriminator: boolean): UpdateMembershipRequest {
    if (json == null) {
        return json;
    }
    return {
        
            ...json,
        '$schema': json['$schema'] == null ? undefined : json['$schema'],
        'expiresAt': json['expiresAt'] == null ? undefined : (new Date(json['expiresAt'])),
        'isBillingContact': json['isBillingContact'] == null ? undefined : json['isBillingContact'],
        'isPrimaryContact': json['isPrimaryContact'] == null ? undefined : json['isPrimaryContact'],
        'metadata': json['metadata'] == null ? undefined : json['metadata'],
        'roleId': json['roleId'] == null ? undefined : json['roleId'],
        'status': json['status'] == null ? undefined : json['status'],
    };
}

export function UpdateMembershipRequestToJSON(json: any): UpdateMembershipRequest {
    return UpdateMembershipRequestToJSONTyped(json, false);
}

export function UpdateMembershipRequestToJSONTyped(value?: Omit<UpdateMembershipRequest, '$schema'> | null, ignoreDiscriminator = false): any {
    if (value == null) {
        return value;
    }

    return {
        
            ...value,
        'expiresAt': value['expiresAt'] == null ? undefined : ((value['expiresAt']).toISOString()),
        'isBillingContact': value['isBillingContact'],
        'isPrimaryContact': value['isPrimaryContact'],
        'metadata': value['metadata'],
        'roleId': value['roleId'],
        'status': value['status'],
    };
}

