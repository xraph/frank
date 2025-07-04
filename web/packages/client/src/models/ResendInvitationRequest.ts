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
 * @interface ResendInvitationRequest
 */
export interface ResendInvitationRequest {
    [key: string]: any | any;
    /**
     * A URL to the JSON Schema for this object.
     * @type {string}
     * @memberof ResendInvitationRequest
     */
    readonly $schema?: string;
    /**
     * Custom message for resend
     * @type {string}
     * @memberof ResendInvitationRequest
     */
    customMessage?: string;
    /**
     * Whether to extend expiration by 7 days
     * @type {boolean}
     * @memberof ResendInvitationRequest
     */
    extendExpiry: boolean;
    /**
     * Invitation ID to resend
     * @type {string}
     * @memberof ResendInvitationRequest
     */
    invitationId: string;
    /**
     * Updated message for resend
     * @type {string}
     * @memberof ResendInvitationRequest
     */
    message?: string;
}

/**
 * Check if a given object implements the ResendInvitationRequest interface.
 */
export function instanceOfResendInvitationRequest(value: object): value is ResendInvitationRequest {
    if (!('extendExpiry' in value) || value['extendExpiry'] === undefined) return false;
    if (!('invitationId' in value) || value['invitationId'] === undefined) return false;
    return true;
}

export function ResendInvitationRequestFromJSON(json: any): ResendInvitationRequest {
    return ResendInvitationRequestFromJSONTyped(json, false);
}

export function ResendInvitationRequestFromJSONTyped(json: any, ignoreDiscriminator: boolean): ResendInvitationRequest {
    if (json == null) {
        return json;
    }
    return {
        
            ...json,
        '$schema': json['$schema'] == null ? undefined : json['$schema'],
        'customMessage': json['customMessage'] == null ? undefined : json['customMessage'],
        'extendExpiry': json['extendExpiry'],
        'invitationId': json['invitationId'],
        'message': json['message'] == null ? undefined : json['message'],
    };
}

export function ResendInvitationRequestToJSON(json: any): ResendInvitationRequest {
    return ResendInvitationRequestToJSONTyped(json, false);
}

export function ResendInvitationRequestToJSONTyped(value?: Omit<ResendInvitationRequest, '$schema'> | null, ignoreDiscriminator = false): any {
    if (value == null) {
        return value;
    }

    return {
        
            ...value,
        'customMessage': value['customMessage'],
        'extendExpiry': value['extendExpiry'],
        'invitationId': value['invitationId'],
        'message': value['message'],
    };
}

