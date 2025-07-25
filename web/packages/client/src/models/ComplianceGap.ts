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
 * @interface ComplianceGap
 */
export interface ComplianceGap {
    /**
     * 
     * @type {Array<string>}
     * @memberof ComplianceGap
     */
    actionItems: Array<string> | null;
    /**
     * 
     * @type {string}
     * @memberof ComplianceGap
     */
    currentState: string;
    /**
     * 
     * @type {string}
     * @memberof ComplianceGap
     */
    owner: string;
    /**
     * 
     * @type {string}
     * @memberof ComplianceGap
     */
    priority: string;
    /**
     * 
     * @type {string}
     * @memberof ComplianceGap
     */
    requiredState: string;
    /**
     * 
     * @type {string}
     * @memberof ComplianceGap
     */
    requirement: string;
    /**
     * 
     * @type {string}
     * @memberof ComplianceGap
     */
    timeline: string;
}

/**
 * Check if a given object implements the ComplianceGap interface.
 */
export function instanceOfComplianceGap(value: object): value is ComplianceGap {
    if (!('actionItems' in value) || value['actionItems'] === undefined) return false;
    if (!('currentState' in value) || value['currentState'] === undefined) return false;
    if (!('owner' in value) || value['owner'] === undefined) return false;
    if (!('priority' in value) || value['priority'] === undefined) return false;
    if (!('requiredState' in value) || value['requiredState'] === undefined) return false;
    if (!('requirement' in value) || value['requirement'] === undefined) return false;
    if (!('timeline' in value) || value['timeline'] === undefined) return false;
    return true;
}

export function ComplianceGapFromJSON(json: any): ComplianceGap {
    return ComplianceGapFromJSONTyped(json, false);
}

export function ComplianceGapFromJSONTyped(json: any, ignoreDiscriminator: boolean): ComplianceGap {
    if (json == null) {
        return json;
    }
    return {
        
        'actionItems': json['action_items'] == null ? null : json['action_items'],
        'currentState': json['current_state'],
        'owner': json['owner'],
        'priority': json['priority'],
        'requiredState': json['required_state'],
        'requirement': json['requirement'],
        'timeline': json['timeline'],
    };
}

export function ComplianceGapToJSON(json: any): ComplianceGap {
    return ComplianceGapToJSONTyped(json, false);
}

export function ComplianceGapToJSONTyped(value?: ComplianceGap | null, ignoreDiscriminator = false): any {
    if (value == null) {
        return value;
    }

    return {
        
        'action_items': value['actionItems'],
        'current_state': value['currentState'],
        'owner': value['owner'],
        'priority': value['priority'],
        'required_state': value['requiredState'],
        'requirement': value['requirement'],
        'timeline': value['timeline'],
    };
}

