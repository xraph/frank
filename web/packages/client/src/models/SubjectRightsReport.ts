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
 * @interface SubjectRightsReport
 */
export interface SubjectRightsReport {
    /**
     * 
     * @type {number}
     * @memberof SubjectRightsReport
     */
    accessRequests: number;
    /**
     * 
     * @type {number}
     * @memberof SubjectRightsReport
     */
    averageResponseTime: number;
    /**
     * 
     * @type {number}
     * @memberof SubjectRightsReport
     */
    complianceRate: number;
    /**
     * 
     * @type {number}
     * @memberof SubjectRightsReport
     */
    erasureRequests: number;
    /**
     * 
     * @type {number}
     * @memberof SubjectRightsReport
     */
    objectionRequests: number;
    /**
     * 
     * @type {number}
     * @memberof SubjectRightsReport
     */
    portabilityRequests: number;
    /**
     * 
     * @type {number}
     * @memberof SubjectRightsReport
     */
    rectificationRequests: number;
    /**
     * 
     * @type {{ [key: string]: number; }}
     * @memberof SubjectRightsReport
     */
    requestsByType: { [key: string]: number; };
    /**
     * 
     * @type {number}
     * @memberof SubjectRightsReport
     */
    totalRequests: number;
}

/**
 * Check if a given object implements the SubjectRightsReport interface.
 */
export function instanceOfSubjectRightsReport(value: object): value is SubjectRightsReport {
    if (!('accessRequests' in value) || value['accessRequests'] === undefined) return false;
    if (!('averageResponseTime' in value) || value['averageResponseTime'] === undefined) return false;
    if (!('complianceRate' in value) || value['complianceRate'] === undefined) return false;
    if (!('erasureRequests' in value) || value['erasureRequests'] === undefined) return false;
    if (!('objectionRequests' in value) || value['objectionRequests'] === undefined) return false;
    if (!('portabilityRequests' in value) || value['portabilityRequests'] === undefined) return false;
    if (!('rectificationRequests' in value) || value['rectificationRequests'] === undefined) return false;
    if (!('requestsByType' in value) || value['requestsByType'] === undefined) return false;
    if (!('totalRequests' in value) || value['totalRequests'] === undefined) return false;
    return true;
}

export function SubjectRightsReportFromJSON(json: any): SubjectRightsReport {
    return SubjectRightsReportFromJSONTyped(json, false);
}

export function SubjectRightsReportFromJSONTyped(json: any, ignoreDiscriminator: boolean): SubjectRightsReport {
    if (json == null) {
        return json;
    }
    return {
        
        'accessRequests': json['access_requests'],
        'averageResponseTime': json['average_response_time'],
        'complianceRate': json['compliance_rate'],
        'erasureRequests': json['erasure_requests'],
        'objectionRequests': json['objection_requests'],
        'portabilityRequests': json['portability_requests'],
        'rectificationRequests': json['rectification_requests'],
        'requestsByType': json['requests_by_type'],
        'totalRequests': json['total_requests'],
    };
}

export function SubjectRightsReportToJSON(json: any): SubjectRightsReport {
    return SubjectRightsReportToJSONTyped(json, false);
}

export function SubjectRightsReportToJSONTyped(value?: SubjectRightsReport | null, ignoreDiscriminator = false): any {
    if (value == null) {
        return value;
    }

    return {
        
        'access_requests': value['accessRequests'],
        'average_response_time': value['averageResponseTime'],
        'compliance_rate': value['complianceRate'],
        'erasure_requests': value['erasureRequests'],
        'objection_requests': value['objectionRequests'],
        'portability_requests': value['portabilityRequests'],
        'rectification_requests': value['rectificationRequests'],
        'requests_by_type': value['requestsByType'],
        'total_requests': value['totalRequests'],
    };
}

