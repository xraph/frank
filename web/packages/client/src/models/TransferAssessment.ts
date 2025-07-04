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
 * @interface TransferAssessment
 */
export interface TransferAssessment {
    /**
     * 
     * @type {string}
     * @memberof TransferAssessment
     */
    adequacy: string;
    /**
     * 
     * @type {Array<string>}
     * @memberof TransferAssessment
     */
    dataCategories: Array<string> | null;
    /**
     * 
     * @type {string}
     * @memberof TransferAssessment
     */
    destination: string;
    /**
     * 
     * @type {Date}
     * @memberof TransferAssessment
     */
    lastAssessed: Date;
    /**
     * 
     * @type {string}
     * @memberof TransferAssessment
     */
    riskLevel: string;
    /**
     * 
     * @type {Array<string>}
     * @memberof TransferAssessment
     */
    safeguards: Array<string> | null;
    /**
     * 
     * @type {string}
     * @memberof TransferAssessment
     */
    status: string;
    /**
     * 
     * @type {string}
     * @memberof TransferAssessment
     */
    transferMechanism: string;
}

/**
 * Check if a given object implements the TransferAssessment interface.
 */
export function instanceOfTransferAssessment(value: object): value is TransferAssessment {
    if (!('adequacy' in value) || value['adequacy'] === undefined) return false;
    if (!('dataCategories' in value) || value['dataCategories'] === undefined) return false;
    if (!('destination' in value) || value['destination'] === undefined) return false;
    if (!('lastAssessed' in value) || value['lastAssessed'] === undefined) return false;
    if (!('riskLevel' in value) || value['riskLevel'] === undefined) return false;
    if (!('safeguards' in value) || value['safeguards'] === undefined) return false;
    if (!('status' in value) || value['status'] === undefined) return false;
    if (!('transferMechanism' in value) || value['transferMechanism'] === undefined) return false;
    return true;
}

export function TransferAssessmentFromJSON(json: any): TransferAssessment {
    return TransferAssessmentFromJSONTyped(json, false);
}

export function TransferAssessmentFromJSONTyped(json: any, ignoreDiscriminator: boolean): TransferAssessment {
    if (json == null) {
        return json;
    }
    return {
        
        'adequacy': json['adequacy'],
        'dataCategories': json['data_categories'] == null ? null : json['data_categories'],
        'destination': json['destination'],
        'lastAssessed': (new Date(json['last_assessed'])),
        'riskLevel': json['risk_level'],
        'safeguards': json['safeguards'] == null ? null : json['safeguards'],
        'status': json['status'],
        'transferMechanism': json['transfer_mechanism'],
    };
}

export function TransferAssessmentToJSON(json: any): TransferAssessment {
    return TransferAssessmentToJSONTyped(json, false);
}

export function TransferAssessmentToJSONTyped(value?: TransferAssessment | null, ignoreDiscriminator = false): any {
    if (value == null) {
        return value;
    }

    return {
        
        'adequacy': value['adequacy'],
        'data_categories': value['dataCategories'],
        'destination': value['destination'],
        'last_assessed': ((value['lastAssessed']).toISOString()),
        'risk_level': value['riskLevel'],
        'safeguards': value['safeguards'],
        'status': value['status'],
        'transfer_mechanism': value['transferMechanism'],
    };
}

