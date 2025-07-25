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
import type { WebhookFormat } from './WebhookFormat';
import {
    WebhookFormatFromJSON,
    WebhookFormatFromJSONTyped,
    WebhookFormatToJSON,
    WebhookFormatToJSONTyped,
} from './WebhookFormat';
import type { WebhookStats } from './WebhookStats';
import {
    WebhookStatsFromJSON,
    WebhookStatsFromJSONTyped,
    WebhookStatsToJSON,
    WebhookStatsToJSONTyped,
} from './WebhookStats';
import type { OrganizationSummary } from './OrganizationSummary';
import {
    OrganizationSummaryFromJSON,
    OrganizationSummaryFromJSONTyped,
    OrganizationSummaryToJSON,
    OrganizationSummaryToJSONTyped,
} from './OrganizationSummary';
import type { WebhookEvent } from './WebhookEvent';
import {
    WebhookEventFromJSON,
    WebhookEventFromJSONTyped,
    WebhookEventToJSON,
    WebhookEventToJSONTyped,
} from './WebhookEvent';

/**
 * 
 * @export
 * @interface Webhook
 */
export interface Webhook {
    [key: string]: any | any;
    /**
     * A URL to the JSON Schema for this object.
     * @type {string}
     * @memberof Webhook
     */
    readonly $schema?: string;
    /**
     * Whether webhook is active
     * @type {boolean}
     * @memberof Webhook
     */
    active: boolean;
    /**
     * 
     * @type {Date}
     * @memberof Webhook
     */
    createdAt: Date;
    /**
     * 
     * @type {string}
     * @memberof Webhook
     */
    createdBy: string;
    /**
     * Subscribed event types
     * @type {Array<string>}
     * @memberof Webhook
     */
    eventTypes: Array<string>;
    /**
     * Recent webhook events
     * @type {Array<WebhookEvent>}
     * @memberof Webhook
     */
    events?: Array<WebhookEvent>;
    /**
     * Payload format (json, form)
     * @type {WebhookFormat}
     * @memberof Webhook
     */
    format: WebhookFormatEnum;
    /**
     * Custom headers to include
     * @type {{ [key: string]: string; }}
     * @memberof Webhook
     */
    headers?: { [key: string]: string; };
    /**
     * 
     * @type {string}
     * @memberof Webhook
     */
    id: string;
    /**
     * Additional webhook metadata
     * @type {object}
     * @memberof Webhook
     */
    metadata?: object;
    /**
     * Webhook name
     * @type {string}
     * @memberof Webhook
     */
    name: string;
    /**
     * Organization information
     * @type {OrganizationSummary}
     * @memberof Webhook
     */
    organization?: OrganizationSummary;
    /**
     * Organization ID
     * @type {string}
     * @memberof Webhook
     */
    organizationId: string;
    /**
     * Number of retry attempts
     * @type {number}
     * @memberof Webhook
     */
    retryCount: number;
    /**
     * Webhook secret for signature verification (write-only)
     * @type {string}
     * @memberof Webhook
     */
    secret?: string;
    /**
     * Webhook statistics
     * @type {WebhookStats}
     * @memberof Webhook
     */
    stats?: WebhookStats;
    /**
     * Request timeout in milliseconds
     * @type {number}
     * @memberof Webhook
     */
    timeoutMs: number;
    /**
     * 
     * @type {Date}
     * @memberof Webhook
     */
    updatedAt: Date;
    /**
     * 
     * @type {string}
     * @memberof Webhook
     */
    updatedBy: string;
    /**
     * Webhook endpoint URL
     * @type {string}
     * @memberof Webhook
     */
    url: string;
    /**
     * Webhook API version
     * @type {string}
     * @memberof Webhook
     */
    version: string;
}


/**
 * @export
 */
export const WebhookFormatEnum = {
    Json: 'json',
    Form: 'form'
} as const;
export type WebhookFormatEnum = typeof WebhookFormatEnum[keyof typeof WebhookFormatEnum];


/**
 * Check if a given object implements the Webhook interface.
 */
export function instanceOfWebhook(value: object): value is Webhook {
    if (!('active' in value) || value['active'] === undefined) return false;
    if (!('createdAt' in value) || value['createdAt'] === undefined) return false;
    if (!('createdBy' in value) || value['createdBy'] === undefined) return false;
    if (!('eventTypes' in value) || value['eventTypes'] === undefined) return false;
    if (!('format' in value) || value['format'] === undefined) return false;
    if (!('id' in value) || value['id'] === undefined) return false;
    if (!('name' in value) || value['name'] === undefined) return false;
    if (!('organizationId' in value) || value['organizationId'] === undefined) return false;
    if (!('retryCount' in value) || value['retryCount'] === undefined) return false;
    if (!('timeoutMs' in value) || value['timeoutMs'] === undefined) return false;
    if (!('updatedAt' in value) || value['updatedAt'] === undefined) return false;
    if (!('updatedBy' in value) || value['updatedBy'] === undefined) return false;
    if (!('url' in value) || value['url'] === undefined) return false;
    if (!('version' in value) || value['version'] === undefined) return false;
    return true;
}

export function WebhookFromJSON(json: any): Webhook {
    return WebhookFromJSONTyped(json, false);
}

export function WebhookFromJSONTyped(json: any, ignoreDiscriminator: boolean): Webhook {
    if (json == null) {
        return json;
    }
    return {
        
            ...json,
        '$schema': json['$schema'] == null ? undefined : json['$schema'],
        'active': json['active'],
        'createdAt': (new Date(json['createdAt'])),
        'createdBy': json['createdBy'],
        'eventTypes': json['eventTypes'],
        'events': json['events'] == null ? undefined : ((json['events'] as Array<any>).map(WebhookEventFromJSON)),
        'format': WebhookFormatFromJSON(json['format']),
        'headers': json['headers'] == null ? undefined : json['headers'],
        'id': json['id'],
        'metadata': json['metadata'] == null ? undefined : json['metadata'],
        'name': json['name'],
        'organization': json['organization'] == null ? undefined : OrganizationSummaryFromJSON(json['organization']),
        'organizationId': json['organizationId'],
        'retryCount': json['retryCount'],
        'secret': json['secret'] == null ? undefined : json['secret'],
        'stats': json['stats'] == null ? undefined : WebhookStatsFromJSON(json['stats']),
        'timeoutMs': json['timeoutMs'],
        'updatedAt': (new Date(json['updatedAt'])),
        'updatedBy': json['updatedBy'],
        'url': json['url'],
        'version': json['version'],
    };
}

export function WebhookToJSON(json: any): Webhook {
    return WebhookToJSONTyped(json, false);
}

export function WebhookToJSONTyped(value?: Omit<Webhook, '$schema'> | null, ignoreDiscriminator = false): any {
    if (value == null) {
        return value;
    }

    return {
        
            ...value,
        'active': value['active'],
        'createdAt': ((value['createdAt']).toISOString()),
        'createdBy': value['createdBy'],
        'eventTypes': value['eventTypes'],
        'events': value['events'] == null ? undefined : ((value['events'] as Array<any>).map(WebhookEventToJSON)),
        'format': WebhookFormatToJSON(value['format']),
        'headers': value['headers'],
        'id': value['id'],
        'metadata': value['metadata'],
        'name': value['name'],
        'organization': OrganizationSummaryToJSON(value['organization']),
        'organizationId': value['organizationId'],
        'retryCount': value['retryCount'],
        'secret': value['secret'],
        'stats': WebhookStatsToJSON(value['stats']),
        'timeoutMs': value['timeoutMs'],
        'updatedAt': ((value['updatedAt']).toISOString()),
        'updatedBy': value['updatedBy'],
        'url': value['url'],
        'version': value['version'],
    };
}

