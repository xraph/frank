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
import type { APIKeyType } from './APIKeyType';
import {
    APIKeyTypeFromJSON,
    APIKeyTypeFromJSONTyped,
    APIKeyTypeToJSON,
    APIKeyTypeToJSONTyped,
} from './APIKeyType';
import type { OrganizationSummary } from './OrganizationSummary';
import {
    OrganizationSummaryFromJSON,
    OrganizationSummaryFromJSONTyped,
    OrganizationSummaryToJSON,
    OrganizationSummaryToJSONTyped,
} from './OrganizationSummary';
import type { Environment } from './Environment';
import {
    EnvironmentFromJSON,
    EnvironmentFromJSONTyped,
    EnvironmentToJSON,
    EnvironmentToJSONTyped,
} from './Environment';
import type { UserSummary } from './UserSummary';
import {
    UserSummaryFromJSON,
    UserSummaryFromJSONTyped,
    UserSummaryToJSON,
    UserSummaryToJSONTyped,
} from './UserSummary';
import type { APIKeyRateLimits } from './APIKeyRateLimits';
import {
    APIKeyRateLimitsFromJSON,
    APIKeyRateLimitsFromJSONTyped,
    APIKeyRateLimitsToJSON,
    APIKeyRateLimitsToJSONTyped,
} from './APIKeyRateLimits';
import type { APIKeyUsage } from './APIKeyUsage';
import {
    APIKeyUsageFromJSON,
    APIKeyUsageFromJSONTyped,
    APIKeyUsageToJSON,
    APIKeyUsageToJSONTyped,
} from './APIKeyUsage';

/**
 * 
 * @export
 * @interface APIKey
 */
export interface APIKey {
    [key: string]: any | any;
    /**
     * A URL to the JSON Schema for this object.
     * @type {string}
     * @memberof APIKey
     */
    readonly $schema?: string;
    /**
     * Whether API key is active
     * @type {boolean}
     * @memberof APIKey
     */
    active: boolean;
    /**
     * 
     * @type {Date}
     * @memberof APIKey
     */
    createdAt: Date;
    /**
     * Environment (test, live)
     * @type {Environment}
     * @memberof APIKey
     */
    environment: Environment;
    /**
     * Expiration timestamp
     * @type {Date}
     * @memberof APIKey
     */
    expiresAt?: Date;
    /**
     * Legacy hashed API key (deprecated)
     * @type {string}
     * @memberof APIKey
     */
    hashedKey?: string;
    /**
     * Hashed secret key (internal use)
     * @type {string}
     * @memberof APIKey
     */
    hashedSecretKey?: string;
    /**
     * 
     * @type {string}
     * @memberof APIKey
     */
    id: string;
    /**
     * Allowed IP addresses/ranges
     * @type {Array<string>}
     * @memberof APIKey
     */
    ipWhitelist?: Array<string>;
    /**
     * Legacy API key value (deprecated)
     * @type {string}
     * @memberof APIKey
     */
    key?: string;
    /**
     * Last usage timestamp
     * @type {Date}
     * @memberof APIKey
     */
    lastUsed?: Date;
    /**
     * Additional API key metadata
     * @type {object}
     * @memberof APIKey
     */
    metadata?: object;
    /**
     * API key name
     * @type {string}
     * @memberof APIKey
     */
    name: string;
    /**
     * Organization information
     * @type {OrganizationSummary}
     * @memberof APIKey
     */
    organization?: OrganizationSummary;
    /**
     * Organization ID
     * @type {string}
     * @memberof APIKey
     */
    organizationId?: string;
    /**
     * Granted permissions
     * @type {Array<string>}
     * @memberof APIKey
     */
    permissions?: Array<string>;
    /**
     * Public API key (safe to display)
     * @type {string}
     * @memberof APIKey
     */
    publicKey?: string;
    /**
     * Rate limiting configuration
     * @type {APIKeyRateLimits}
     * @memberof APIKey
     */
    rateLimits?: APIKeyRateLimits;
    /**
     * API scopes
     * @type {Array<string>}
     * @memberof APIKey
     */
    scopes?: Array<string>;
    /**
     * Secret API key value (write-only)
     * @type {string}
     * @memberof APIKey
     */
    secretKey?: string;
    /**
     * API key type (server, client, admin)
     * @type {APIKeyType}
     * @memberof APIKey
     */
    type: APIKeyType;
    /**
     * 
     * @type {Date}
     * @memberof APIKey
     */
    updatedAt: Date;
    /**
     * Usage statistics
     * @type {APIKeyUsage}
     * @memberof APIKey
     */
    usage?: APIKeyUsage;
    /**
     * User information (for user-scoped keys)
     * @type {UserSummary}
     * @memberof APIKey
     */
    user?: UserSummary;
    /**
     * User ID (for user-scoped keys)
     * @type {string}
     * @memberof APIKey
     */
    userId?: string;
}



/**
 * Check if a given object implements the APIKey interface.
 */
export function instanceOfAPIKey(value: object): value is APIKey {
    if (!('active' in value) || value['active'] === undefined) return false;
    if (!('createdAt' in value) || value['createdAt'] === undefined) return false;
    if (!('environment' in value) || value['environment'] === undefined) return false;
    if (!('id' in value) || value['id'] === undefined) return false;
    if (!('name' in value) || value['name'] === undefined) return false;
    if (!('type' in value) || value['type'] === undefined) return false;
    if (!('updatedAt' in value) || value['updatedAt'] === undefined) return false;
    return true;
}

export function APIKeyFromJSON(json: any): APIKey {
    return APIKeyFromJSONTyped(json, false);
}

export function APIKeyFromJSONTyped(json: any, ignoreDiscriminator: boolean): APIKey {
    if (json == null) {
        return json;
    }
    return {
        
            ...json,
        '$schema': json['$schema'] == null ? undefined : json['$schema'],
        'active': json['active'],
        'createdAt': (new Date(json['createdAt'])),
        'environment': EnvironmentFromJSON(json['environment']),
        'expiresAt': json['expiresAt'] == null ? undefined : (new Date(json['expiresAt'])),
        'hashedKey': json['hashedKey'] == null ? undefined : json['hashedKey'],
        'hashedSecretKey': json['hashedSecretKey'] == null ? undefined : json['hashedSecretKey'],
        'id': json['id'],
        'ipWhitelist': json['ipWhitelist'] == null ? undefined : json['ipWhitelist'],
        'key': json['key'] == null ? undefined : json['key'],
        'lastUsed': json['lastUsed'] == null ? undefined : (new Date(json['lastUsed'])),
        'metadata': json['metadata'] == null ? undefined : json['metadata'],
        'name': json['name'],
        'organization': json['organization'] == null ? undefined : OrganizationSummaryFromJSON(json['organization']),
        'organizationId': json['organizationId'] == null ? undefined : json['organizationId'],
        'permissions': json['permissions'] == null ? undefined : json['permissions'],
        'publicKey': json['publicKey'] == null ? undefined : json['publicKey'],
        'rateLimits': json['rateLimits'] == null ? undefined : APIKeyRateLimitsFromJSON(json['rateLimits']),
        'scopes': json['scopes'] == null ? undefined : json['scopes'],
        'secretKey': json['secretKey'] == null ? undefined : json['secretKey'],
        'type': APIKeyTypeFromJSON(json['type']),
        'updatedAt': (new Date(json['updatedAt'])),
        'usage': json['usage'] == null ? undefined : APIKeyUsageFromJSON(json['usage']),
        'user': json['user'] == null ? undefined : UserSummaryFromJSON(json['user']),
        'userId': json['userId'] == null ? undefined : json['userId'],
    };
}

export function APIKeyToJSON(json: any): APIKey {
    return APIKeyToJSONTyped(json, false);
}

export function APIKeyToJSONTyped(value?: Omit<APIKey, '$schema'> | null, ignoreDiscriminator = false): any {
    if (value == null) {
        return value;
    }

    return {
        
            ...value,
        'active': value['active'],
        'createdAt': ((value['createdAt']).toISOString()),
        'environment': EnvironmentToJSON(value['environment']),
        'expiresAt': value['expiresAt'] == null ? undefined : ((value['expiresAt']).toISOString()),
        'hashedKey': value['hashedKey'],
        'hashedSecretKey': value['hashedSecretKey'],
        'id': value['id'],
        'ipWhitelist': value['ipWhitelist'],
        'key': value['key'],
        'lastUsed': value['lastUsed'] == null ? undefined : ((value['lastUsed']).toISOString()),
        'metadata': value['metadata'],
        'name': value['name'],
        'organization': OrganizationSummaryToJSON(value['organization']),
        'organizationId': value['organizationId'],
        'permissions': value['permissions'],
        'publicKey': value['publicKey'],
        'rateLimits': APIKeyRateLimitsToJSON(value['rateLimits']),
        'scopes': value['scopes'],
        'secretKey': value['secretKey'],
        'type': APIKeyTypeToJSON(value['type']),
        'updatedAt': ((value['updatedAt']).toISOString()),
        'usage': APIKeyUsageToJSON(value['usage']),
        'user': UserSummaryToJSON(value['user']),
        'userId': value['userId'],
    };
}

