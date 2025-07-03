import type {JSONObject, Timestamp, XID} from './index';

// Base event interface
export interface BaseEvent {
    type: string;
    timestamp: Timestamp;
    id: XID;
    metadata?: JSONObject;
}

// Authentication events
export type AuthEventType =
    | 'auth.signIn.attempt'
    | 'auth.signIn.success'
    | 'auth.signIn.failure'
    | 'auth.signUp.attempt'
    | 'auth.signUp.success'
    | 'auth.signUp.failure'
    | 'auth.signOut.success'
    | 'auth.session.created'
    | 'auth.session.refreshed'
    | 'auth.session.expired'
    | 'auth.session.terminated'
    | 'auth.mfa.enabled'
    | 'auth.mfa.disabled'
    | 'auth.mfa.challenge.sent'
    | 'auth.mfa.challenge.success'
    | 'auth.mfa.challenge.failure'
    | 'auth.passkey.registered'
    | 'auth.passkey.removed'
    | 'auth.passkey.used'
    | 'auth.oauth.connected'
    | 'auth.oauth.disconnected'
    | 'auth.password.changed'
    | 'auth.password.reset.requested'
    | 'auth.password.reset.completed'
    | 'auth.email.verification.sent'
    | 'auth.email.verification.success'
    | 'auth.phone.verification.sent'
    | 'auth.phone.verification.success'
    | 'auth.magic_link.sent'
    | 'auth.magic_link.used';

export interface AuthEvent extends BaseEvent {
    type: AuthEventType;
    userId?: XID;
    organizationId?: XID;
    sessionId?: XID;
    ipAddress?: string;
    userAgent?: string;
    authMethod?: string;
    provider?: string;
    success: boolean;
    reason?: string;
    details?: JSONObject;
}

// User events
export type UserEventType =
    | 'user.created'
    | 'user.updated'
    | 'user.deleted'
    | 'user.activated'
    | 'user.deactivated'
    | 'user.blocked'
    | 'user.unblocked'
    | 'user.profile.updated'
    | 'user.email.changed'
    | 'user.phone.changed'
    | 'user.username.changed'
    | 'user.role.assigned'
    | 'user.role.removed'
    | 'user.permission.granted'
    | 'user.permission.revoked'
    | 'user.impersonation.started'
    | 'user.impersonation.ended';

export interface UserEvent extends BaseEvent {
    type: UserEventType;
    userId: XID;
    organizationId?: XID;
    targetUserId?: XID; // for impersonation events
    performedBy?: XID;
    changes?: JSONObject;
    previousValues?: JSONObject;
    newValues?: JSONObject;
}

// Organization events
export type OrganizationEventType =
    | 'organization.created'
    | 'organization.updated'
    | 'organization.deleted'
    | 'organization.activated'
    | 'organization.deactivated'
    | 'organization.member.added'
    | 'organization.member.removed'
    | 'organization.member.role.changed'
    | 'organization.member.status.changed'
    | 'organization.invitation.created'
    | 'organization.invitation.accepted'
    | 'organization.invitation.expired'
    | 'organization.invitation.revoked'
    | 'organization.settings.updated'
    | 'organization.domain.added'
    | 'organization.domain.verified'
    | 'organization.domain.removed'
    | 'organization.sso.enabled'
    | 'organization.sso.disabled'
    | 'organization.sso.configured'
    | 'organization.billing.updated'
    | 'organization.plan.changed'
    | 'organization.ownership.transferred';

export interface OrganizationEvent extends BaseEvent {
    type: OrganizationEventType;
    organizationId: XID;
    userId?: XID;
    targetUserId?: XID; // for member-related events
    performedBy?: XID;
    changes?: JSONObject;
    previousValues?: JSONObject;
    newValues?: JSONObject;
}

// Session events
export type SessionEventType =
    | 'session.created'
    | 'session.refreshed'
    | 'session.updated'
    | 'session.expired'
    | 'session.terminated'
    | 'session.activity.recorded'
    | 'session.suspicious.activity'
    | 'session.device.changed'
    | 'session.location.changed'
    | 'session.concurrent.limit.exceeded';

export interface SessionEvent extends BaseEvent {
    type: SessionEventType;
    sessionId: XID;
    userId: XID;
    organizationId?: XID;
    ipAddress?: string;
    userAgent?: string;
    deviceInfo?: JSONObject;
    locationInfo?: JSONObject;
    reason?: string;
    details?: JSONObject;
}

// Security events
export type SecurityEventType =
    | 'security.login.failure.threshold'
    | 'security.account.locked'
    | 'security.account.unlocked'
    | 'security.password.breach.detected'
    | 'security.suspicious.login'
    | 'security.device.new'
    | 'security.location.new'
    | 'security.api.rate.limit.exceeded'
    | 'security.permission.escalation'
    | 'security.data.export'
    | 'security.admin.action'
    | 'security.configuration.changed';

export interface SecurityEvent extends BaseEvent {
    type: SecurityEventType;
    userId?: XID;
    organizationId?: XID;
    sessionId?: XID;
    severity: 'low' | 'medium' | 'high' | 'critical';
    riskScore?: number;
    ipAddress?: string;
    userAgent?: string;
    automated: boolean;
    resolved: boolean;
    resolvedAt?: Timestamp;
    resolvedBy?: XID;
    actionTaken?: string;
    details?: JSONObject;
}

// System events
export type SystemEventType =
    | 'system.startup'
    | 'system.shutdown'
    | 'system.error'
    | 'system.maintenance.started'
    | 'system.maintenance.completed'
    | 'system.backup.started'
    | 'system.backup.completed'
    | 'system.update.started'
    | 'system.update.completed'
    | 'system.configuration.changed';

export interface SystemEvent extends BaseEvent {
    type: SystemEventType;
    severity: 'info' | 'warning' | 'error' | 'critical';
    component?: string;
    version?: string;
    details?: JSONObject;
}

// Billing events
export type BillingEventType =
    | 'billing.subscription.created'
    | 'billing.subscription.updated'
    | 'billing.subscription.canceled'
    | 'billing.payment.succeeded'
    | 'billing.payment.failed'
    | 'billing.invoice.created'
    | 'billing.invoice.paid'
    | 'billing.invoice.overdue'
    | 'billing.trial.started'
    | 'billing.trial.ended'
    | 'billing.seat.added'
    | 'billing.seat.removed'
    | 'billing.usage.threshold.exceeded';

export interface BillingEvent extends BaseEvent {
    type: BillingEventType;
    organizationId: XID;
    customerId?: string;
    subscriptionId?: string;
    invoiceId?: string;
    amount?: number;
    currency?: string;
    details?: JSONObject;
}

// Integration events
export type IntegrationEventType =
    | 'integration.webhook.sent'
    | 'integration.webhook.failed'
    | 'integration.api.key.created'
    | 'integration.api.key.revoked'
    | 'integration.sso.login'
    | 'integration.sso.failure'
    | 'integration.directory.sync'
    | 'integration.audit.export';

export interface IntegrationEvent extends BaseEvent {
    type: IntegrationEventType;
    organizationId?: XID;
    integrationId?: XID;
    webhookUrl?: string;
    statusCode?: number;
    responseTime?: number;
    retryCount?: number;
    details?: JSONObject;
}

// Union type for all events
export type FrankAuthEvent =
    | AuthEvent
    | UserEvent
    | OrganizationEvent
    | SessionEvent
    | SecurityEvent
    | SystemEvent
    | BillingEvent
    | IntegrationEvent;

// Event handler function type
export type EventHandler<T extends FrankAuthEvent = FrankAuthEvent> = (event: T) => void | Promise<void>;

// Event listener interface
export interface EventListener {
    id: XID;
    eventType: string;
    handler: EventHandler;
    once?: boolean;
    organizationId?: XID;
    userId?: XID;
}

// Event emitter interface
export interface EventEmitter {
    // Subscribe to events
    on<T extends FrankAuthEvent>(eventType: T['type'], handler: EventHandler<T>): () => void;
    once<T extends FrankAuthEvent>(eventType: T['type'], handler: EventHandler<T>): () => void;

    // Unsubscribe from events
    off<T extends FrankAuthEvent>(eventType: T['type'], handler: EventHandler<T>): void;
    removeAllListeners(eventType?: string): void;

    // Emit events
    emit<T extends FrankAuthEvent>(event: T): void;

    // Event listener management
    listenerCount(eventType: string): number;
    listeners(eventType: string): EventHandler[];
}

// Event store interface
export interface EventStore {
    // Store events
    store(event: FrankAuthEvent): Promise<void>;

    // Query events
    query(filters: EventQueryFilters): Promise<FrankAuthEvent[]>;

    // Get event by ID
    getById(eventId: XID): Promise<FrankAuthEvent | null>;

    // Delete events
    delete(eventId: XID): Promise<void>;
    cleanup(olderThan: Timestamp): Promise<number>;
}

// Event query filters
export interface EventQueryFilters {
    eventTypes?: string[];
    userId?: XID;
    organizationId?: XID;
    sessionId?: XID;
    startTime?: Timestamp;
    endTime?: Timestamp;
    severity?: string[];
    limit?: number;
    offset?: number;
    sortBy?: 'timestamp' | 'type' | 'severity';
    sortOrder?: 'asc' | 'desc';
}

// Event subscription
export interface EventSubscription {
    id: XID;
    eventTypes: string[];
    filters?: EventSubscriptionFilters;
    endpoint?: string;
    headers?: Record<string, string>;
    active: boolean;
    createdAt: Timestamp;
    updatedAt: Timestamp;
}

// Event subscription filters
export interface EventSubscriptionFilters {
    organizationId?: XID;
    userId?: XID;
    severity?: string[];
    excludeEventTypes?: string[];
}

// Webhook event payload
export interface WebhookEventPayload {
    id: XID;
    event: FrankAuthEvent;
    organizationId?: XID;
    timestamp: Timestamp;
    signature: string;
    attempt: number;
}

// Event analytics
export interface EventAnalytics {
    organizationId?: XID;
    timeRange: {
        start: Timestamp;
        end: Timestamp;
    };

    // Event counts
    totalEvents: number;
    eventTypeBreakdown: Record<string, number>;

    // User activity
    activeUsers: number;
    newUsers: number;

    // Authentication metrics
    loginAttempts: number;
    successfulLogins: number;
    failedLogins: number;
    mfaUsage: number;

    // Security metrics
    securityEvents: number;
    blockedAttempts: number;
    suspiciousActivity: number;

    // Time series data
    timeSeriesData: Array<{
        timestamp: Timestamp;
        eventCount: number;
        userCount: number;
        securityEventCount: number;
    }>;
}

// Event configuration
export interface EventConfig {
    // Event storage
    storage: {
        enabled: boolean;
        retentionDays: number;
        compressionEnabled: boolean;
    };

    // Event streaming
    streaming: {
        enabled: boolean;
        batchSize: number;
        flushInterval: number;
    };

    // Webhooks
    webhooks: {
        enabled: boolean;
        maxRetries: number;
        timeoutMs: number;
        signatureSecret: string;
    };

    // Analytics
    analytics: {
        enabled: boolean;
        aggregationInterval: number;
        realTimeEnabled: boolean;
    };

    // Security
    security: {
        encryptionEnabled: boolean;
        sanitizeUserData: boolean;
        allowEventExport: boolean;
    };
}

// Real-time event subscription
export interface RealtimeEventSubscription {
    id: XID;
    eventTypes: string[];
    callback: EventHandler;
    filters?: EventSubscriptionFilters;
    active: boolean;
}

// Event context for UI components
export interface EventContext {
    // Event emitter
    emitter: EventEmitter;

    // Subscribe to events
    subscribe: <T extends FrankAuthEvent>(
        eventType: T['type'],
        handler: EventHandler<T>,
        options?: { once?: boolean; organizationId?: XID }
    ) => () => void;

    // Emit events
    emit: <T extends FrankAuthEvent>(event: T) => void;

    // Event history
    getEventHistory: (filters: EventQueryFilters) => Promise<FrankAuthEvent[]>;

    // Analytics
    getAnalytics: (timeRange: { start: Timestamp; end: Timestamp }) => Promise<EventAnalytics>;
}

// Event middleware
export type EventMiddleware = (event: FrankAuthEvent, next: () => void) => void | Promise<void>

// Event pipeline
export interface EventPipeline {
    // Add middleware
    use(middleware: EventMiddleware): void;

    // Process event through pipeline
    process(event: FrankAuthEvent): Promise<void>;

    // Pipeline configuration
    configure(config: {
        errorHandling: 'throw' | 'log' | 'ignore';
        timeout?: number;
        retries?: number;
    }): void;
}