-- create "organizations" table
CREATE TABLE "organizations" ("id" character varying NOT NULL, "created_at" timestamptz NOT NULL, "updated_at" timestamptz NOT NULL, "deleted_at" timestamptz NULL, "name" character varying NOT NULL, "slug" character varying NOT NULL, "domains" jsonb NULL, "verified_domains" jsonb NULL, "domain" character varying NULL, "logo_url" character varying NULL, "plan" character varying NOT NULL DEFAULT 'free', "active" boolean NOT NULL DEFAULT true, "metadata" jsonb NULL, "trial_ends_at" timestamptz NULL, "trial_used" boolean NOT NULL DEFAULT false, "owner_id" character varying NULL, "org_type" character varying NOT NULL DEFAULT 'customer', "is_platform_organization" boolean NOT NULL DEFAULT false, "external_user_limit" bigint NOT NULL DEFAULT 5, "end_user_limit" bigint NOT NULL DEFAULT 100, "sso_enabled" boolean NOT NULL DEFAULT false, "sso_domain" character varying NULL, "subscription_id" character varying NULL, "customer_id" character varying NULL, "subscription_status" character varying NOT NULL DEFAULT 'trialing', "auth_service_enabled" boolean NOT NULL DEFAULT false, "auth_config" jsonb NULL, "auth_domain" character varying NULL, "api_request_limit" bigint NOT NULL DEFAULT 10000, "api_requests_used" bigint NOT NULL DEFAULT 0, "current_external_users" bigint NOT NULL DEFAULT 0, "current_end_users" bigint NOT NULL DEFAULT 0, PRIMARY KEY ("id"));
-- create index "organization_active" to table: "organizations"
CREATE INDEX "organization_active" ON "organizations" ("active");
-- create index "organization_auth_domain" to table: "organizations"
CREATE UNIQUE INDEX "organization_auth_domain" ON "organizations" ("auth_domain");
-- create index "organization_auth_service_enabled" to table: "organizations"
CREATE INDEX "organization_auth_service_enabled" ON "organizations" ("auth_service_enabled");
-- create index "organization_customer_id" to table: "organizations"
CREATE INDEX "organization_customer_id" ON "organizations" ("customer_id");
-- create index "organization_domain" to table: "organizations"
CREATE INDEX "organization_domain" ON "organizations" ("domain");
-- create index "organization_is_platform_organization" to table: "organizations"
CREATE INDEX "organization_is_platform_organization" ON "organizations" ("is_platform_organization");
-- create index "organization_org_type" to table: "organizations"
CREATE INDEX "organization_org_type" ON "organizations" ("org_type");
-- create index "organization_owner_id" to table: "organizations"
CREATE INDEX "organization_owner_id" ON "organizations" ("owner_id");
-- create index "organization_slug" to table: "organizations"
CREATE INDEX "organization_slug" ON "organizations" ("slug");
-- create index "organization_sso_domain" to table: "organizations"
CREATE INDEX "organization_sso_domain" ON "organizations" ("sso_domain");
-- create index "organization_subscription_id" to table: "organizations"
CREATE INDEX "organization_subscription_id" ON "organizations" ("subscription_id");
-- create index "organization_subscription_status" to table: "organizations"
CREATE INDEX "organization_subscription_status" ON "organizations" ("subscription_status");
-- create index "organizations_slug_key" to table: "organizations"
CREATE UNIQUE INDEX "organizations_slug_key" ON "organizations" ("slug");
-- create "sso_states" table
CREATE TABLE "sso_states" ("id" character varying NOT NULL, "created_at" timestamptz NOT NULL, "updated_at" timestamptz NOT NULL, "deleted_at" timestamptz NULL, "state" character varying NOT NULL, "data" character varying NOT NULL, "expires_at" timestamptz NOT NULL, "redirect_url" character varying NULL, PRIMARY KEY ("id"));
-- create index "sso_states_state_key" to table: "sso_states"
CREATE UNIQUE INDEX "sso_states_state_key" ON "sso_states" ("state");
-- create index "ssostate_expires_at" to table: "sso_states"
CREATE INDEX "ssostate_expires_at" ON "sso_states" ("expires_at");
-- create "users" table
CREATE TABLE "users" ("id" character varying NOT NULL, "created_at" timestamptz NOT NULL, "updated_at" timestamptz NOT NULL, "email" character varying NOT NULL, "phone_number" character varying NULL, "first_name" character varying NULL, "last_name" character varying NULL, "username" character varying NULL, "password_hash" character varying NULL, "email_verified" boolean NOT NULL DEFAULT false, "phone_verified" boolean NOT NULL DEFAULT false, "active" boolean NOT NULL DEFAULT true, "blocked" boolean NOT NULL DEFAULT false, "last_login" timestamptz NULL, "last_password_change" timestamptz NULL, "metadata" jsonb NULL, "profile_image_url" character varying NULL, "locale" character varying NOT NULL DEFAULT 'en', "timezone" character varying NULL, "user_type" character varying NOT NULL DEFAULT 'external', "primary_organization_id" character varying NULL, "is_platform_admin" boolean NOT NULL DEFAULT false, "auth_provider" character varying NOT NULL DEFAULT 'internal', "external_id" character varying NULL, "customer_id" character varying NULL, "custom_attributes" jsonb NULL, "created_by" character varying NULL, "password_reset_token_expires" timestamptz NULL, "password_reset_token" character varying NULL, "login_count" bigint NOT NULL DEFAULT 0, "last_login_ip" character varying NULL, "organization_id" character varying NULL, PRIMARY KEY ("id"), CONSTRAINT "users_organizations_users" FOREIGN KEY ("organization_id") REFERENCES "organizations" ("id") ON UPDATE NO ACTION ON DELETE SET NULL);
-- create index "user_active" to table: "users"
CREATE INDEX "user_active" ON "users" ("active");
-- create index "user_auth_provider" to table: "users"
CREATE INDEX "user_auth_provider" ON "users" ("auth_provider");
-- create index "user_auth_provider_external_id" to table: "users"
CREATE INDEX "user_auth_provider_external_id" ON "users" ("auth_provider", "external_id");
-- create index "user_blocked" to table: "users"
CREATE INDEX "user_blocked" ON "users" ("blocked");
-- create index "user_created_by" to table: "users"
CREATE INDEX "user_created_by" ON "users" ("created_by");
-- create index "user_customer_id" to table: "users"
CREATE INDEX "user_customer_id" ON "users" ("customer_id");
-- create index "user_email" to table: "users"
CREATE INDEX "user_email" ON "users" ("email");
-- create index "user_external_id" to table: "users"
CREATE INDEX "user_external_id" ON "users" ("external_id");
-- create index "user_is_platform_admin" to table: "users"
CREATE INDEX "user_is_platform_admin" ON "users" ("is_platform_admin");
-- create index "user_last_login" to table: "users"
CREATE INDEX "user_last_login" ON "users" ("last_login");
-- create index "user_organization_id" to table: "users"
CREATE INDEX "user_organization_id" ON "users" ("organization_id");
-- create index "user_organization_id_active" to table: "users"
CREATE INDEX "user_organization_id_active" ON "users" ("organization_id", "active");
-- create index "user_organization_id_user_type" to table: "users"
CREATE INDEX "user_organization_id_user_type" ON "users" ("organization_id", "user_type");
-- create index "user_organization_id_user_type_auth_provider_external_id" to table: "users"
CREATE UNIQUE INDEX "user_organization_id_user_type_auth_provider_external_id" ON "users" ("organization_id", "user_type", "auth_provider", "external_id");
-- create index "user_organization_id_user_type_email" to table: "users"
CREATE UNIQUE INDEX "user_organization_id_user_type_email" ON "users" ("organization_id", "user_type", "email");
-- create index "user_organization_id_user_type_username" to table: "users"
CREATE UNIQUE INDEX "user_organization_id_user_type_username" ON "users" ("organization_id", "user_type", "username");
-- create index "user_user_type" to table: "users"
CREATE INDEX "user_user_type" ON "users" ("user_type");
-- create index "user_user_type_active" to table: "users"
CREATE INDEX "user_user_type_active" ON "users" ("user_type", "active");
-- create index "user_user_type_email" to table: "users"
CREATE UNIQUE INDEX "user_user_type_email" ON "users" ("user_type", "email");
-- create index "user_username" to table: "users"
CREATE INDEX "user_username" ON "users" ("username");
-- create "sessions" table
CREATE TABLE "sessions" ("id" character varying NOT NULL, "created_at" timestamptz NOT NULL, "updated_at" timestamptz NOT NULL, "token" character varying NOT NULL, "ip_address" character varying NULL, "user_agent" character varying NULL, "device_id" character varying NULL, "location" character varying NULL, "organization_id" character varying NULL, "active" boolean NOT NULL DEFAULT true, "expires_at" timestamptz NOT NULL, "last_active_at" timestamptz NOT NULL, "metadata" jsonb NULL, "user_id" character varying NOT NULL, PRIMARY KEY ("id"), CONSTRAINT "sessions_users_sessions" FOREIGN KEY ("user_id") REFERENCES "users" ("id") ON UPDATE NO ACTION ON DELETE NO ACTION);
-- create index "session_expires_at" to table: "sessions"
CREATE INDEX "session_expires_at" ON "sessions" ("expires_at");
-- create index "session_organization_id" to table: "sessions"
CREATE INDEX "session_organization_id" ON "sessions" ("organization_id");
-- create index "session_token" to table: "sessions"
CREATE INDEX "session_token" ON "sessions" ("token");
-- create index "session_user_id" to table: "sessions"
CREATE INDEX "session_user_id" ON "sessions" ("user_id");
-- create index "sessions_token_key" to table: "sessions"
CREATE UNIQUE INDEX "sessions_token_key" ON "sessions" ("token");
-- create "activities" table
CREATE TABLE "activities" ("id" character varying NOT NULL, "resource_type" character varying NOT NULL DEFAULT 'common', "resource_id" character varying NOT NULL, "action" character varying NOT NULL, "category" character varying NOT NULL DEFAULT 'general', "source" character varying NULL, "endpoint" character varying NULL, "method" character varying NULL, "status_code" bigint NULL, "response_time" bigint NULL, "ip_address" character varying NULL, "user_agent" character varying NULL, "location" character varying NULL, "success" boolean NOT NULL DEFAULT true, "error" character varying NULL, "error_code" character varying NULL, "size" bigint NULL, "count" bigint NULL, "value" double precision NULL, "timestamp" timestamptz NOT NULL, "expires_at" timestamptz NULL, "metadata" jsonb NULL, "tags" jsonb NULL, "organization_id" character varying NULL, "session_id" character varying NULL, "user_id" character varying NULL, PRIMARY KEY ("id"), CONSTRAINT "activities_organizations_activities" FOREIGN KEY ("organization_id") REFERENCES "organizations" ("id") ON UPDATE NO ACTION ON DELETE SET NULL, CONSTRAINT "activities_sessions_activities" FOREIGN KEY ("session_id") REFERENCES "sessions" ("id") ON UPDATE NO ACTION ON DELETE SET NULL, CONSTRAINT "activities_users_activities" FOREIGN KEY ("user_id") REFERENCES "users" ("id") ON UPDATE NO ACTION ON DELETE SET NULL);
-- create index "activity_action" to table: "activities"
CREATE INDEX "activity_action" ON "activities" ("action");
-- create index "activity_category" to table: "activities"
CREATE INDEX "activity_category" ON "activities" ("category");
-- create index "activity_endpoint" to table: "activities"
CREATE INDEX "activity_endpoint" ON "activities" ("endpoint");
-- create index "activity_expires_at" to table: "activities"
CREATE INDEX "activity_expires_at" ON "activities" ("expires_at");
-- create index "activity_ip_address" to table: "activities"
CREATE INDEX "activity_ip_address" ON "activities" ("ip_address");
-- create index "activity_method" to table: "activities"
CREATE INDEX "activity_method" ON "activities" ("method");
-- create index "activity_organization_id" to table: "activities"
CREATE INDEX "activity_organization_id" ON "activities" ("organization_id");
-- create index "activity_organization_id_resource_type_timestamp" to table: "activities"
CREATE INDEX "activity_organization_id_resource_type_timestamp" ON "activities" ("organization_id", "resource_type", "timestamp");
-- create index "activity_organization_id_timestamp" to table: "activities"
CREATE INDEX "activity_organization_id_timestamp" ON "activities" ("organization_id", "timestamp");
-- create index "activity_resource_type_action" to table: "activities"
CREATE INDEX "activity_resource_type_action" ON "activities" ("resource_type", "action");
-- create index "activity_resource_type_action_timestamp" to table: "activities"
CREATE INDEX "activity_resource_type_action_timestamp" ON "activities" ("resource_type", "action", "timestamp");
-- create index "activity_resource_type_resource_id" to table: "activities"
CREATE INDEX "activity_resource_type_resource_id" ON "activities" ("resource_type", "resource_id");
-- create index "activity_resource_type_resource_id_timestamp" to table: "activities"
CREATE INDEX "activity_resource_type_resource_id_timestamp" ON "activities" ("resource_type", "resource_id", "timestamp");
-- create index "activity_resource_type_timestamp_success" to table: "activities"
CREATE INDEX "activity_resource_type_timestamp_success" ON "activities" ("resource_type", "timestamp", "success");
-- create index "activity_session_id" to table: "activities"
CREATE INDEX "activity_session_id" ON "activities" ("session_id");
-- create index "activity_source" to table: "activities"
CREATE INDEX "activity_source" ON "activities" ("source");
-- create index "activity_status_code" to table: "activities"
CREATE INDEX "activity_status_code" ON "activities" ("status_code");
-- create index "activity_success" to table: "activities"
CREATE INDEX "activity_success" ON "activities" ("success");
-- create index "activity_timestamp" to table: "activities"
CREATE INDEX "activity_timestamp" ON "activities" ("timestamp");
-- create index "activity_timestamp_action" to table: "activities"
CREATE INDEX "activity_timestamp_action" ON "activities" ("timestamp", "action");
-- create index "activity_timestamp_resource_type" to table: "activities"
CREATE INDEX "activity_timestamp_resource_type" ON "activities" ("timestamp", "resource_type");
-- create index "activity_timestamp_success" to table: "activities"
CREATE INDEX "activity_timestamp_success" ON "activities" ("timestamp", "success");
-- create index "activity_user_agent" to table: "activities"
CREATE INDEX "activity_user_agent" ON "activities" ("user_agent");
-- create index "activity_user_id" to table: "activities"
CREATE INDEX "activity_user_id" ON "activities" ("user_id");
-- create index "activity_user_id_resource_type_timestamp" to table: "activities"
CREATE INDEX "activity_user_id_resource_type_timestamp" ON "activities" ("user_id", "resource_type", "timestamp");
-- create index "activity_user_id_timestamp" to table: "activities"
CREATE INDEX "activity_user_id_timestamp" ON "activities" ("user_id", "timestamp");
-- create "api_keys" table
CREATE TABLE "api_keys" ("id" character varying NOT NULL, "created_at" timestamptz NOT NULL, "updated_at" timestamptz NOT NULL, "deleted_at" timestamptz NULL, "name" character varying NOT NULL, "key" character varying NOT NULL, "hashed_key" character varying NOT NULL, "type" character varying NOT NULL DEFAULT 'server', "active" boolean NOT NULL DEFAULT true, "permissions" jsonb NULL, "scopes" jsonb NULL, "ip_whitelist" jsonb NULL, "rate_limits" jsonb NULL, "metadata" jsonb NULL, "last_used" timestamptz NULL, "expires_at" timestamptz NULL, "organization_id" character varying NULL, "user_id" character varying NULL, PRIMARY KEY ("id"), CONSTRAINT "api_keys_organizations_api_keys" FOREIGN KEY ("organization_id") REFERENCES "organizations" ("id") ON UPDATE NO ACTION ON DELETE SET NULL, CONSTRAINT "api_keys_users_api_keys" FOREIGN KEY ("user_id") REFERENCES "users" ("id") ON UPDATE NO ACTION ON DELETE SET NULL);
-- create index "api_keys_hashed_key_key" to table: "api_keys"
CREATE UNIQUE INDEX "api_keys_hashed_key_key" ON "api_keys" ("hashed_key");
-- create index "api_keys_key_key" to table: "api_keys"
CREATE UNIQUE INDEX "api_keys_key_key" ON "api_keys" ("key");
-- create index "apikey_active" to table: "api_keys"
CREATE INDEX "apikey_active" ON "api_keys" ("active");
-- create index "apikey_active_expires_at" to table: "api_keys"
CREATE INDEX "apikey_active_expires_at" ON "api_keys" ("active", "expires_at");
-- create index "apikey_created_at" to table: "api_keys"
CREATE INDEX "apikey_created_at" ON "api_keys" ("created_at");
-- create index "apikey_expires_at" to table: "api_keys"
CREATE INDEX "apikey_expires_at" ON "api_keys" ("expires_at");
-- create index "apikey_hashed_key" to table: "api_keys"
CREATE INDEX "apikey_hashed_key" ON "api_keys" ("hashed_key");
-- create index "apikey_last_used" to table: "api_keys"
CREATE INDEX "apikey_last_used" ON "api_keys" ("last_used");
-- create index "apikey_name" to table: "api_keys"
CREATE INDEX "apikey_name" ON "api_keys" ("name");
-- create index "apikey_organization_id" to table: "api_keys"
CREATE INDEX "apikey_organization_id" ON "api_keys" ("organization_id");
-- create index "apikey_organization_id_active" to table: "api_keys"
CREATE INDEX "apikey_organization_id_active" ON "api_keys" ("organization_id", "active");
-- create index "apikey_organization_id_type" to table: "api_keys"
CREATE INDEX "apikey_organization_id_type" ON "api_keys" ("organization_id", "type");
-- create index "apikey_type" to table: "api_keys"
CREATE INDEX "apikey_type" ON "api_keys" ("type");
-- create index "apikey_updated_at" to table: "api_keys"
CREATE INDEX "apikey_updated_at" ON "api_keys" ("updated_at");
-- create index "apikey_user_id" to table: "api_keys"
CREATE INDEX "apikey_user_id" ON "api_keys" ("user_id");
-- create index "apikey_user_id_active" to table: "api_keys"
CREATE INDEX "apikey_user_id_active" ON "api_keys" ("user_id", "active");
-- create index "apikey_user_id_type" to table: "api_keys"
CREATE INDEX "apikey_user_id_type" ON "api_keys" ("user_id", "type");
-- create "api_key_activities" table
CREATE TABLE "api_key_activities" ("id" character varying NOT NULL, "action" character varying NOT NULL, "endpoint" character varying NULL, "method" character varying NULL, "status_code" bigint NULL, "response_time" bigint NULL, "ip_address" character varying NULL, "user_agent" character varying NULL, "success" boolean NOT NULL DEFAULT true, "error" character varying NULL, "timestamp" timestamptz NOT NULL, "metadata" jsonb NULL, "key_id" character varying NOT NULL, PRIMARY KEY ("id"), CONSTRAINT "api_key_activities_api_keys_activities" FOREIGN KEY ("key_id") REFERENCES "api_keys" ("id") ON UPDATE NO ACTION ON DELETE NO ACTION);
-- create index "apikeyactivity_action" to table: "api_key_activities"
CREATE INDEX "apikeyactivity_action" ON "api_key_activities" ("action");
-- create index "apikeyactivity_action_timestamp" to table: "api_key_activities"
CREATE INDEX "apikeyactivity_action_timestamp" ON "api_key_activities" ("action", "timestamp");
-- create index "apikeyactivity_endpoint" to table: "api_key_activities"
CREATE INDEX "apikeyactivity_endpoint" ON "api_key_activities" ("endpoint");
-- create index "apikeyactivity_ip_address" to table: "api_key_activities"
CREATE INDEX "apikeyactivity_ip_address" ON "api_key_activities" ("ip_address");
-- create index "apikeyactivity_key_id" to table: "api_key_activities"
CREATE INDEX "apikeyactivity_key_id" ON "api_key_activities" ("key_id");
-- create index "apikeyactivity_key_id_action" to table: "api_key_activities"
CREATE INDEX "apikeyactivity_key_id_action" ON "api_key_activities" ("key_id", "action");
-- create index "apikeyactivity_key_id_endpoint" to table: "api_key_activities"
CREATE INDEX "apikeyactivity_key_id_endpoint" ON "api_key_activities" ("key_id", "endpoint");
-- create index "apikeyactivity_key_id_success" to table: "api_key_activities"
CREATE INDEX "apikeyactivity_key_id_success" ON "api_key_activities" ("key_id", "success");
-- create index "apikeyactivity_key_id_timestamp" to table: "api_key_activities"
CREATE INDEX "apikeyactivity_key_id_timestamp" ON "api_key_activities" ("key_id", "timestamp");
-- create index "apikeyactivity_method" to table: "api_key_activities"
CREATE INDEX "apikeyactivity_method" ON "api_key_activities" ("method");
-- create index "apikeyactivity_status_code" to table: "api_key_activities"
CREATE INDEX "apikeyactivity_status_code" ON "api_key_activities" ("status_code");
-- create index "apikeyactivity_success" to table: "api_key_activities"
CREATE INDEX "apikeyactivity_success" ON "api_key_activities" ("success");
-- create index "apikeyactivity_success_timestamp" to table: "api_key_activities"
CREATE INDEX "apikeyactivity_success_timestamp" ON "api_key_activities" ("success", "timestamp");
-- create index "apikeyactivity_timestamp" to table: "api_key_activities"
CREATE INDEX "apikeyactivity_timestamp" ON "api_key_activities" ("timestamp");
-- create index "apikeyactivity_timestamp_action" to table: "api_key_activities"
CREATE INDEX "apikeyactivity_timestamp_action" ON "api_key_activities" ("timestamp", "action");
-- create index "apikeyactivity_timestamp_key_id" to table: "api_key_activities"
CREATE INDEX "apikeyactivity_timestamp_key_id" ON "api_key_activities" ("timestamp", "key_id");
-- create index "apikeyactivity_timestamp_success" to table: "api_key_activities"
CREATE INDEX "apikeyactivity_timestamp_success" ON "api_key_activities" ("timestamp", "success");
-- create "audits" table
CREATE TABLE "audits" ("id" character varying NOT NULL, "deleted_at" timestamptz NULL, "created_at" timestamptz NOT NULL, "updated_at" timestamptz NOT NULL, "action" character varying NOT NULL, "resource_type" character varying NOT NULL, "resource_id" character varying NULL, "status" character varying NOT NULL, "ip_address" character varying NULL, "user_agent" character varying NULL, "location" character varying NULL, "device_id" character varying NULL, "request_id" character varying NULL, "error_code" character varying NULL, "error_message" character varying NULL, "description" character varying NULL, "metadata" jsonb NULL, "old_values" jsonb NULL, "current_values" jsonb NULL, "timestamp" timestamptz NOT NULL, "organization_id" character varying NULL, "session_id" character varying NULL, "user_id" character varying NULL, PRIMARY KEY ("id"), CONSTRAINT "audits_organizations_audit_logs" FOREIGN KEY ("organization_id") REFERENCES "organizations" ("id") ON UPDATE NO ACTION ON DELETE SET NULL, CONSTRAINT "audits_sessions_audit_logs" FOREIGN KEY ("session_id") REFERENCES "sessions" ("id") ON UPDATE NO ACTION ON DELETE SET NULL, CONSTRAINT "audits_users_audit_logs" FOREIGN KEY ("user_id") REFERENCES "users" ("id") ON UPDATE NO ACTION ON DELETE SET NULL);
-- create index "audit_action" to table: "audits"
CREATE INDEX "audit_action" ON "audits" ("action");
-- create index "audit_action_timestamp" to table: "audits"
CREATE INDEX "audit_action_timestamp" ON "audits" ("action", "timestamp");
-- create index "audit_ip_address_timestamp" to table: "audits"
CREATE INDEX "audit_ip_address_timestamp" ON "audits" ("ip_address", "timestamp");
-- create index "audit_organization_id" to table: "audits"
CREATE INDEX "audit_organization_id" ON "audits" ("organization_id");
-- create index "audit_organization_id_timestamp" to table: "audits"
CREATE INDEX "audit_organization_id_timestamp" ON "audits" ("organization_id", "timestamp");
-- create index "audit_resource_id" to table: "audits"
CREATE INDEX "audit_resource_id" ON "audits" ("resource_id");
-- create index "audit_resource_type" to table: "audits"
CREATE INDEX "audit_resource_type" ON "audits" ("resource_type");
-- create index "audit_resource_type_resource_id" to table: "audits"
CREATE INDEX "audit_resource_type_resource_id" ON "audits" ("resource_type", "resource_id");
-- create index "audit_session_id" to table: "audits"
CREATE INDEX "audit_session_id" ON "audits" ("session_id");
-- create index "audit_status" to table: "audits"
CREATE INDEX "audit_status" ON "audits" ("status");
-- create index "audit_timestamp" to table: "audits"
CREATE INDEX "audit_timestamp" ON "audits" ("timestamp");
-- create index "audit_user_id" to table: "audits"
CREATE INDEX "audit_user_id" ON "audits" ("user_id");
-- create index "audit_user_id_timestamp" to table: "audits"
CREATE INDEX "audit_user_id_timestamp" ON "audits" ("user_id", "timestamp");
-- create "email_templates" table
CREATE TABLE "email_templates" ("id" character varying NOT NULL, "created_at" timestamptz NOT NULL, "updated_at" timestamptz NOT NULL, "deleted_at" timestamptz NULL, "name" character varying NOT NULL, "subject" character varying NOT NULL, "type" character varying NOT NULL, "html_content" character varying NOT NULL, "text_content" character varying NULL, "active" boolean NOT NULL DEFAULT true, "system" boolean NOT NULL DEFAULT false, "locale" character varying NOT NULL DEFAULT 'en', "metadata" jsonb NULL, "organization_id" character varying NULL, PRIMARY KEY ("id"), CONSTRAINT "email_templates_organizations_email_templates" FOREIGN KEY ("organization_id") REFERENCES "organizations" ("id") ON UPDATE NO ACTION ON DELETE SET NULL);
-- create index "emailtemplate_organization_id" to table: "email_templates"
CREATE INDEX "emailtemplate_organization_id" ON "email_templates" ("organization_id");
-- create index "emailtemplate_organization_id_type_locale" to table: "email_templates"
CREATE UNIQUE INDEX "emailtemplate_organization_id_type_locale" ON "email_templates" ("organization_id", "type", "locale");
-- create index "emailtemplate_type" to table: "email_templates"
CREATE INDEX "emailtemplate_type" ON "email_templates" ("type");
-- create "identity_providers" table
CREATE TABLE "identity_providers" ("id" character varying NOT NULL, "created_at" timestamptz NOT NULL, "updated_at" timestamptz NOT NULL, "deleted_at" timestamptz NULL, "name" character varying NOT NULL, "provider_type" character varying NOT NULL, "client_id" character varying NULL, "client_secret" character varying NULL, "issuer" character varying NULL, "authorization_endpoint" character varying NULL, "token_endpoint" character varying NULL, "userinfo_endpoint" character varying NULL, "jwks_uri" character varying NULL, "metadata_url" character varying NULL, "redirect_uri" character varying NULL, "certificate" character varying NULL, "private_key" character varying NULL, "active" boolean NOT NULL DEFAULT true, "enabled" boolean NOT NULL DEFAULT true, "primary" boolean NOT NULL DEFAULT false, "auto_provision" boolean NOT NULL DEFAULT false, "default_role" character varying NULL, "domain" character varying NULL, "icon_url" character varying NULL, "button_text" character varying NULL, "protocol" character varying NULL, "domains" jsonb NULL, "attributes_mapping" jsonb NULL, "metadata" jsonb NULL, "organization_id" character varying NOT NULL, PRIMARY KEY ("id"), CONSTRAINT "identity_providers_organizations_identity_providers" FOREIGN KEY ("organization_id") REFERENCES "organizations" ("id") ON UPDATE NO ACTION ON DELETE NO ACTION);
-- create index "identityprovider_organization_id" to table: "identity_providers"
CREATE INDEX "identityprovider_organization_id" ON "identity_providers" ("organization_id");
-- create index "identityprovider_provider_type" to table: "identity_providers"
CREATE INDEX "identityprovider_provider_type" ON "identity_providers" ("provider_type");
-- create "roles" table
CREATE TABLE "roles" ("id" character varying NOT NULL, "created_at" timestamptz NOT NULL, "updated_at" timestamptz NOT NULL, "deleted_at" timestamptz NULL, "name" character varying NOT NULL, "display_name" character varying NULL, "description" character varying NULL, "role_type" character varying NOT NULL, "application_id" character varying NULL, "system" boolean NOT NULL DEFAULT false, "is_default" boolean NOT NULL DEFAULT false, "priority" bigint NOT NULL DEFAULT 0, "color" character varying NULL, "applicable_user_types" jsonb NOT NULL, "created_by" character varying NULL, "active" boolean NOT NULL DEFAULT true, "organization_id" character varying NULL, "parent_id" character varying NULL, PRIMARY KEY ("id"), CONSTRAINT "roles_organizations_roles" FOREIGN KEY ("organization_id") REFERENCES "organizations" ("id") ON UPDATE NO ACTION ON DELETE SET NULL, CONSTRAINT "roles_roles_children" FOREIGN KEY ("parent_id") REFERENCES "roles" ("id") ON UPDATE NO ACTION ON DELETE SET NULL);
-- create index "role_active" to table: "roles"
CREATE INDEX "role_active" ON "roles" ("active");
-- create index "role_application_id" to table: "roles"
CREATE INDEX "role_application_id" ON "roles" ("application_id");
-- create index "role_created_by" to table: "roles"
CREATE INDEX "role_created_by" ON "roles" ("created_by");
-- create index "role_is_default" to table: "roles"
CREATE INDEX "role_is_default" ON "roles" ("is_default");
-- create index "role_name_role_type_organization_id_application_id" to table: "roles"
CREATE UNIQUE INDEX "role_name_role_type_organization_id_application_id" ON "roles" ("name", "role_type", "organization_id", "application_id");
-- create index "role_organization_id" to table: "roles"
CREATE INDEX "role_organization_id" ON "roles" ("organization_id");
-- create index "role_organization_id_is_default" to table: "roles"
CREATE INDEX "role_organization_id_is_default" ON "roles" ("organization_id", "is_default");
-- create index "role_parent_id" to table: "roles"
CREATE INDEX "role_parent_id" ON "roles" ("parent_id");
-- create index "role_parent_id_active" to table: "roles"
CREATE INDEX "role_parent_id_active" ON "roles" ("parent_id", "active");
-- create index "role_priority" to table: "roles"
CREATE INDEX "role_priority" ON "roles" ("priority");
-- create index "role_role_type" to table: "roles"
CREATE INDEX "role_role_type" ON "roles" ("role_type");
-- create index "role_role_type_application_id" to table: "roles"
CREATE INDEX "role_role_type_application_id" ON "roles" ("role_type", "application_id");
-- create index "role_role_type_organization_id" to table: "roles"
CREATE INDEX "role_role_type_organization_id" ON "roles" ("role_type", "organization_id");
-- create index "role_system" to table: "roles"
CREATE INDEX "role_system" ON "roles" ("system");
-- create "memberships" table
CREATE TABLE "memberships" ("id" character varying NOT NULL, "created_at" timestamptz NOT NULL, "updated_at" timestamptz NOT NULL, "deleted_at" timestamptz NULL, "email" character varying NOT NULL, "status" character varying NOT NULL DEFAULT 'pending', "invited_at" timestamptz NOT NULL, "joined_at" timestamptz NULL, "expires_at" timestamptz NULL, "invitation_token" character varying NULL, "is_billing_contact" boolean NOT NULL DEFAULT false, "is_primary_contact" boolean NOT NULL DEFAULT false, "left_at" timestamptz NULL, "metadata" jsonb NULL, "custom_fields" jsonb NULL, "organization_id" character varying NOT NULL, "role_id" character varying NOT NULL, "user_id" character varying NOT NULL, "invited_by" character varying NULL, PRIMARY KEY ("id"), CONSTRAINT "memberships_organizations_memberships" FOREIGN KEY ("organization_id") REFERENCES "organizations" ("id") ON UPDATE NO ACTION ON DELETE NO ACTION, CONSTRAINT "memberships_roles_memberships" FOREIGN KEY ("role_id") REFERENCES "roles" ("id") ON UPDATE NO ACTION ON DELETE NO ACTION, CONSTRAINT "memberships_users_memberships" FOREIGN KEY ("user_id") REFERENCES "users" ("id") ON UPDATE NO ACTION ON DELETE NO ACTION, CONSTRAINT "memberships_users_sent_invitations" FOREIGN KEY ("invited_by") REFERENCES "users" ("id") ON UPDATE NO ACTION ON DELETE SET NULL);
-- create index "membership_expires_at" to table: "memberships"
CREATE INDEX "membership_expires_at" ON "memberships" ("expires_at");
-- create index "membership_invitation_token" to table: "memberships"
CREATE INDEX "membership_invitation_token" ON "memberships" ("invitation_token");
-- create index "membership_invited_by" to table: "memberships"
CREATE INDEX "membership_invited_by" ON "memberships" ("invited_by");
-- create index "membership_organization_id" to table: "memberships"
CREATE INDEX "membership_organization_id" ON "memberships" ("organization_id");
-- create index "membership_role_id" to table: "memberships"
CREATE INDEX "membership_role_id" ON "memberships" ("role_id");
-- create index "membership_status" to table: "memberships"
CREATE INDEX "membership_status" ON "memberships" ("status");
-- create index "membership_user_id" to table: "memberships"
CREATE INDEX "membership_user_id" ON "memberships" ("user_id");
-- create index "membership_user_id_organization_id" to table: "memberships"
CREATE UNIQUE INDEX "membership_user_id_organization_id" ON "memberships" ("user_id", "organization_id");
-- create "mf_as" table
CREATE TABLE "mf_as" ("id" character varying NOT NULL, "created_at" timestamptz NOT NULL, "updated_at" timestamptz NOT NULL, "deleted_at" timestamptz NULL, "method" character varying NOT NULL, "secret" character varying NOT NULL, "verified" boolean NOT NULL DEFAULT false, "active" boolean NOT NULL DEFAULT true, "backup_codes" jsonb NULL, "phone_number" character varying NULL, "email" character varying NULL, "last_used" timestamptz NULL, "metadata" jsonb NULL, "user_id" character varying NOT NULL, PRIMARY KEY ("id"), CONSTRAINT "mf_as_users_mfa_methods" FOREIGN KEY ("user_id") REFERENCES "users" ("id") ON UPDATE NO ACTION ON DELETE NO ACTION);
-- create index "mfa_method_user_id" to table: "mf_as"
CREATE UNIQUE INDEX "mfa_method_user_id" ON "mf_as" ("method", "user_id");
-- create index "mfa_user_id" to table: "mf_as"
CREATE INDEX "mfa_user_id" ON "mf_as" ("user_id");
-- create "oauth_clients" table
CREATE TABLE "oauth_clients" ("id" character varying NOT NULL, "created_at" timestamptz NOT NULL, "updated_at" timestamptz NOT NULL, "deleted_at" timestamptz NULL, "client_id" character varying NOT NULL, "client_secret" character varying NOT NULL, "client_name" character varying NOT NULL, "client_description" character varying NULL, "client_uri" character varying NULL, "logo_uri" character varying NULL, "redirect_uris" jsonb NOT NULL, "post_logout_redirect_uris" jsonb NULL, "public" boolean NOT NULL DEFAULT false, "active" boolean NOT NULL DEFAULT true, "allowed_cors_origins" jsonb NULL, "allowed_grant_types" jsonb NOT NULL, "token_expiry_seconds" bigint NOT NULL DEFAULT 3600, "refresh_token_expiry_seconds" bigint NOT NULL DEFAULT 2592000, "auth_code_expiry_seconds" bigint NOT NULL DEFAULT 600, "requires_pkce" boolean NOT NULL DEFAULT true, "requires_consent" boolean NOT NULL DEFAULT true, "organization_id" character varying NULL, PRIMARY KEY ("id"), CONSTRAINT "oauth_clients_organizations_oauth_clients" FOREIGN KEY ("organization_id") REFERENCES "organizations" ("id") ON UPDATE NO ACTION ON DELETE SET NULL);
-- create index "oauth_clients_client_id_key" to table: "oauth_clients"
CREATE UNIQUE INDEX "oauth_clients_client_id_key" ON "oauth_clients" ("client_id");
-- create index "oauthclient_client_id" to table: "oauth_clients"
CREATE INDEX "oauthclient_client_id" ON "oauth_clients" ("client_id");
-- create index "oauthclient_organization_id" to table: "oauth_clients"
CREATE INDEX "oauthclient_organization_id" ON "oauth_clients" ("organization_id");
-- create "oauth_authorizations" table
CREATE TABLE "oauth_authorizations" ("id" character varying NOT NULL, "created_at" timestamptz NOT NULL, "updated_at" timestamptz NOT NULL, "deleted_at" timestamptz NULL, "organization_id" character varying NULL, "code" character varying NULL, "code_challenge" character varying NULL, "code_challenge_method" character varying NULL, "redirect_uri" character varying NOT NULL, "scope_names" jsonb NULL, "used" boolean NOT NULL DEFAULT false, "used_at" timestamptz NOT NULL, "expires_at" timestamptz NOT NULL, "state" character varying NULL, "nonce" character varying NULL, "user_agent" character varying NULL, "ip_address" character varying NULL, "client_id" character varying NOT NULL, "user_id" character varying NOT NULL, PRIMARY KEY ("id"), CONSTRAINT "oauth_authorizations_oauth_clients_authorizations" FOREIGN KEY ("client_id") REFERENCES "oauth_clients" ("id") ON UPDATE NO ACTION ON DELETE NO ACTION, CONSTRAINT "oauth_authorizations_users_oauth_authorizations" FOREIGN KEY ("user_id") REFERENCES "users" ("id") ON UPDATE NO ACTION ON DELETE NO ACTION);
-- create index "oauth_authorizations_code_key" to table: "oauth_authorizations"
CREATE UNIQUE INDEX "oauth_authorizations_code_key" ON "oauth_authorizations" ("code");
-- create index "oauthauthorization_client_id" to table: "oauth_authorizations"
CREATE INDEX "oauthauthorization_client_id" ON "oauth_authorizations" ("client_id");
-- create index "oauthauthorization_code" to table: "oauth_authorizations"
CREATE INDEX "oauthauthorization_code" ON "oauth_authorizations" ("code");
-- create index "oauthauthorization_expires_at" to table: "oauth_authorizations"
CREATE INDEX "oauthauthorization_expires_at" ON "oauth_authorizations" ("expires_at");
-- create index "oauthauthorization_organization_id" to table: "oauth_authorizations"
CREATE INDEX "oauthauthorization_organization_id" ON "oauth_authorizations" ("organization_id");
-- create index "oauthauthorization_user_id" to table: "oauth_authorizations"
CREATE INDEX "oauthauthorization_user_id" ON "oauth_authorizations" ("user_id");
-- create "oauth_scopes" table
CREATE TABLE "oauth_scopes" ("id" character varying NOT NULL, "created_at" timestamptz NOT NULL, "updated_at" timestamptz NOT NULL, "deleted_at" timestamptz NULL, "name" character varying NOT NULL, "description" character varying NOT NULL, "default_scope" boolean NOT NULL DEFAULT false, "public" boolean NOT NULL DEFAULT true, PRIMARY KEY ("id"));
-- create index "oauth_scopes_name_key" to table: "oauth_scopes"
CREATE UNIQUE INDEX "oauth_scopes_name_key" ON "oauth_scopes" ("name");
-- create index "oauthscope_name" to table: "oauth_scopes"
CREATE INDEX "oauthscope_name" ON "oauth_scopes" ("name");
-- create "oauth_authorization_scopes" table
CREATE TABLE "oauth_authorization_scopes" ("oauth_authorization_id" character varying NOT NULL, "oauth_scope_id" character varying NOT NULL, PRIMARY KEY ("oauth_authorization_id", "oauth_scope_id"), CONSTRAINT "oauth_authorization_scopes_oauth_authorization_id" FOREIGN KEY ("oauth_authorization_id") REFERENCES "oauth_authorizations" ("id") ON UPDATE NO ACTION ON DELETE CASCADE, CONSTRAINT "oauth_authorization_scopes_oauth_scope_id" FOREIGN KEY ("oauth_scope_id") REFERENCES "oauth_scopes" ("id") ON UPDATE NO ACTION ON DELETE CASCADE);
-- create "oauth_client_scopes" table
CREATE TABLE "oauth_client_scopes" ("oauth_client_id" character varying NOT NULL, "oauth_scope_id" character varying NOT NULL, PRIMARY KEY ("oauth_client_id", "oauth_scope_id"), CONSTRAINT "oauth_client_scopes_oauth_client_id" FOREIGN KEY ("oauth_client_id") REFERENCES "oauth_clients" ("id") ON UPDATE NO ACTION ON DELETE CASCADE, CONSTRAINT "oauth_client_scopes_oauth_scope_id" FOREIGN KEY ("oauth_scope_id") REFERENCES "oauth_scopes" ("id") ON UPDATE NO ACTION ON DELETE CASCADE);
-- create "oauth_tokens" table
CREATE TABLE "oauth_tokens" ("id" character varying NOT NULL, "created_at" timestamptz NOT NULL, "updated_at" timestamptz NOT NULL, "deleted_at" timestamptz NULL, "access_token" character varying NOT NULL, "refresh_token" character varying NULL, "token_type" character varying NOT NULL DEFAULT 'bearer', "organization_id" character varying NULL, "scope_names" jsonb NULL, "expires_in" bigint NOT NULL DEFAULT 3600, "expires_at" timestamptz NOT NULL, "refresh_token_expires_at" timestamptz NULL, "revoked" boolean NOT NULL DEFAULT false, "revoked_at" timestamptz NULL, "ip_address" character varying NULL, "user_agent" character varying NULL, "client_id" character varying NOT NULL, "user_id" character varying NOT NULL, PRIMARY KEY ("id"), CONSTRAINT "oauth_tokens_oauth_clients_tokens" FOREIGN KEY ("client_id") REFERENCES "oauth_clients" ("id") ON UPDATE NO ACTION ON DELETE NO ACTION, CONSTRAINT "oauth_tokens_users_oauth_tokens" FOREIGN KEY ("user_id") REFERENCES "users" ("id") ON UPDATE NO ACTION ON DELETE NO ACTION);
-- create index "oauth_tokens_access_token_key" to table: "oauth_tokens"
CREATE UNIQUE INDEX "oauth_tokens_access_token_key" ON "oauth_tokens" ("access_token");
-- create index "oauth_tokens_refresh_token_key" to table: "oauth_tokens"
CREATE UNIQUE INDEX "oauth_tokens_refresh_token_key" ON "oauth_tokens" ("refresh_token");
-- create index "oauthtoken_access_token" to table: "oauth_tokens"
CREATE INDEX "oauthtoken_access_token" ON "oauth_tokens" ("access_token");
-- create index "oauthtoken_client_id" to table: "oauth_tokens"
CREATE INDEX "oauthtoken_client_id" ON "oauth_tokens" ("client_id");
-- create index "oauthtoken_expires_at" to table: "oauth_tokens"
CREATE INDEX "oauthtoken_expires_at" ON "oauth_tokens" ("expires_at");
-- create index "oauthtoken_organization_id" to table: "oauth_tokens"
CREATE INDEX "oauthtoken_organization_id" ON "oauth_tokens" ("organization_id");
-- create index "oauthtoken_refresh_token" to table: "oauth_tokens"
CREATE INDEX "oauthtoken_refresh_token" ON "oauth_tokens" ("refresh_token");
-- create index "oauthtoken_user_id" to table: "oauth_tokens"
CREATE INDEX "oauthtoken_user_id" ON "oauth_tokens" ("user_id");
-- create "oauth_token_scopes" table
CREATE TABLE "oauth_token_scopes" ("oauth_token_id" character varying NOT NULL, "oauth_scope_id" character varying NOT NULL, PRIMARY KEY ("oauth_token_id", "oauth_scope_id"), CONSTRAINT "oauth_token_scopes_oauth_scope_id" FOREIGN KEY ("oauth_scope_id") REFERENCES "oauth_scopes" ("id") ON UPDATE NO ACTION ON DELETE CASCADE, CONSTRAINT "oauth_token_scopes_oauth_token_id" FOREIGN KEY ("oauth_token_id") REFERENCES "oauth_tokens" ("id") ON UPDATE NO ACTION ON DELETE CASCADE);
-- create "feature_flags" table
CREATE TABLE "feature_flags" ("id" character varying NOT NULL, "created_at" timestamptz NOT NULL, "updated_at" timestamptz NOT NULL, "deleted_at" timestamptz NULL, "name" character varying NOT NULL, "key" character varying NOT NULL, "description" character varying NULL, "enabled" boolean NOT NULL DEFAULT false, "is_premium" boolean NOT NULL DEFAULT false, "component" character varying NOT NULL, PRIMARY KEY ("id"));
-- create index "feature_flags_key_key" to table: "feature_flags"
CREATE UNIQUE INDEX "feature_flags_key_key" ON "feature_flags" ("key");
-- create index "feature_flags_name_key" to table: "feature_flags"
CREATE UNIQUE INDEX "feature_flags_name_key" ON "feature_flags" ("name");
-- create index "featureflag_component" to table: "feature_flags"
CREATE INDEX "featureflag_component" ON "feature_flags" ("component");
-- create index "featureflag_key" to table: "feature_flags"
CREATE INDEX "featureflag_key" ON "feature_flags" ("key");
-- create "organization_features" table
CREATE TABLE "organization_features" ("id" character varying NOT NULL, "created_at" timestamptz NOT NULL, "updated_at" timestamptz NOT NULL, "deleted_at" timestamptz NULL, "enabled" boolean NOT NULL DEFAULT true, "settings" jsonb NULL, "feature_id" character varying NOT NULL, "organization_id" character varying NOT NULL, PRIMARY KEY ("id"), CONSTRAINT "organization_features_feature_flags_organization_features" FOREIGN KEY ("feature_id") REFERENCES "feature_flags" ("id") ON UPDATE NO ACTION ON DELETE NO ACTION, CONSTRAINT "organization_features_organizations_feature_flags" FOREIGN KEY ("organization_id") REFERENCES "organizations" ("id") ON UPDATE NO ACTION ON DELETE NO ACTION);
-- create index "organizationfeature_feature_id" to table: "organization_features"
CREATE INDEX "organizationfeature_feature_id" ON "organization_features" ("feature_id");
-- create index "organizationfeature_organization_id" to table: "organization_features"
CREATE INDEX "organizationfeature_organization_id" ON "organization_features" ("organization_id");
-- create index "organizationfeature_organization_id_feature_id" to table: "organization_features"
CREATE UNIQUE INDEX "organizationfeature_organization_id_feature_id" ON "organization_features" ("organization_id", "feature_id");
-- create "provider_templates" table
CREATE TABLE "provider_templates" ("id" character varying NOT NULL, "created_at" timestamptz NOT NULL, "updated_at" timestamptz NOT NULL, "deleted_at" timestamptz NULL, "key" character varying NOT NULL, "name" character varying NOT NULL, "display_name" character varying NOT NULL, "type" character varying NOT NULL, "protocol" character varying NOT NULL, "icon_url" character varying NULL, "category" character varying NOT NULL DEFAULT 'general', "popular" boolean NOT NULL DEFAULT false, "active" boolean NOT NULL DEFAULT true, "description" text NULL, "config_template" jsonb NOT NULL, "required_fields" jsonb NULL, "supported_features" jsonb NULL, "documentation_url" character varying NULL, "setup_guide_url" character varying NULL, "usage_count" bigint NOT NULL DEFAULT 0, "average_setup_time" double precision NULL, "success_rate" double precision NOT NULL DEFAULT 0, "popularity_rank" bigint NOT NULL DEFAULT 0, "metadata" jsonb NULL, PRIMARY KEY ("id"));
-- create index "provider_templates_key_key" to table: "provider_templates"
CREATE UNIQUE INDEX "provider_templates_key_key" ON "provider_templates" ("key");
-- create index "providertemplate_active" to table: "provider_templates"
CREATE INDEX "providertemplate_active" ON "provider_templates" ("active");
-- create index "providertemplate_category" to table: "provider_templates"
CREATE INDEX "providertemplate_category" ON "provider_templates" ("category");
-- create index "providertemplate_category_popular" to table: "provider_templates"
CREATE INDEX "providertemplate_category_popular" ON "provider_templates" ("category", "popular");
-- create index "providertemplate_key" to table: "provider_templates"
CREATE UNIQUE INDEX "providertemplate_key" ON "provider_templates" ("key");
-- create index "providertemplate_popular" to table: "provider_templates"
CREATE INDEX "providertemplate_popular" ON "provider_templates" ("popular");
-- create index "providertemplate_popularity_rank" to table: "provider_templates"
CREATE INDEX "providertemplate_popularity_rank" ON "provider_templates" ("popularity_rank");
-- create index "providertemplate_type" to table: "provider_templates"
CREATE INDEX "providertemplate_type" ON "provider_templates" ("type");
-- create index "providertemplate_type_active" to table: "provider_templates"
CREATE INDEX "providertemplate_type_active" ON "provider_templates" ("type", "active");
-- create "organization_providers" table
CREATE TABLE "organization_providers" ("id" character varying NOT NULL, "created_at" timestamptz NOT NULL, "updated_at" timestamptz NOT NULL, "deleted_at" timestamptz NULL, "template_key" character varying NOT NULL, "custom_config" jsonb NULL, "enabled_at" timestamptz NOT NULL, "last_used" timestamptz NULL, "usage_count" bigint NOT NULL DEFAULT 0, "enabled" boolean NOT NULL DEFAULT true, "success_rate" double precision NOT NULL DEFAULT 0, "total_logins" bigint NOT NULL DEFAULT 0, "successful_logins" bigint NOT NULL DEFAULT 0, "failed_logins" bigint NOT NULL DEFAULT 0, "last_success" timestamptz NULL, "last_failure" timestamptz NULL, "config_errors" bigint NOT NULL DEFAULT 0, "average_response_time" double precision NOT NULL DEFAULT 0, "analytics_data" jsonb NULL, "metadata" jsonb NULL, "provider_id" character varying NOT NULL, "organization_id" character varying NOT NULL, "template_id" character varying NOT NULL, PRIMARY KEY ("id"), CONSTRAINT "organization_providers_identit_f70bd63c33ee422abf2a3496f958bb4b" FOREIGN KEY ("provider_id") REFERENCES "identity_providers" ("id") ON UPDATE NO ACTION ON DELETE NO ACTION, CONSTRAINT "organization_providers_organizations_organization_providers" FOREIGN KEY ("organization_id") REFERENCES "organizations" ("id") ON UPDATE NO ACTION ON DELETE NO ACTION, CONSTRAINT "organization_providers_provide_9c65c13d5797f04c8993daef483d66e1" FOREIGN KEY ("template_id") REFERENCES "provider_templates" ("id") ON UPDATE NO ACTION ON DELETE NO ACTION);
-- create index "organizationprovider_enabled" to table: "organization_providers"
CREATE INDEX "organizationprovider_enabled" ON "organization_providers" ("enabled");
-- create index "organizationprovider_enabled_at" to table: "organization_providers"
CREATE INDEX "organizationprovider_enabled_at" ON "organization_providers" ("enabled_at");
-- create index "organizationprovider_last_used" to table: "organization_providers"
CREATE INDEX "organizationprovider_last_used" ON "organization_providers" ("last_used");
-- create index "organizationprovider_organization_id" to table: "organization_providers"
CREATE INDEX "organizationprovider_organization_id" ON "organization_providers" ("organization_id");
-- create index "organizationprovider_organization_id_enabled" to table: "organization_providers"
CREATE INDEX "organizationprovider_organization_id_enabled" ON "organization_providers" ("organization_id", "enabled");
-- create index "organizationprovider_organization_id_provider_id" to table: "organization_providers"
CREATE UNIQUE INDEX "organizationprovider_organization_id_provider_id" ON "organization_providers" ("organization_id", "provider_id");
-- create index "organizationprovider_organization_id_template_id" to table: "organization_providers"
CREATE INDEX "organizationprovider_organization_id_template_id" ON "organization_providers" ("organization_id", "template_id");
-- create index "organizationprovider_organization_id_template_key" to table: "organization_providers"
CREATE INDEX "organizationprovider_organization_id_template_key" ON "organization_providers" ("organization_id", "template_key");
-- create index "organizationprovider_provider_id" to table: "organization_providers"
CREATE INDEX "organizationprovider_provider_id" ON "organization_providers" ("provider_id");
-- create index "organizationprovider_success_rate" to table: "organization_providers"
CREATE INDEX "organizationprovider_success_rate" ON "organization_providers" ("success_rate");
-- create index "organizationprovider_template_id" to table: "organization_providers"
CREATE INDEX "organizationprovider_template_id" ON "organization_providers" ("template_id");
-- create index "organizationprovider_template_id_enabled" to table: "organization_providers"
CREATE INDEX "organizationprovider_template_id_enabled" ON "organization_providers" ("template_id", "enabled");
-- create index "organizationprovider_template_key" to table: "organization_providers"
CREATE INDEX "organizationprovider_template_key" ON "organization_providers" ("template_key");
-- create index "organizationprovider_template_key_enabled" to table: "organization_providers"
CREATE INDEX "organizationprovider_template_key_enabled" ON "organization_providers" ("template_key", "enabled");
-- create index "organizationprovider_usage_count" to table: "organization_providers"
CREATE INDEX "organizationprovider_usage_count" ON "organization_providers" ("usage_count");
-- create "passkeys" table
CREATE TABLE "passkeys" ("id" character varying NOT NULL, "created_at" timestamptz NOT NULL, "updated_at" timestamptz NOT NULL, "deleted_at" timestamptz NULL, "name" character varying NOT NULL, "credential_id" character varying NOT NULL, "public_key" bytea NOT NULL, "sign_count" bigint NOT NULL DEFAULT 0, "active" boolean NOT NULL DEFAULT true, "device_type" character varying NULL, "aaguid" character varying NULL, "last_used" timestamptz NULL, "transports" jsonb NULL, "attestation" jsonb NULL, "backup_state" boolean NULL, "backup_eligible" boolean NULL, "user_agent" character varying NULL, "ip_address" character varying NULL, "user_id" character varying NOT NULL, PRIMARY KEY ("id"), CONSTRAINT "passkeys_users_passkeys" FOREIGN KEY ("user_id") REFERENCES "users" ("id") ON UPDATE NO ACTION ON DELETE NO ACTION);
-- create index "passkey_credential_id" to table: "passkeys"
CREATE INDEX "passkey_credential_id" ON "passkeys" ("credential_id");
-- create index "passkey_user_id" to table: "passkeys"
CREATE INDEX "passkey_user_id" ON "passkeys" ("user_id");
-- create index "passkeys_credential_id_key" to table: "passkeys"
CREATE UNIQUE INDEX "passkeys_credential_id_key" ON "passkeys" ("credential_id");
-- create "permissions" table
CREATE TABLE "permissions" ("id" character varying NOT NULL, "created_at" timestamptz NOT NULL, "updated_at" timestamptz NOT NULL, "deleted_at" timestamptz NULL, "name" character varying NOT NULL, "display_name" character varying NULL, "description" character varying NOT NULL, "resource" character varying NOT NULL, "action" character varying NOT NULL, "category" character varying NOT NULL, "applicable_user_types" jsonb NOT NULL, "applicable_contexts" jsonb NOT NULL, "conditions" character varying NULL, "system" boolean NOT NULL DEFAULT false, "dangerous" boolean NOT NULL DEFAULT false, "risk_level" bigint NOT NULL DEFAULT 1, "created_by" character varying NULL, "active" boolean NOT NULL DEFAULT true, "permission_group" character varying NULL, PRIMARY KEY ("id"));
-- create index "permission_active" to table: "permissions"
CREATE INDEX "permission_active" ON "permissions" ("active");
-- create index "permission_category" to table: "permissions"
CREATE INDEX "permission_category" ON "permissions" ("category");
-- create index "permission_created_by" to table: "permissions"
CREATE INDEX "permission_created_by" ON "permissions" ("created_by");
-- create index "permission_dangerous" to table: "permissions"
CREATE INDEX "permission_dangerous" ON "permissions" ("dangerous");
-- create index "permission_name" to table: "permissions"
CREATE INDEX "permission_name" ON "permissions" ("name");
-- create index "permission_permission_group" to table: "permissions"
CREATE INDEX "permission_permission_group" ON "permissions" ("permission_group");
-- create index "permission_resource_action" to table: "permissions"
CREATE UNIQUE INDEX "permission_resource_action" ON "permissions" ("resource", "action");
-- create index "permission_risk_level" to table: "permissions"
CREATE INDEX "permission_risk_level" ON "permissions" ("risk_level");
-- create index "permission_system" to table: "permissions"
CREATE INDEX "permission_system" ON "permissions" ("system");
-- create index "permissions_name_key" to table: "permissions"
CREATE UNIQUE INDEX "permissions_name_key" ON "permissions" ("name");
-- create "permission_dependencies" table
CREATE TABLE "permission_dependencies" ("id" character varying NOT NULL, "created_at" timestamptz NOT NULL, "updated_at" timestamptz NOT NULL, "deleted_at" timestamptz NULL, "dependency_type" character varying NOT NULL DEFAULT 'required', "condition" character varying NULL, "active" boolean NOT NULL DEFAULT true, "created_by" character varying NULL, "permission_id" character varying NOT NULL, "required_permission_id" character varying NOT NULL, PRIMARY KEY ("id"), CONSTRAINT "permission_dependencies_permissions_dependencies" FOREIGN KEY ("permission_id") REFERENCES "permissions" ("id") ON UPDATE NO ACTION ON DELETE NO ACTION, CONSTRAINT "permission_dependencies_permissions_dependents" FOREIGN KEY ("required_permission_id") REFERENCES "permissions" ("id") ON UPDATE NO ACTION ON DELETE NO ACTION);
-- create index "permissiondependency_active" to table: "permission_dependencies"
CREATE INDEX "permissiondependency_active" ON "permission_dependencies" ("active");
-- create index "permissiondependency_created_by" to table: "permission_dependencies"
CREATE INDEX "permissiondependency_created_by" ON "permission_dependencies" ("created_by");
-- create index "permissiondependency_dependency_type" to table: "permission_dependencies"
CREATE INDEX "permissiondependency_dependency_type" ON "permission_dependencies" ("dependency_type");
-- create index "permissiondependency_permission_id" to table: "permission_dependencies"
CREATE INDEX "permissiondependency_permission_id" ON "permission_dependencies" ("permission_id");
-- create index "permissiondependency_permission_id_required_permission_id" to table: "permission_dependencies"
CREATE UNIQUE INDEX "permissiondependency_permission_id_required_permission_id" ON "permission_dependencies" ("permission_id", "required_permission_id");
-- create index "permissiondependency_required_permission_id" to table: "permission_dependencies"
CREATE INDEX "permissiondependency_required_permission_id" ON "permission_dependencies" ("required_permission_id");
-- create "permission_required_permissions" table
CREATE TABLE "permission_required_permissions" ("permission_id" character varying NOT NULL, "dependent_permission_id" character varying NOT NULL, PRIMARY KEY ("permission_id", "dependent_permission_id"), CONSTRAINT "permission_required_permissions_dependent_permission_id" FOREIGN KEY ("dependent_permission_id") REFERENCES "permissions" ("id") ON UPDATE NO ACTION ON DELETE CASCADE, CONSTRAINT "permission_required_permissions_permission_id" FOREIGN KEY ("permission_id") REFERENCES "permissions" ("id") ON UPDATE NO ACTION ON DELETE CASCADE);
-- create "role_permissions" table
CREATE TABLE "role_permissions" ("role_id" character varying NOT NULL, "permission_id" character varying NOT NULL, PRIMARY KEY ("role_id", "permission_id"), CONSTRAINT "role_permissions_permission_id" FOREIGN KEY ("permission_id") REFERENCES "permissions" ("id") ON UPDATE NO ACTION ON DELETE CASCADE, CONSTRAINT "role_permissions_role_id" FOREIGN KEY ("role_id") REFERENCES "roles" ("id") ON UPDATE NO ACTION ON DELETE CASCADE);
-- create "sms_templates" table
CREATE TABLE "sms_templates" ("id" character varying NOT NULL, "created_at" timestamptz NOT NULL, "updated_at" timestamptz NOT NULL, "deleted_at" timestamptz NULL, "name" character varying NOT NULL, "content" character varying NOT NULL, "type" character varying NOT NULL, "active" boolean NOT NULL DEFAULT true, "system" boolean NOT NULL DEFAULT false, "locale" character varying NOT NULL DEFAULT 'en', "max_length" bigint NOT NULL DEFAULT 160, "message_type" character varying NOT NULL DEFAULT 'transactional', "estimated_segments" bigint NULL DEFAULT 1, "estimated_cost" double precision NULL DEFAULT 0, "currency" character varying NULL DEFAULT 'USD', "variables" jsonb NULL, "metadata" jsonb NULL, "last_used_at" timestamptz NULL, "usage_count" bigint NOT NULL DEFAULT 0, "organization_id" character varying NULL, PRIMARY KEY ("id"), CONSTRAINT "sms_templates_organizations_sms_templates" FOREIGN KEY ("organization_id") REFERENCES "organizations" ("id") ON UPDATE NO ACTION ON DELETE SET NULL);
-- create index "smstemplate_active" to table: "sms_templates"
CREATE INDEX "smstemplate_active" ON "sms_templates" ("active");
-- create index "smstemplate_last_used_at" to table: "sms_templates"
CREATE INDEX "smstemplate_last_used_at" ON "sms_templates" ("last_used_at");
-- create index "smstemplate_message_type" to table: "sms_templates"
CREATE INDEX "smstemplate_message_type" ON "sms_templates" ("message_type");
-- create index "smstemplate_organization_id" to table: "sms_templates"
CREATE INDEX "smstemplate_organization_id" ON "sms_templates" ("organization_id");
-- create index "smstemplate_organization_id_type" to table: "sms_templates"
CREATE INDEX "smstemplate_organization_id_type" ON "sms_templates" ("organization_id", "type");
-- create index "smstemplate_organization_id_type_locale" to table: "sms_templates"
CREATE UNIQUE INDEX "smstemplate_organization_id_type_locale" ON "sms_templates" ("organization_id", "type", "locale");
-- create index "smstemplate_system" to table: "sms_templates"
CREATE INDEX "smstemplate_system" ON "sms_templates" ("system");
-- create index "smstemplate_type" to table: "sms_templates"
CREATE INDEX "smstemplate_type" ON "sms_templates" ("type");
-- create index "smstemplate_usage_count" to table: "sms_templates"
CREATE INDEX "smstemplate_usage_count" ON "sms_templates" ("usage_count");
-- create "user_permissions" table
CREATE TABLE "user_permissions" ("id" character varying NOT NULL, "created_at" timestamptz NOT NULL, "updated_at" timestamptz NOT NULL, "deleted_at" timestamptz NULL, "context_type" character varying NOT NULL, "resource_type" character varying NULL, "resource_id" character varying NULL, "permission_type" character varying NOT NULL DEFAULT 'grant', "assigned_at" timestamptz NOT NULL, "expires_at" timestamptz NULL, "active" boolean NOT NULL DEFAULT true, "conditions" jsonb NULL, "reason" character varying NULL, "permission_id" character varying NOT NULL, "user_id" character varying NOT NULL, "assigned_by" character varying NULL, "context_id" character varying NULL, PRIMARY KEY ("id"), CONSTRAINT "user_permissions_organizations_organization_context" FOREIGN KEY ("context_id") REFERENCES "organizations" ("id") ON UPDATE NO ACTION ON DELETE SET NULL, CONSTRAINT "user_permissions_permissions_user_assignments" FOREIGN KEY ("permission_id") REFERENCES "permissions" ("id") ON UPDATE NO ACTION ON DELETE NO ACTION, CONSTRAINT "user_permissions_users_assigned_user_permissions" FOREIGN KEY ("assigned_by") REFERENCES "users" ("id") ON UPDATE NO ACTION ON DELETE SET NULL, CONSTRAINT "user_permissions_users_user_permissions" FOREIGN KEY ("user_id") REFERENCES "users" ("id") ON UPDATE NO ACTION ON DELETE NO ACTION);
-- create index "userpermission_active" to table: "user_permissions"
CREATE INDEX "userpermission_active" ON "user_permissions" ("active");
-- create index "userpermission_assigned_by" to table: "user_permissions"
CREATE INDEX "userpermission_assigned_by" ON "user_permissions" ("assigned_by");
-- create index "userpermission_context_id" to table: "user_permissions"
CREATE INDEX "userpermission_context_id" ON "user_permissions" ("context_id");
-- create index "userpermission_context_type" to table: "user_permissions"
CREATE INDEX "userpermission_context_type" ON "user_permissions" ("context_type");
-- create index "userpermission_context_type_context_id_active" to table: "user_permissions"
CREATE INDEX "userpermission_context_type_context_id_active" ON "user_permissions" ("context_type", "context_id", "active");
-- create index "userpermission_expires_at" to table: "user_permissions"
CREATE INDEX "userpermission_expires_at" ON "user_permissions" ("expires_at");
-- create index "userpermission_permission_id" to table: "user_permissions"
CREATE INDEX "userpermission_permission_id" ON "user_permissions" ("permission_id");
-- create index "userpermission_permission_type" to table: "user_permissions"
CREATE INDEX "userpermission_permission_type" ON "user_permissions" ("permission_type");
-- create index "userpermission_resource_id" to table: "user_permissions"
CREATE INDEX "userpermission_resource_id" ON "user_permissions" ("resource_id");
-- create index "userpermission_resource_type" to table: "user_permissions"
CREATE INDEX "userpermission_resource_type" ON "user_permissions" ("resource_type");
-- create index "userpermission_user_id" to table: "user_permissions"
CREATE INDEX "userpermission_user_id" ON "user_permissions" ("user_id");
-- create index "userpermission_user_id_context_type_context_id" to table: "user_permissions"
CREATE INDEX "userpermission_user_id_context_type_context_id" ON "user_permissions" ("user_id", "context_type", "context_id");
-- create index "userpermission_user_id_permiss_29e6bf1065fb7a61fc9825b79f34a10e" to table: "user_permissions"
CREATE UNIQUE INDEX "userpermission_user_id_permiss_29e6bf1065fb7a61fc9825b79f34a10e" ON "user_permissions" ("user_id", "permission_id", "context_type", "context_id", "resource_type", "resource_id");
-- create index "userpermission_user_id_resource_type_resource_id" to table: "user_permissions"
CREATE INDEX "userpermission_user_id_resource_type_resource_id" ON "user_permissions" ("user_id", "resource_type", "resource_id");
-- create "user_roles" table
CREATE TABLE "user_roles" ("id" character varying NOT NULL, "created_at" timestamptz NOT NULL, "updated_at" timestamptz NOT NULL, "deleted_at" timestamptz NULL, "context_type" character varying NOT NULL, "assigned_at" timestamptz NOT NULL, "expires_at" timestamptz NULL, "active" boolean NOT NULL DEFAULT true, "conditions" jsonb NULL, "role_id" character varying NOT NULL, "user_id" character varying NOT NULL, "assigned_by" character varying NULL, "context_id" character varying NULL, PRIMARY KEY ("id"), CONSTRAINT "user_roles_organizations_organization_context" FOREIGN KEY ("context_id") REFERENCES "organizations" ("id") ON UPDATE NO ACTION ON DELETE SET NULL, CONSTRAINT "user_roles_roles_user_assignments" FOREIGN KEY ("role_id") REFERENCES "roles" ("id") ON UPDATE NO ACTION ON DELETE NO ACTION, CONSTRAINT "user_roles_users_assigned_user_roles" FOREIGN KEY ("assigned_by") REFERENCES "users" ("id") ON UPDATE NO ACTION ON DELETE SET NULL, CONSTRAINT "user_roles_users_user_roles" FOREIGN KEY ("user_id") REFERENCES "users" ("id") ON UPDATE NO ACTION ON DELETE NO ACTION);
-- create index "userrole_active" to table: "user_roles"
CREATE INDEX "userrole_active" ON "user_roles" ("active");
-- create index "userrole_assigned_by" to table: "user_roles"
CREATE INDEX "userrole_assigned_by" ON "user_roles" ("assigned_by");
-- create index "userrole_context_id" to table: "user_roles"
CREATE INDEX "userrole_context_id" ON "user_roles" ("context_id");
-- create index "userrole_context_type" to table: "user_roles"
CREATE INDEX "userrole_context_type" ON "user_roles" ("context_type");
-- create index "userrole_context_type_context_id" to table: "user_roles"
CREATE INDEX "userrole_context_type_context_id" ON "user_roles" ("context_type", "context_id");
-- create index "userrole_expires_at" to table: "user_roles"
CREATE INDEX "userrole_expires_at" ON "user_roles" ("expires_at");
-- create index "userrole_role_id" to table: "user_roles"
CREATE INDEX "userrole_role_id" ON "user_roles" ("role_id");
-- create index "userrole_user_id" to table: "user_roles"
CREATE INDEX "userrole_user_id" ON "user_roles" ("user_id");
-- create index "userrole_user_id_context_type_context_id" to table: "user_roles"
CREATE INDEX "userrole_user_id_context_type_context_id" ON "user_roles" ("user_id", "context_type", "context_id");
-- create index "userrole_user_id_role_id_context_type_context_id" to table: "user_roles"
CREATE UNIQUE INDEX "userrole_user_id_role_id_context_type_context_id" ON "user_roles" ("user_id", "role_id", "context_type", "context_id");
-- create "user_system_roles" table
CREATE TABLE "user_system_roles" ("user_id" character varying NOT NULL, "role_id" character varying NOT NULL, PRIMARY KEY ("user_id", "role_id"), CONSTRAINT "user_system_roles_role_id" FOREIGN KEY ("role_id") REFERENCES "roles" ("id") ON UPDATE NO ACTION ON DELETE CASCADE, CONSTRAINT "user_system_roles_user_id" FOREIGN KEY ("user_id") REFERENCES "users" ("id") ON UPDATE NO ACTION ON DELETE CASCADE);
-- create "verifications" table
CREATE TABLE "verifications" ("id" character varying NOT NULL, "created_at" timestamptz NOT NULL, "updated_at" timestamptz NOT NULL, "deleted_at" timestamptz NULL, "type" character varying NOT NULL, "token" character varying NOT NULL, "email" character varying NULL, "phone_number" character varying NULL, "redirect_url" character varying NULL, "used" boolean NOT NULL DEFAULT false, "used_at" timestamptz NULL, "attempts" bigint NOT NULL DEFAULT 0, "expires_at" timestamptz NOT NULL, "ip_address" character varying NULL, "user_agent" character varying NULL, "attestation" jsonb NULL, "metadata" jsonb NULL, "user_id" character varying NOT NULL, PRIMARY KEY ("id"), CONSTRAINT "verifications_users_verifications" FOREIGN KEY ("user_id") REFERENCES "users" ("id") ON UPDATE NO ACTION ON DELETE NO ACTION);
-- create index "verification_email" to table: "verifications"
CREATE INDEX "verification_email" ON "verifications" ("email");
-- create index "verification_expires_at" to table: "verifications"
CREATE INDEX "verification_expires_at" ON "verifications" ("expires_at");
-- create index "verification_phone_number" to table: "verifications"
CREATE INDEX "verification_phone_number" ON "verifications" ("phone_number");
-- create index "verification_token" to table: "verifications"
CREATE INDEX "verification_token" ON "verifications" ("token");
-- create index "verification_user_id" to table: "verifications"
CREATE INDEX "verification_user_id" ON "verifications" ("user_id");
-- create index "verifications_token_key" to table: "verifications"
CREATE UNIQUE INDEX "verifications_token_key" ON "verifications" ("token");
-- create "webhooks" table
CREATE TABLE "webhooks" ("id" character varying NOT NULL, "created_at" timestamptz NOT NULL, "updated_at" timestamptz NOT NULL, "deleted_at" timestamptz NULL, "name" character varying NOT NULL, "url" character varying NOT NULL, "secret" character varying NOT NULL, "active" boolean NOT NULL DEFAULT true, "event_types" jsonb NOT NULL, "version" character varying NOT NULL DEFAULT 'v1', "retry_count" bigint NOT NULL DEFAULT 3, "timeout_ms" bigint NOT NULL DEFAULT 5000, "format" character varying NOT NULL DEFAULT 'json', "metadata" jsonb NULL, "headers" jsonb NULL, "organization_id" character varying NOT NULL, PRIMARY KEY ("id"), CONSTRAINT "webhooks_organizations_webhooks" FOREIGN KEY ("organization_id") REFERENCES "organizations" ("id") ON UPDATE NO ACTION ON DELETE NO ACTION);
-- create index "webhook_organization_id" to table: "webhooks"
CREATE INDEX "webhook_organization_id" ON "webhooks" ("organization_id");
-- create "webhook_events" table
CREATE TABLE "webhook_events" ("id" character varying NOT NULL, "created_at" timestamptz NOT NULL, "updated_at" timestamptz NOT NULL, "deleted_at" timestamptz NULL, "event_type" character varying NOT NULL, "headers" jsonb NULL, "payload" jsonb NULL, "delivered" boolean NOT NULL DEFAULT false, "delivered_at" timestamptz NULL, "attempts" bigint NOT NULL DEFAULT 0, "next_retry" timestamptz NULL, "status_code" bigint NULL, "response_body" character varying NULL, "error" character varying NULL, "webhook_id" character varying NOT NULL, PRIMARY KEY ("id"), CONSTRAINT "webhook_events_webhooks_events" FOREIGN KEY ("webhook_id") REFERENCES "webhooks" ("id") ON UPDATE NO ACTION ON DELETE NO ACTION);
-- create index "webhookevent_delivered" to table: "webhook_events"
CREATE INDEX "webhookevent_delivered" ON "webhook_events" ("delivered");
-- create index "webhookevent_event_type" to table: "webhook_events"
CREATE INDEX "webhookevent_event_type" ON "webhook_events" ("event_type");
-- create index "webhookevent_next_retry" to table: "webhook_events"
CREATE INDEX "webhookevent_next_retry" ON "webhook_events" ("next_retry");
-- create index "webhookevent_webhook_id" to table: "webhook_events"
CREATE INDEX "webhookevent_webhook_id" ON "webhook_events" ("webhook_id");
