-- Create "organizations" table
CREATE TABLE "organizations" ("id" character varying NOT NULL, "created_at" timestamptz NOT NULL, "updated_at" timestamptz NOT NULL, "deleted_at" timestamptz NULL, "name" character varying NOT NULL, "slug" character varying NOT NULL, "domains" jsonb NULL, "verified_domains" jsonb NULL, "domain" character varying NULL, "logo_url" character varying NULL, "plan" character varying NOT NULL DEFAULT 'free', "active" boolean NOT NULL DEFAULT true, "metadata" jsonb NULL, "trial_ends_at" timestamptz NULL, "trial_used" boolean NOT NULL DEFAULT false, "owner_id" character varying NULL, "org_type" character varying NOT NULL DEFAULT 'customer', "is_platform_organization" boolean NOT NULL DEFAULT false, "external_user_limit" bigint NOT NULL DEFAULT 5, "end_user_limit" bigint NOT NULL DEFAULT 100, "sso_enabled" boolean NOT NULL DEFAULT false, "sso_domain" character varying NULL, "subscription_id" character varying NULL, "customer_id" character varying NULL, "subscription_status" character varying NOT NULL DEFAULT 'trialing', "auth_service_enabled" boolean NOT NULL DEFAULT false, "auth_config" jsonb NULL, "auth_domain" character varying NULL, "api_request_limit" bigint NOT NULL DEFAULT 10000, "api_requests_used" bigint NOT NULL DEFAULT 0, "current_external_users" bigint NOT NULL DEFAULT 0, "current_end_users" bigint NOT NULL DEFAULT 0, PRIMARY KEY ("id"));
-- Create index "organization_active" to table: "organizations"
CREATE INDEX "organization_active" ON "organizations" ("active");
-- Create index "organization_auth_domain" to table: "organizations"
CREATE UNIQUE INDEX "organization_auth_domain" ON "organizations" ("auth_domain");
-- Create index "organization_auth_service_enabled" to table: "organizations"
CREATE INDEX "organization_auth_service_enabled" ON "organizations" ("auth_service_enabled");
-- Create index "organization_customer_id" to table: "organizations"
CREATE INDEX "organization_customer_id" ON "organizations" ("customer_id");
-- Create index "organization_domain" to table: "organizations"
CREATE INDEX "organization_domain" ON "organizations" ("domain");
-- Create index "organization_is_platform_organization" to table: "organizations"
CREATE INDEX "organization_is_platform_organization" ON "organizations" ("is_platform_organization");
-- Create index "organization_org_type" to table: "organizations"
CREATE INDEX "organization_org_type" ON "organizations" ("org_type");
-- Create index "organization_owner_id" to table: "organizations"
CREATE INDEX "organization_owner_id" ON "organizations" ("owner_id");
-- Create index "organization_slug" to table: "organizations"
CREATE INDEX "organization_slug" ON "organizations" ("slug");
-- Create index "organization_sso_domain" to table: "organizations"
CREATE INDEX "organization_sso_domain" ON "organizations" ("sso_domain");
-- Create index "organization_subscription_id" to table: "organizations"
CREATE INDEX "organization_subscription_id" ON "organizations" ("subscription_id");
-- Create index "organization_subscription_status" to table: "organizations"
CREATE INDEX "organization_subscription_status" ON "organizations" ("subscription_status");
-- Create index "organizations_slug_key" to table: "organizations"
CREATE UNIQUE INDEX "organizations_slug_key" ON "organizations" ("slug");
-- Create "sso_states" table
CREATE TABLE "sso_states" ("id" character varying NOT NULL, "created_at" timestamptz NOT NULL, "updated_at" timestamptz NOT NULL, "deleted_at" timestamptz NULL, "state" character varying NOT NULL, "data" character varying NOT NULL, "expires_at" timestamptz NOT NULL, "redirect_url" character varying NULL, PRIMARY KEY ("id"));
-- Create index "sso_states_state_key" to table: "sso_states"
CREATE UNIQUE INDEX "sso_states_state_key" ON "sso_states" ("state");
-- Create index "ssostate_expires_at" to table: "sso_states"
CREATE INDEX "ssostate_expires_at" ON "sso_states" ("expires_at");
-- Create "users" table
CREATE TABLE "users" ("id" character varying NOT NULL, "created_at" timestamptz NOT NULL, "updated_at" timestamptz NOT NULL, "email" character varying NOT NULL, "phone_number" character varying NULL, "first_name" character varying NULL, "last_name" character varying NULL, "username" character varying NULL, "password_hash" character varying NULL, "email_verified" boolean NOT NULL DEFAULT false, "phone_verified" boolean NOT NULL DEFAULT false, "active" boolean NOT NULL DEFAULT true, "blocked" boolean NOT NULL DEFAULT false, "last_login" timestamptz NULL, "last_password_change" timestamptz NULL, "metadata" jsonb NULL, "profile_image_url" character varying NULL, "locale" character varying NOT NULL DEFAULT 'en', "timezone" character varying NULL, "user_type" character varying NOT NULL DEFAULT 'external', "primary_organization_id" character varying NULL, "is_platform_admin" boolean NOT NULL DEFAULT false, "auth_provider" character varying NOT NULL DEFAULT 'internal', "external_id" character varying NULL, "customer_id" character varying NULL, "custom_attributes" jsonb NULL, "created_by" character varying NULL, "password_reset_token_expires" timestamptz NULL, "password_reset_token" character varying NULL, "login_count" bigint NOT NULL DEFAULT 0, "last_login_ip" character varying NULL, "organization_id" character varying NULL, PRIMARY KEY ("id"), CONSTRAINT "users_organizations_users" FOREIGN KEY ("organization_id") REFERENCES "organizations" ("id") ON UPDATE NO ACTION ON DELETE SET NULL);
-- Create index "user_active" to table: "users"
CREATE INDEX "user_active" ON "users" ("active");
-- Create index "user_auth_provider" to table: "users"
CREATE INDEX "user_auth_provider" ON "users" ("auth_provider");
-- Create index "user_auth_provider_external_id" to table: "users"
CREATE INDEX "user_auth_provider_external_id" ON "users" ("auth_provider", "external_id");
-- Create index "user_blocked" to table: "users"
CREATE INDEX "user_blocked" ON "users" ("blocked");
-- Create index "user_created_by" to table: "users"
CREATE INDEX "user_created_by" ON "users" ("created_by");
-- Create index "user_customer_id" to table: "users"
CREATE INDEX "user_customer_id" ON "users" ("customer_id");
-- Create index "user_email" to table: "users"
CREATE INDEX "user_email" ON "users" ("email");
-- Create index "user_external_id" to table: "users"
CREATE INDEX "user_external_id" ON "users" ("external_id");
-- Create index "user_is_platform_admin" to table: "users"
CREATE INDEX "user_is_platform_admin" ON "users" ("is_platform_admin");
-- Create index "user_last_login" to table: "users"
CREATE INDEX "user_last_login" ON "users" ("last_login");
-- Create index "user_organization_id" to table: "users"
CREATE INDEX "user_organization_id" ON "users" ("organization_id");
-- Create index "user_organization_id_active" to table: "users"
CREATE INDEX "user_organization_id_active" ON "users" ("organization_id", "active");
-- Create index "user_organization_id_user_type" to table: "users"
CREATE INDEX "user_organization_id_user_type" ON "users" ("organization_id", "user_type");
-- Create index "user_organization_id_user_type_auth_provider_external_id" to table: "users"
CREATE UNIQUE INDEX "user_organization_id_user_type_auth_provider_external_id" ON "users" ("organization_id", "user_type", "auth_provider", "external_id");
-- Create index "user_organization_id_user_type_email" to table: "users"
CREATE UNIQUE INDEX "user_organization_id_user_type_email" ON "users" ("organization_id", "user_type", "email");
-- Create index "user_organization_id_user_type_username" to table: "users"
CREATE UNIQUE INDEX "user_organization_id_user_type_username" ON "users" ("organization_id", "user_type", "username");
-- Create index "user_user_type" to table: "users"
CREATE INDEX "user_user_type" ON "users" ("user_type");
-- Create index "user_user_type_active" to table: "users"
CREATE INDEX "user_user_type_active" ON "users" ("user_type", "active");
-- Create index "user_user_type_email" to table: "users"
CREATE UNIQUE INDEX "user_user_type_email" ON "users" ("user_type", "email");
-- Create index "user_username" to table: "users"
CREATE INDEX "user_username" ON "users" ("username");
-- Create "api_keys" table
CREATE TABLE "api_keys" ("id" character varying NOT NULL, "created_at" timestamptz NOT NULL, "updated_at" timestamptz NOT NULL, "deleted_at" timestamptz NULL, "name" character varying NOT NULL, "key" character varying NOT NULL, "hashed_key" character varying NOT NULL, "type" character varying NOT NULL DEFAULT 'server', "active" boolean NOT NULL DEFAULT true, "permissions" jsonb NULL, "scopes" jsonb NULL, "metadata" jsonb NULL, "last_used" timestamptz NULL, "expires_at" timestamptz NULL, "organization_id" character varying NULL, "user_id" character varying NULL, PRIMARY KEY ("id"), CONSTRAINT "api_keys_organizations_api_keys" FOREIGN KEY ("organization_id") REFERENCES "organizations" ("id") ON UPDATE NO ACTION ON DELETE SET NULL, CONSTRAINT "api_keys_users_api_keys" FOREIGN KEY ("user_id") REFERENCES "users" ("id") ON UPDATE NO ACTION ON DELETE SET NULL);
-- Create index "api_keys_hashed_key_key" to table: "api_keys"
CREATE UNIQUE INDEX "api_keys_hashed_key_key" ON "api_keys" ("hashed_key");
-- Create index "api_keys_key_key" to table: "api_keys"
CREATE UNIQUE INDEX "api_keys_key_key" ON "api_keys" ("key");
-- Create index "apikey_hashed_key" to table: "api_keys"
CREATE INDEX "apikey_hashed_key" ON "api_keys" ("hashed_key");
-- Create index "apikey_organization_id" to table: "api_keys"
CREATE INDEX "apikey_organization_id" ON "api_keys" ("organization_id");
-- Create index "apikey_user_id" to table: "api_keys"
CREATE INDEX "apikey_user_id" ON "api_keys" ("user_id");
-- Create "sessions" table
CREATE TABLE "sessions" ("id" character varying NOT NULL, "created_at" timestamptz NOT NULL, "updated_at" timestamptz NOT NULL, "token" character varying NOT NULL, "ip_address" character varying NULL, "user_agent" character varying NULL, "device_id" character varying NULL, "location" character varying NULL, "organization_id" character varying NULL, "active" boolean NOT NULL DEFAULT true, "expires_at" timestamptz NOT NULL, "last_active_at" timestamptz NOT NULL, "metadata" jsonb NULL, "user_id" character varying NOT NULL, PRIMARY KEY ("id"), CONSTRAINT "sessions_users_sessions" FOREIGN KEY ("user_id") REFERENCES "users" ("id") ON UPDATE NO ACTION ON DELETE NO ACTION);
-- Create index "session_expires_at" to table: "sessions"
CREATE INDEX "session_expires_at" ON "sessions" ("expires_at");
-- Create index "session_organization_id" to table: "sessions"
CREATE INDEX "session_organization_id" ON "sessions" ("organization_id");
-- Create index "session_token" to table: "sessions"
CREATE INDEX "session_token" ON "sessions" ("token");
-- Create index "session_user_id" to table: "sessions"
CREATE INDEX "session_user_id" ON "sessions" ("user_id");
-- Create index "sessions_token_key" to table: "sessions"
CREATE UNIQUE INDEX "sessions_token_key" ON "sessions" ("token");
-- Create "audits" table
CREATE TABLE "audits" ("id" character varying NOT NULL, "deleted_at" timestamptz NULL, "created_at" timestamptz NOT NULL, "updated_at" timestamptz NOT NULL, "action" character varying NOT NULL, "resource_type" character varying NOT NULL, "resource_id" character varying NULL, "status" character varying NOT NULL, "ip_address" character varying NULL, "user_agent" character varying NULL, "location" character varying NULL, "device_id" character varying NULL, "request_id" character varying NULL, "error_code" character varying NULL, "error_message" character varying NULL, "description" character varying NULL, "metadata" jsonb NULL, "old_values" jsonb NULL, "current_values" jsonb NULL, "timestamp" timestamptz NOT NULL, "organization_id" character varying NULL, "session_id" character varying NULL, "user_id" character varying NULL, PRIMARY KEY ("id"), CONSTRAINT "audits_organizations_audit_logs" FOREIGN KEY ("organization_id") REFERENCES "organizations" ("id") ON UPDATE NO ACTION ON DELETE SET NULL, CONSTRAINT "audits_sessions_audit_logs" FOREIGN KEY ("session_id") REFERENCES "sessions" ("id") ON UPDATE NO ACTION ON DELETE SET NULL, CONSTRAINT "audits_users_audit_logs" FOREIGN KEY ("user_id") REFERENCES "users" ("id") ON UPDATE NO ACTION ON DELETE SET NULL);
-- Create index "audit_action" to table: "audits"
CREATE INDEX "audit_action" ON "audits" ("action");
-- Create index "audit_action_timestamp" to table: "audits"
CREATE INDEX "audit_action_timestamp" ON "audits" ("action", "timestamp");
-- Create index "audit_ip_address_timestamp" to table: "audits"
CREATE INDEX "audit_ip_address_timestamp" ON "audits" ("ip_address", "timestamp");
-- Create index "audit_organization_id" to table: "audits"
CREATE INDEX "audit_organization_id" ON "audits" ("organization_id");
-- Create index "audit_organization_id_timestamp" to table: "audits"
CREATE INDEX "audit_organization_id_timestamp" ON "audits" ("organization_id", "timestamp");
-- Create index "audit_resource_id" to table: "audits"
CREATE INDEX "audit_resource_id" ON "audits" ("resource_id");
-- Create index "audit_resource_type" to table: "audits"
CREATE INDEX "audit_resource_type" ON "audits" ("resource_type");
-- Create index "audit_resource_type_resource_id" to table: "audits"
CREATE INDEX "audit_resource_type_resource_id" ON "audits" ("resource_type", "resource_id");
-- Create index "audit_session_id" to table: "audits"
CREATE INDEX "audit_session_id" ON "audits" ("session_id");
-- Create index "audit_status" to table: "audits"
CREATE INDEX "audit_status" ON "audits" ("status");
-- Create index "audit_timestamp" to table: "audits"
CREATE INDEX "audit_timestamp" ON "audits" ("timestamp");
-- Create index "audit_user_id" to table: "audits"
CREATE INDEX "audit_user_id" ON "audits" ("user_id");
-- Create index "audit_user_id_timestamp" to table: "audits"
CREATE INDEX "audit_user_id_timestamp" ON "audits" ("user_id", "timestamp");
-- Create "email_templates" table
CREATE TABLE "email_templates" ("id" character varying NOT NULL, "created_at" timestamptz NOT NULL, "updated_at" timestamptz NOT NULL, "deleted_at" timestamptz NULL, "name" character varying NOT NULL, "subject" character varying NOT NULL, "type" character varying NOT NULL, "html_content" character varying NOT NULL, "text_content" character varying NULL, "active" boolean NOT NULL DEFAULT true, "system" boolean NOT NULL DEFAULT false, "locale" character varying NOT NULL DEFAULT 'en', "metadata" jsonb NULL, "organization_id" character varying NULL, PRIMARY KEY ("id"), CONSTRAINT "email_templates_organizations_email_templates" FOREIGN KEY ("organization_id") REFERENCES "organizations" ("id") ON UPDATE NO ACTION ON DELETE SET NULL);
-- Create index "emailtemplate_organization_id" to table: "email_templates"
CREATE INDEX "emailtemplate_organization_id" ON "email_templates" ("organization_id");
-- Create index "emailtemplate_organization_id_type_locale" to table: "email_templates"
CREATE UNIQUE INDEX "emailtemplate_organization_id_type_locale" ON "email_templates" ("organization_id", "type", "locale");
-- Create index "emailtemplate_type" to table: "email_templates"
CREATE INDEX "emailtemplate_type" ON "email_templates" ("type");
-- Create "identity_providers" table
CREATE TABLE "identity_providers" ("id" character varying NOT NULL, "created_at" timestamptz NOT NULL, "updated_at" timestamptz NOT NULL, "deleted_at" timestamptz NULL, "name" character varying NOT NULL, "provider_type" character varying NOT NULL, "client_id" character varying NULL, "client_secret" character varying NULL, "issuer" character varying NULL, "authorization_endpoint" character varying NULL, "token_endpoint" character varying NULL, "userinfo_endpoint" character varying NULL, "jwks_uri" character varying NULL, "metadata_url" character varying NULL, "redirect_uri" character varying NULL, "certificate" character varying NULL, "private_key" character varying NULL, "active" boolean NOT NULL DEFAULT true, "enabled" boolean NOT NULL DEFAULT true, "primary" boolean NOT NULL DEFAULT false, "auto_provision" boolean NOT NULL DEFAULT false, "default_role" character varying NULL, "domain" character varying NULL, "icon_url" character varying NULL, "button_text" character varying NULL, "protocol" character varying NULL, "domains" jsonb NULL, "attributes_mapping" jsonb NULL, "metadata" jsonb NULL, "organization_id" character varying NOT NULL, PRIMARY KEY ("id"), CONSTRAINT "identity_providers_organizations_identity_providers" FOREIGN KEY ("organization_id") REFERENCES "organizations" ("id") ON UPDATE NO ACTION ON DELETE NO ACTION);
-- Create index "identityprovider_organization_id" to table: "identity_providers"
CREATE INDEX "identityprovider_organization_id" ON "identity_providers" ("organization_id");
-- Create index "identityprovider_provider_type" to table: "identity_providers"
CREATE INDEX "identityprovider_provider_type" ON "identity_providers" ("provider_type");
-- Create "roles" table
CREATE TABLE "roles" ("id" character varying NOT NULL, "created_at" timestamptz NOT NULL, "updated_at" timestamptz NOT NULL, "deleted_at" timestamptz NULL, "name" character varying NOT NULL, "display_name" character varying NULL, "description" character varying NULL, "role_type" character varying NOT NULL, "application_id" character varying NULL, "system" boolean NOT NULL DEFAULT false, "is_default" boolean NOT NULL DEFAULT false, "priority" bigint NOT NULL DEFAULT 0, "color" character varying NULL, "applicable_user_types" jsonb NOT NULL, "created_by" character varying NULL, "active" boolean NOT NULL DEFAULT true, "organization_id" character varying NULL, "parent_id" character varying NULL, PRIMARY KEY ("id"), CONSTRAINT "roles_organizations_roles" FOREIGN KEY ("organization_id") REFERENCES "organizations" ("id") ON UPDATE NO ACTION ON DELETE SET NULL, CONSTRAINT "roles_roles_children" FOREIGN KEY ("parent_id") REFERENCES "roles" ("id") ON UPDATE NO ACTION ON DELETE SET NULL);
-- Create index "role_active" to table: "roles"
CREATE INDEX "role_active" ON "roles" ("active");
-- Create index "role_application_id" to table: "roles"
CREATE INDEX "role_application_id" ON "roles" ("application_id");
-- Create index "role_created_by" to table: "roles"
CREATE INDEX "role_created_by" ON "roles" ("created_by");
-- Create index "role_is_default" to table: "roles"
CREATE INDEX "role_is_default" ON "roles" ("is_default");
-- Create index "role_name_role_type_organization_id_application_id" to table: "roles"
CREATE UNIQUE INDEX "role_name_role_type_organization_id_application_id" ON "roles" ("name", "role_type", "organization_id", "application_id");
-- Create index "role_organization_id" to table: "roles"
CREATE INDEX "role_organization_id" ON "roles" ("organization_id");
-- Create index "role_organization_id_is_default" to table: "roles"
CREATE INDEX "role_organization_id_is_default" ON "roles" ("organization_id", "is_default");
-- Create index "role_parent_id" to table: "roles"
CREATE INDEX "role_parent_id" ON "roles" ("parent_id");
-- Create index "role_parent_id_active" to table: "roles"
CREATE INDEX "role_parent_id_active" ON "roles" ("parent_id", "active");
-- Create index "role_priority" to table: "roles"
CREATE INDEX "role_priority" ON "roles" ("priority");
-- Create index "role_role_type" to table: "roles"
CREATE INDEX "role_role_type" ON "roles" ("role_type");
-- Create index "role_role_type_application_id" to table: "roles"
CREATE INDEX "role_role_type_application_id" ON "roles" ("role_type", "application_id");
-- Create index "role_role_type_organization_id" to table: "roles"
CREATE INDEX "role_role_type_organization_id" ON "roles" ("role_type", "organization_id");
-- Create index "role_system" to table: "roles"
CREATE INDEX "role_system" ON "roles" ("system");
-- Create "memberships" table
CREATE TABLE "memberships" ("id" character varying NOT NULL, "created_at" timestamptz NOT NULL, "updated_at" timestamptz NOT NULL, "deleted_at" timestamptz NULL, "email" character varying NOT NULL, "status" character varying NOT NULL DEFAULT 'pending', "invited_at" timestamptz NOT NULL, "joined_at" timestamptz NULL, "expires_at" timestamptz NULL, "invitation_token" character varying NULL, "is_billing_contact" boolean NOT NULL DEFAULT false, "is_primary_contact" boolean NOT NULL DEFAULT false, "left_at" timestamptz NULL, "metadata" jsonb NULL, "custom_fields" jsonb NULL, "organization_id" character varying NOT NULL, "role_id" character varying NOT NULL, "user_id" character varying NOT NULL, "invited_by" character varying NULL, PRIMARY KEY ("id"), CONSTRAINT "memberships_organizations_memberships" FOREIGN KEY ("organization_id") REFERENCES "organizations" ("id") ON UPDATE NO ACTION ON DELETE NO ACTION, CONSTRAINT "memberships_roles_memberships" FOREIGN KEY ("role_id") REFERENCES "roles" ("id") ON UPDATE NO ACTION ON DELETE NO ACTION, CONSTRAINT "memberships_users_memberships" FOREIGN KEY ("user_id") REFERENCES "users" ("id") ON UPDATE NO ACTION ON DELETE NO ACTION, CONSTRAINT "memberships_users_sent_invitations" FOREIGN KEY ("invited_by") REFERENCES "users" ("id") ON UPDATE NO ACTION ON DELETE SET NULL);
-- Create index "membership_expires_at" to table: "memberships"
CREATE INDEX "membership_expires_at" ON "memberships" ("expires_at");
-- Create index "membership_invitation_token" to table: "memberships"
CREATE INDEX "membership_invitation_token" ON "memberships" ("invitation_token");
-- Create index "membership_invited_by" to table: "memberships"
CREATE INDEX "membership_invited_by" ON "memberships" ("invited_by");
-- Create index "membership_organization_id" to table: "memberships"
CREATE INDEX "membership_organization_id" ON "memberships" ("organization_id");
-- Create index "membership_role_id" to table: "memberships"
CREATE INDEX "membership_role_id" ON "memberships" ("role_id");
-- Create index "membership_status" to table: "memberships"
CREATE INDEX "membership_status" ON "memberships" ("status");
-- Create index "membership_user_id" to table: "memberships"
CREATE INDEX "membership_user_id" ON "memberships" ("user_id");
-- Create index "membership_user_id_organization_id" to table: "memberships"
CREATE UNIQUE INDEX "membership_user_id_organization_id" ON "memberships" ("user_id", "organization_id");
-- Create "mf_as" table
CREATE TABLE "mf_as" ("id" character varying NOT NULL, "created_at" timestamptz NOT NULL, "updated_at" timestamptz NOT NULL, "deleted_at" timestamptz NULL, "method" character varying NOT NULL, "secret" character varying NOT NULL, "verified" boolean NOT NULL DEFAULT false, "active" boolean NOT NULL DEFAULT true, "backup_codes" jsonb NULL, "phone_number" character varying NULL, "email" character varying NULL, "last_used" timestamptz NULL, "metadata" jsonb NULL, "user_id" character varying NOT NULL, PRIMARY KEY ("id"), CONSTRAINT "mf_as_users_mfa_methods" FOREIGN KEY ("user_id") REFERENCES "users" ("id") ON UPDATE NO ACTION ON DELETE NO ACTION);
-- Create index "mfa_method_user_id" to table: "mf_as"
CREATE UNIQUE INDEX "mfa_method_user_id" ON "mf_as" ("method", "user_id");
-- Create index "mfa_user_id" to table: "mf_as"
CREATE INDEX "mfa_user_id" ON "mf_as" ("user_id");
-- Create "oauth_clients" table
CREATE TABLE "oauth_clients" ("id" character varying NOT NULL, "created_at" timestamptz NOT NULL, "updated_at" timestamptz NOT NULL, "deleted_at" timestamptz NULL, "client_id" character varying NOT NULL, "client_secret" character varying NOT NULL, "client_name" character varying NOT NULL, "client_description" character varying NULL, "client_uri" character varying NULL, "logo_uri" character varying NULL, "redirect_uris" jsonb NOT NULL, "post_logout_redirect_uris" jsonb NULL, "public" boolean NOT NULL DEFAULT false, "active" boolean NOT NULL DEFAULT true, "allowed_cors_origins" jsonb NULL, "allowed_grant_types" jsonb NOT NULL, "token_expiry_seconds" bigint NOT NULL DEFAULT 3600, "refresh_token_expiry_seconds" bigint NOT NULL DEFAULT 2592000, "auth_code_expiry_seconds" bigint NOT NULL DEFAULT 600, "requires_pkce" boolean NOT NULL DEFAULT true, "requires_consent" boolean NOT NULL DEFAULT true, "organization_id" character varying NULL, PRIMARY KEY ("id"), CONSTRAINT "oauth_clients_organizations_oauth_clients" FOREIGN KEY ("organization_id") REFERENCES "organizations" ("id") ON UPDATE NO ACTION ON DELETE SET NULL);
-- Create index "oauth_clients_client_id_key" to table: "oauth_clients"
CREATE UNIQUE INDEX "oauth_clients_client_id_key" ON "oauth_clients" ("client_id");
-- Create index "oauthclient_client_id" to table: "oauth_clients"
CREATE INDEX "oauthclient_client_id" ON "oauth_clients" ("client_id");
-- Create index "oauthclient_organization_id" to table: "oauth_clients"
CREATE INDEX "oauthclient_organization_id" ON "oauth_clients" ("organization_id");
-- Create "oauth_authorizations" table
CREATE TABLE "oauth_authorizations" ("id" character varying NOT NULL, "created_at" timestamptz NOT NULL, "updated_at" timestamptz NOT NULL, "deleted_at" timestamptz NULL, "organization_id" character varying NULL, "code" character varying NULL, "code_challenge" character varying NULL, "code_challenge_method" character varying NULL, "redirect_uri" character varying NOT NULL, "scope_names" jsonb NULL, "used" boolean NOT NULL DEFAULT false, "used_at" timestamptz NOT NULL, "expires_at" timestamptz NOT NULL, "state" character varying NULL, "nonce" character varying NULL, "user_agent" character varying NULL, "ip_address" character varying NULL, "client_id" character varying NOT NULL, "user_id" character varying NOT NULL, PRIMARY KEY ("id"), CONSTRAINT "oauth_authorizations_oauth_clients_authorizations" FOREIGN KEY ("client_id") REFERENCES "oauth_clients" ("id") ON UPDATE NO ACTION ON DELETE NO ACTION, CONSTRAINT "oauth_authorizations_users_oauth_authorizations" FOREIGN KEY ("user_id") REFERENCES "users" ("id") ON UPDATE NO ACTION ON DELETE NO ACTION);
-- Create index "oauth_authorizations_code_key" to table: "oauth_authorizations"
CREATE UNIQUE INDEX "oauth_authorizations_code_key" ON "oauth_authorizations" ("code");
-- Create index "oauthauthorization_client_id" to table: "oauth_authorizations"
CREATE INDEX "oauthauthorization_client_id" ON "oauth_authorizations" ("client_id");
-- Create index "oauthauthorization_code" to table: "oauth_authorizations"
CREATE INDEX "oauthauthorization_code" ON "oauth_authorizations" ("code");
-- Create index "oauthauthorization_expires_at" to table: "oauth_authorizations"
CREATE INDEX "oauthauthorization_expires_at" ON "oauth_authorizations" ("expires_at");
-- Create index "oauthauthorization_organization_id" to table: "oauth_authorizations"
CREATE INDEX "oauthauthorization_organization_id" ON "oauth_authorizations" ("organization_id");
-- Create index "oauthauthorization_user_id" to table: "oauth_authorizations"
CREATE INDEX "oauthauthorization_user_id" ON "oauth_authorizations" ("user_id");
-- Create "oauth_scopes" table
CREATE TABLE "oauth_scopes" ("id" character varying NOT NULL, "created_at" timestamptz NOT NULL, "updated_at" timestamptz NOT NULL, "deleted_at" timestamptz NULL, "name" character varying NOT NULL, "description" character varying NOT NULL, "default_scope" boolean NOT NULL DEFAULT false, "public" boolean NOT NULL DEFAULT true, PRIMARY KEY ("id"));
-- Create index "oauth_scopes_name_key" to table: "oauth_scopes"
CREATE UNIQUE INDEX "oauth_scopes_name_key" ON "oauth_scopes" ("name");
-- Create index "oauthscope_name" to table: "oauth_scopes"
CREATE INDEX "oauthscope_name" ON "oauth_scopes" ("name");
-- Create "oauth_authorization_scopes" table
CREATE TABLE "oauth_authorization_scopes" ("oauth_authorization_id" character varying NOT NULL, "oauth_scope_id" character varying NOT NULL, PRIMARY KEY ("oauth_authorization_id", "oauth_scope_id"), CONSTRAINT "oauth_authorization_scopes_oauth_authorization_id" FOREIGN KEY ("oauth_authorization_id") REFERENCES "oauth_authorizations" ("id") ON UPDATE NO ACTION ON DELETE CASCADE, CONSTRAINT "oauth_authorization_scopes_oauth_scope_id" FOREIGN KEY ("oauth_scope_id") REFERENCES "oauth_scopes" ("id") ON UPDATE NO ACTION ON DELETE CASCADE);
-- Create "oauth_client_scopes" table
CREATE TABLE "oauth_client_scopes" ("oauth_client_id" character varying NOT NULL, "oauth_scope_id" character varying NOT NULL, PRIMARY KEY ("oauth_client_id", "oauth_scope_id"), CONSTRAINT "oauth_client_scopes_oauth_client_id" FOREIGN KEY ("oauth_client_id") REFERENCES "oauth_clients" ("id") ON UPDATE NO ACTION ON DELETE CASCADE, CONSTRAINT "oauth_client_scopes_oauth_scope_id" FOREIGN KEY ("oauth_scope_id") REFERENCES "oauth_scopes" ("id") ON UPDATE NO ACTION ON DELETE CASCADE);
-- Create "oauth_tokens" table
CREATE TABLE "oauth_tokens" ("id" character varying NOT NULL, "created_at" timestamptz NOT NULL, "updated_at" timestamptz NOT NULL, "deleted_at" timestamptz NULL, "access_token" character varying NOT NULL, "refresh_token" character varying NULL, "token_type" character varying NOT NULL DEFAULT 'bearer', "organization_id" character varying NULL, "scope_names" jsonb NULL, "expires_in" bigint NOT NULL DEFAULT 3600, "expires_at" timestamptz NOT NULL, "refresh_token_expires_at" timestamptz NULL, "revoked" boolean NOT NULL DEFAULT false, "revoked_at" timestamptz NULL, "ip_address" character varying NULL, "user_agent" character varying NULL, "client_id" character varying NOT NULL, "user_id" character varying NOT NULL, PRIMARY KEY ("id"), CONSTRAINT "oauth_tokens_oauth_clients_tokens" FOREIGN KEY ("client_id") REFERENCES "oauth_clients" ("id") ON UPDATE NO ACTION ON DELETE NO ACTION, CONSTRAINT "oauth_tokens_users_oauth_tokens" FOREIGN KEY ("user_id") REFERENCES "users" ("id") ON UPDATE NO ACTION ON DELETE NO ACTION);
-- Create index "oauth_tokens_access_token_key" to table: "oauth_tokens"
CREATE UNIQUE INDEX "oauth_tokens_access_token_key" ON "oauth_tokens" ("access_token");
-- Create index "oauth_tokens_refresh_token_key" to table: "oauth_tokens"
CREATE UNIQUE INDEX "oauth_tokens_refresh_token_key" ON "oauth_tokens" ("refresh_token");
-- Create index "oauthtoken_access_token" to table: "oauth_tokens"
CREATE INDEX "oauthtoken_access_token" ON "oauth_tokens" ("access_token");
-- Create index "oauthtoken_client_id" to table: "oauth_tokens"
CREATE INDEX "oauthtoken_client_id" ON "oauth_tokens" ("client_id");
-- Create index "oauthtoken_expires_at" to table: "oauth_tokens"
CREATE INDEX "oauthtoken_expires_at" ON "oauth_tokens" ("expires_at");
-- Create index "oauthtoken_organization_id" to table: "oauth_tokens"
CREATE INDEX "oauthtoken_organization_id" ON "oauth_tokens" ("organization_id");
-- Create index "oauthtoken_refresh_token" to table: "oauth_tokens"
CREATE INDEX "oauthtoken_refresh_token" ON "oauth_tokens" ("refresh_token");
-- Create index "oauthtoken_user_id" to table: "oauth_tokens"
CREATE INDEX "oauthtoken_user_id" ON "oauth_tokens" ("user_id");
-- Create "oauth_token_scopes" table
CREATE TABLE "oauth_token_scopes" ("oauth_token_id" character varying NOT NULL, "oauth_scope_id" character varying NOT NULL, PRIMARY KEY ("oauth_token_id", "oauth_scope_id"), CONSTRAINT "oauth_token_scopes_oauth_scope_id" FOREIGN KEY ("oauth_scope_id") REFERENCES "oauth_scopes" ("id") ON UPDATE NO ACTION ON DELETE CASCADE, CONSTRAINT "oauth_token_scopes_oauth_token_id" FOREIGN KEY ("oauth_token_id") REFERENCES "oauth_tokens" ("id") ON UPDATE NO ACTION ON DELETE CASCADE);
-- Create "feature_flags" table
CREATE TABLE "feature_flags" ("id" character varying NOT NULL, "created_at" timestamptz NOT NULL, "updated_at" timestamptz NOT NULL, "deleted_at" timestamptz NULL, "name" character varying NOT NULL, "key" character varying NOT NULL, "description" character varying NULL, "enabled" boolean NOT NULL DEFAULT false, "is_premium" boolean NOT NULL DEFAULT false, "component" character varying NOT NULL, PRIMARY KEY ("id"));
-- Create index "feature_flags_key_key" to table: "feature_flags"
CREATE UNIQUE INDEX "feature_flags_key_key" ON "feature_flags" ("key");
-- Create index "feature_flags_name_key" to table: "feature_flags"
CREATE UNIQUE INDEX "feature_flags_name_key" ON "feature_flags" ("name");
-- Create index "featureflag_component" to table: "feature_flags"
CREATE INDEX "featureflag_component" ON "feature_flags" ("component");
-- Create index "featureflag_key" to table: "feature_flags"
CREATE INDEX "featureflag_key" ON "feature_flags" ("key");
-- Create "organization_features" table
CREATE TABLE "organization_features" ("id" character varying NOT NULL, "created_at" timestamptz NOT NULL, "updated_at" timestamptz NOT NULL, "deleted_at" timestamptz NULL, "enabled" boolean NOT NULL DEFAULT true, "settings" jsonb NULL, "feature_id" character varying NOT NULL, "organization_id" character varying NOT NULL, PRIMARY KEY ("id"), CONSTRAINT "organization_features_feature_flags_organization_features" FOREIGN KEY ("feature_id") REFERENCES "feature_flags" ("id") ON UPDATE NO ACTION ON DELETE NO ACTION, CONSTRAINT "organization_features_organizations_feature_flags" FOREIGN KEY ("organization_id") REFERENCES "organizations" ("id") ON UPDATE NO ACTION ON DELETE NO ACTION);
-- Create index "organizationfeature_feature_id" to table: "organization_features"
CREATE INDEX "organizationfeature_feature_id" ON "organization_features" ("feature_id");
-- Create index "organizationfeature_organization_id" to table: "organization_features"
CREATE INDEX "organizationfeature_organization_id" ON "organization_features" ("organization_id");
-- Create index "organizationfeature_organization_id_feature_id" to table: "organization_features"
CREATE UNIQUE INDEX "organizationfeature_organization_id_feature_id" ON "organization_features" ("organization_id", "feature_id");
-- Create "passkeys" table
CREATE TABLE "passkeys" ("id" character varying NOT NULL, "created_at" timestamptz NOT NULL, "updated_at" timestamptz NOT NULL, "deleted_at" timestamptz NULL, "name" character varying NOT NULL, "credential_id" character varying NOT NULL, "public_key" bytea NOT NULL, "sign_count" bigint NOT NULL DEFAULT 0, "active" boolean NOT NULL DEFAULT true, "device_type" character varying NULL, "aaguid" character varying NULL, "last_used" timestamptz NULL, "transports" jsonb NULL, "attestation" jsonb NULL, "backup_state" boolean NULL, "backup_eligible" boolean NULL, "user_agent" character varying NULL, "ip_address" character varying NULL, "user_id" character varying NOT NULL, PRIMARY KEY ("id"), CONSTRAINT "passkeys_users_passkeys" FOREIGN KEY ("user_id") REFERENCES "users" ("id") ON UPDATE NO ACTION ON DELETE NO ACTION);
-- Create index "passkey_credential_id" to table: "passkeys"
CREATE INDEX "passkey_credential_id" ON "passkeys" ("credential_id");
-- Create index "passkey_user_id" to table: "passkeys"
CREATE INDEX "passkey_user_id" ON "passkeys" ("user_id");
-- Create index "passkeys_credential_id_key" to table: "passkeys"
CREATE UNIQUE INDEX "passkeys_credential_id_key" ON "passkeys" ("credential_id");
-- Create "permissions" table
CREATE TABLE "permissions" ("id" character varying NOT NULL, "created_at" timestamptz NOT NULL, "updated_at" timestamptz NOT NULL, "deleted_at" timestamptz NULL, "name" character varying NOT NULL, "display_name" character varying NULL, "description" character varying NOT NULL, "resource" character varying NOT NULL, "action" character varying NOT NULL, "category" character varying NOT NULL, "applicable_user_types" jsonb NOT NULL, "applicable_contexts" jsonb NOT NULL, "conditions" character varying NULL, "system" boolean NOT NULL DEFAULT false, "dangerous" boolean NOT NULL DEFAULT false, "risk_level" bigint NOT NULL DEFAULT 1, "created_by" character varying NULL, "active" boolean NOT NULL DEFAULT true, "permission_group" character varying NULL, PRIMARY KEY ("id"));
-- Create index "permission_active" to table: "permissions"
CREATE INDEX "permission_active" ON "permissions" ("active");
-- Create index "permission_category" to table: "permissions"
CREATE INDEX "permission_category" ON "permissions" ("category");
-- Create index "permission_created_by" to table: "permissions"
CREATE INDEX "permission_created_by" ON "permissions" ("created_by");
-- Create index "permission_dangerous" to table: "permissions"
CREATE INDEX "permission_dangerous" ON "permissions" ("dangerous");
-- Create index "permission_name" to table: "permissions"
CREATE INDEX "permission_name" ON "permissions" ("name");
-- Create index "permission_permission_group" to table: "permissions"
CREATE INDEX "permission_permission_group" ON "permissions" ("permission_group");
-- Create index "permission_resource_action" to table: "permissions"
CREATE UNIQUE INDEX "permission_resource_action" ON "permissions" ("resource", "action");
-- Create index "permission_risk_level" to table: "permissions"
CREATE INDEX "permission_risk_level" ON "permissions" ("risk_level");
-- Create index "permission_system" to table: "permissions"
CREATE INDEX "permission_system" ON "permissions" ("system");
-- Create index "permissions_name_key" to table: "permissions"
CREATE UNIQUE INDEX "permissions_name_key" ON "permissions" ("name");
-- Create "permission_dependencies" table
CREATE TABLE "permission_dependencies" ("id" character varying NOT NULL, "created_at" timestamptz NOT NULL, "updated_at" timestamptz NOT NULL, "deleted_at" timestamptz NULL, "dependency_type" character varying NOT NULL DEFAULT 'required', "condition" character varying NULL, "active" boolean NOT NULL DEFAULT true, "created_by" character varying NULL, "permission_id" character varying NOT NULL, "required_permission_id" character varying NOT NULL, PRIMARY KEY ("id"), CONSTRAINT "permission_dependencies_permissions_dependencies" FOREIGN KEY ("permission_id") REFERENCES "permissions" ("id") ON UPDATE NO ACTION ON DELETE NO ACTION, CONSTRAINT "permission_dependencies_permissions_dependents" FOREIGN KEY ("required_permission_id") REFERENCES "permissions" ("id") ON UPDATE NO ACTION ON DELETE NO ACTION);
-- Create index "permissiondependency_active" to table: "permission_dependencies"
CREATE INDEX "permissiondependency_active" ON "permission_dependencies" ("active");
-- Create index "permissiondependency_created_by" to table: "permission_dependencies"
CREATE INDEX "permissiondependency_created_by" ON "permission_dependencies" ("created_by");
-- Create index "permissiondependency_dependency_type" to table: "permission_dependencies"
CREATE INDEX "permissiondependency_dependency_type" ON "permission_dependencies" ("dependency_type");
-- Create index "permissiondependency_permission_id" to table: "permission_dependencies"
CREATE INDEX "permissiondependency_permission_id" ON "permission_dependencies" ("permission_id");
-- Create index "permissiondependency_permission_id_required_permission_id" to table: "permission_dependencies"
CREATE UNIQUE INDEX "permissiondependency_permission_id_required_permission_id" ON "permission_dependencies" ("permission_id", "required_permission_id");
-- Create index "permissiondependency_required_permission_id" to table: "permission_dependencies"
CREATE INDEX "permissiondependency_required_permission_id" ON "permission_dependencies" ("required_permission_id");
-- Create "permission_required_permissions" table
CREATE TABLE "permission_required_permissions" ("permission_id" character varying NOT NULL, "dependent_permission_id" character varying NOT NULL, PRIMARY KEY ("permission_id", "dependent_permission_id"), CONSTRAINT "permission_required_permissions_dependent_permission_id" FOREIGN KEY ("dependent_permission_id") REFERENCES "permissions" ("id") ON UPDATE NO ACTION ON DELETE CASCADE, CONSTRAINT "permission_required_permissions_permission_id" FOREIGN KEY ("permission_id") REFERENCES "permissions" ("id") ON UPDATE NO ACTION ON DELETE CASCADE);
-- Create "role_permissions" table
CREATE TABLE "role_permissions" ("role_id" character varying NOT NULL, "permission_id" character varying NOT NULL, PRIMARY KEY ("role_id", "permission_id"), CONSTRAINT "role_permissions_permission_id" FOREIGN KEY ("permission_id") REFERENCES "permissions" ("id") ON UPDATE NO ACTION ON DELETE CASCADE, CONSTRAINT "role_permissions_role_id" FOREIGN KEY ("role_id") REFERENCES "roles" ("id") ON UPDATE NO ACTION ON DELETE CASCADE);
-- Create "sms_templates" table
CREATE TABLE "sms_templates" ("id" character varying NOT NULL, "created_at" timestamptz NOT NULL, "updated_at" timestamptz NOT NULL, "deleted_at" timestamptz NULL, "name" character varying NOT NULL, "content" character varying NOT NULL, "type" character varying NOT NULL, "active" boolean NOT NULL DEFAULT true, "system" boolean NOT NULL DEFAULT false, "locale" character varying NOT NULL DEFAULT 'en', "max_length" bigint NOT NULL DEFAULT 160, "message_type" character varying NOT NULL DEFAULT 'transactional', "estimated_segments" bigint NULL DEFAULT 1, "estimated_cost" double precision NULL DEFAULT 0, "currency" character varying NULL DEFAULT 'USD', "variables" jsonb NULL, "metadata" jsonb NULL, "last_used_at" timestamptz NULL, "usage_count" bigint NOT NULL DEFAULT 0, "organization_id" character varying NULL, PRIMARY KEY ("id"), CONSTRAINT "sms_templates_organizations_sms_templates" FOREIGN KEY ("organization_id") REFERENCES "organizations" ("id") ON UPDATE NO ACTION ON DELETE SET NULL);
-- Create index "smstemplate_active" to table: "sms_templates"
CREATE INDEX "smstemplate_active" ON "sms_templates" ("active");
-- Create index "smstemplate_last_used_at" to table: "sms_templates"
CREATE INDEX "smstemplate_last_used_at" ON "sms_templates" ("last_used_at");
-- Create index "smstemplate_message_type" to table: "sms_templates"
CREATE INDEX "smstemplate_message_type" ON "sms_templates" ("message_type");
-- Create index "smstemplate_organization_id" to table: "sms_templates"
CREATE INDEX "smstemplate_organization_id" ON "sms_templates" ("organization_id");
-- Create index "smstemplate_organization_id_type" to table: "sms_templates"
CREATE INDEX "smstemplate_organization_id_type" ON "sms_templates" ("organization_id", "type");
-- Create index "smstemplate_organization_id_type_locale" to table: "sms_templates"
CREATE UNIQUE INDEX "smstemplate_organization_id_type_locale" ON "sms_templates" ("organization_id", "type", "locale");
-- Create index "smstemplate_system" to table: "sms_templates"
CREATE INDEX "smstemplate_system" ON "sms_templates" ("system");
-- Create index "smstemplate_type" to table: "sms_templates"
CREATE INDEX "smstemplate_type" ON "sms_templates" ("type");
-- Create index "smstemplate_usage_count" to table: "sms_templates"
CREATE INDEX "smstemplate_usage_count" ON "sms_templates" ("usage_count");
-- Create "user_permissions" table
CREATE TABLE "user_permissions" ("id" character varying NOT NULL, "created_at" timestamptz NOT NULL, "updated_at" timestamptz NOT NULL, "deleted_at" timestamptz NULL, "context_type" character varying NOT NULL, "resource_type" character varying NULL, "resource_id" character varying NULL, "permission_type" character varying NOT NULL DEFAULT 'grant', "assigned_at" timestamptz NOT NULL, "expires_at" timestamptz NULL, "active" boolean NOT NULL DEFAULT true, "conditions" jsonb NULL, "reason" character varying NULL, "permission_id" character varying NOT NULL, "user_id" character varying NOT NULL, "assigned_by" character varying NULL, "context_id" character varying NULL, PRIMARY KEY ("id"), CONSTRAINT "user_permissions_organizations_organization_context" FOREIGN KEY ("context_id") REFERENCES "organizations" ("id") ON UPDATE NO ACTION ON DELETE SET NULL, CONSTRAINT "user_permissions_permissions_user_assignments" FOREIGN KEY ("permission_id") REFERENCES "permissions" ("id") ON UPDATE NO ACTION ON DELETE NO ACTION, CONSTRAINT "user_permissions_users_assigned_user_permissions" FOREIGN KEY ("assigned_by") REFERENCES "users" ("id") ON UPDATE NO ACTION ON DELETE SET NULL, CONSTRAINT "user_permissions_users_user_permissions" FOREIGN KEY ("user_id") REFERENCES "users" ("id") ON UPDATE NO ACTION ON DELETE NO ACTION);
-- Create index "userpermission_active" to table: "user_permissions"
CREATE INDEX "userpermission_active" ON "user_permissions" ("active");
-- Create index "userpermission_assigned_by" to table: "user_permissions"
CREATE INDEX "userpermission_assigned_by" ON "user_permissions" ("assigned_by");
-- Create index "userpermission_context_id" to table: "user_permissions"
CREATE INDEX "userpermission_context_id" ON "user_permissions" ("context_id");
-- Create index "userpermission_context_type" to table: "user_permissions"
CREATE INDEX "userpermission_context_type" ON "user_permissions" ("context_type");
-- Create index "userpermission_context_type_context_id_active" to table: "user_permissions"
CREATE INDEX "userpermission_context_type_context_id_active" ON "user_permissions" ("context_type", "context_id", "active");
-- Create index "userpermission_expires_at" to table: "user_permissions"
CREATE INDEX "userpermission_expires_at" ON "user_permissions" ("expires_at");
-- Create index "userpermission_permission_id" to table: "user_permissions"
CREATE INDEX "userpermission_permission_id" ON "user_permissions" ("permission_id");
-- Create index "userpermission_permission_type" to table: "user_permissions"
CREATE INDEX "userpermission_permission_type" ON "user_permissions" ("permission_type");
-- Create index "userpermission_resource_id" to table: "user_permissions"
CREATE INDEX "userpermission_resource_id" ON "user_permissions" ("resource_id");
-- Create index "userpermission_resource_type" to table: "user_permissions"
CREATE INDEX "userpermission_resource_type" ON "user_permissions" ("resource_type");
-- Create index "userpermission_user_id" to table: "user_permissions"
CREATE INDEX "userpermission_user_id" ON "user_permissions" ("user_id");
-- Create index "userpermission_user_id_context_type_context_id" to table: "user_permissions"
CREATE INDEX "userpermission_user_id_context_type_context_id" ON "user_permissions" ("user_id", "context_type", "context_id");
-- Create index "userpermission_user_id_permiss_29e6bf1065fb7a61fc9825b79f34a10e" to table: "user_permissions"
CREATE UNIQUE INDEX "userpermission_user_id_permiss_29e6bf1065fb7a61fc9825b79f34a10e" ON "user_permissions" ("user_id", "permission_id", "context_type", "context_id", "resource_type", "resource_id");
-- Create index "userpermission_user_id_resource_type_resource_id" to table: "user_permissions"
CREATE INDEX "userpermission_user_id_resource_type_resource_id" ON "user_permissions" ("user_id", "resource_type", "resource_id");
-- Create "user_roles" table
CREATE TABLE "user_roles" ("id" character varying NOT NULL, "created_at" timestamptz NOT NULL, "updated_at" timestamptz NOT NULL, "deleted_at" timestamptz NULL, "context_type" character varying NOT NULL, "assigned_at" timestamptz NOT NULL, "expires_at" timestamptz NULL, "active" boolean NOT NULL DEFAULT true, "conditions" jsonb NULL, "role_id" character varying NOT NULL, "user_id" character varying NOT NULL, "assigned_by" character varying NULL, "context_id" character varying NULL, PRIMARY KEY ("id"), CONSTRAINT "user_roles_organizations_organization_context" FOREIGN KEY ("context_id") REFERENCES "organizations" ("id") ON UPDATE NO ACTION ON DELETE SET NULL, CONSTRAINT "user_roles_roles_user_assignments" FOREIGN KEY ("role_id") REFERENCES "roles" ("id") ON UPDATE NO ACTION ON DELETE NO ACTION, CONSTRAINT "user_roles_users_assigned_user_roles" FOREIGN KEY ("assigned_by") REFERENCES "users" ("id") ON UPDATE NO ACTION ON DELETE SET NULL, CONSTRAINT "user_roles_users_user_roles" FOREIGN KEY ("user_id") REFERENCES "users" ("id") ON UPDATE NO ACTION ON DELETE NO ACTION);
-- Create index "userrole_active" to table: "user_roles"
CREATE INDEX "userrole_active" ON "user_roles" ("active");
-- Create index "userrole_assigned_by" to table: "user_roles"
CREATE INDEX "userrole_assigned_by" ON "user_roles" ("assigned_by");
-- Create index "userrole_context_id" to table: "user_roles"
CREATE INDEX "userrole_context_id" ON "user_roles" ("context_id");
-- Create index "userrole_context_type" to table: "user_roles"
CREATE INDEX "userrole_context_type" ON "user_roles" ("context_type");
-- Create index "userrole_context_type_context_id" to table: "user_roles"
CREATE INDEX "userrole_context_type_context_id" ON "user_roles" ("context_type", "context_id");
-- Create index "userrole_expires_at" to table: "user_roles"
CREATE INDEX "userrole_expires_at" ON "user_roles" ("expires_at");
-- Create index "userrole_role_id" to table: "user_roles"
CREATE INDEX "userrole_role_id" ON "user_roles" ("role_id");
-- Create index "userrole_user_id" to table: "user_roles"
CREATE INDEX "userrole_user_id" ON "user_roles" ("user_id");
-- Create index "userrole_user_id_context_type_context_id" to table: "user_roles"
CREATE INDEX "userrole_user_id_context_type_context_id" ON "user_roles" ("user_id", "context_type", "context_id");
-- Create index "userrole_user_id_role_id_context_type_context_id" to table: "user_roles"
CREATE UNIQUE INDEX "userrole_user_id_role_id_context_type_context_id" ON "user_roles" ("user_id", "role_id", "context_type", "context_id");
-- Create "user_system_roles" table
CREATE TABLE "user_system_roles" ("user_id" character varying NOT NULL, "role_id" character varying NOT NULL, PRIMARY KEY ("user_id", "role_id"), CONSTRAINT "user_system_roles_role_id" FOREIGN KEY ("role_id") REFERENCES "roles" ("id") ON UPDATE NO ACTION ON DELETE CASCADE, CONSTRAINT "user_system_roles_user_id" FOREIGN KEY ("user_id") REFERENCES "users" ("id") ON UPDATE NO ACTION ON DELETE CASCADE);
-- Create "verifications" table
CREATE TABLE "verifications" ("id" character varying NOT NULL, "created_at" timestamptz NOT NULL, "updated_at" timestamptz NOT NULL, "deleted_at" timestamptz NULL, "type" character varying NOT NULL, "token" character varying NOT NULL, "email" character varying NULL, "phone_number" character varying NULL, "redirect_url" character varying NULL, "used" boolean NOT NULL DEFAULT false, "used_at" timestamptz NULL, "attempts" bigint NOT NULL DEFAULT 0, "expires_at" timestamptz NOT NULL, "ip_address" character varying NULL, "user_agent" character varying NULL, "attestation" jsonb NULL, "user_id" character varying NOT NULL, PRIMARY KEY ("id"), CONSTRAINT "verifications_users_verifications" FOREIGN KEY ("user_id") REFERENCES "users" ("id") ON UPDATE NO ACTION ON DELETE NO ACTION);
-- Create index "verification_email" to table: "verifications"
CREATE INDEX "verification_email" ON "verifications" ("email");
-- Create index "verification_expires_at" to table: "verifications"
CREATE INDEX "verification_expires_at" ON "verifications" ("expires_at");
-- Create index "verification_phone_number" to table: "verifications"
CREATE INDEX "verification_phone_number" ON "verifications" ("phone_number");
-- Create index "verification_token" to table: "verifications"
CREATE INDEX "verification_token" ON "verifications" ("token");
-- Create index "verification_user_id" to table: "verifications"
CREATE INDEX "verification_user_id" ON "verifications" ("user_id");
-- Create index "verifications_token_key" to table: "verifications"
CREATE UNIQUE INDEX "verifications_token_key" ON "verifications" ("token");
-- Create "webhooks" table
CREATE TABLE "webhooks" ("id" character varying NOT NULL, "created_at" timestamptz NOT NULL, "updated_at" timestamptz NOT NULL, "deleted_at" timestamptz NULL, "name" character varying NOT NULL, "url" character varying NOT NULL, "secret" character varying NOT NULL, "active" boolean NOT NULL DEFAULT true, "event_types" jsonb NOT NULL, "version" character varying NOT NULL DEFAULT 'v1', "retry_count" bigint NOT NULL DEFAULT 3, "timeout_ms" bigint NOT NULL DEFAULT 5000, "format" character varying NOT NULL DEFAULT 'json', "metadata" jsonb NULL, "headers" jsonb NULL, "organization_id" character varying NOT NULL, PRIMARY KEY ("id"), CONSTRAINT "webhooks_organizations_webhooks" FOREIGN KEY ("organization_id") REFERENCES "organizations" ("id") ON UPDATE NO ACTION ON DELETE NO ACTION);
-- Create index "webhook_organization_id" to table: "webhooks"
CREATE INDEX "webhook_organization_id" ON "webhooks" ("organization_id");
-- Create "webhook_events" table
CREATE TABLE "webhook_events" ("id" character varying NOT NULL, "created_at" timestamptz NOT NULL, "updated_at" timestamptz NOT NULL, "deleted_at" timestamptz NULL, "event_type" character varying NOT NULL, "headers" jsonb NULL, "payload" jsonb NULL, "delivered" boolean NOT NULL DEFAULT false, "delivered_at" timestamptz NULL, "attempts" bigint NOT NULL DEFAULT 0, "next_retry" timestamptz NULL, "status_code" bigint NULL, "response_body" character varying NULL, "error" character varying NULL, "webhook_id" character varying NOT NULL, PRIMARY KEY ("id"), CONSTRAINT "webhook_events_webhooks_events" FOREIGN KEY ("webhook_id") REFERENCES "webhooks" ("id") ON UPDATE NO ACTION ON DELETE NO ACTION);
-- Create index "webhookevent_delivered" to table: "webhook_events"
CREATE INDEX "webhookevent_delivered" ON "webhook_events" ("delivered");
-- Create index "webhookevent_event_type" to table: "webhook_events"
CREATE INDEX "webhookevent_event_type" ON "webhook_events" ("event_type");
-- Create index "webhookevent_next_retry" to table: "webhook_events"
CREATE INDEX "webhookevent_next_retry" ON "webhook_events" ("next_retry");
-- Create index "webhookevent_webhook_id" to table: "webhook_events"
CREATE INDEX "webhookevent_webhook_id" ON "webhook_events" ("webhook_id");
