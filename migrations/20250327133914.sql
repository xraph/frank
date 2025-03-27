-- Create "email_templates" table
CREATE TABLE "email_templates" ("id" character varying NOT NULL, "created_at" timestamptz NOT NULL, "updated_at" timestamptz NOT NULL, "name" character varying NOT NULL, "subject" character varying NOT NULL, "type" character varying NOT NULL, "html_content" character varying NOT NULL, "text_content" character varying NULL, "organization_id" character varying NULL, "active" boolean NOT NULL DEFAULT true, "system" boolean NOT NULL DEFAULT false, "locale" character varying NOT NULL DEFAULT 'en', "metadata" jsonb NULL, PRIMARY KEY ("id"));
-- Create index "emailtemplate_organization_id" to table: "email_templates"
CREATE INDEX "emailtemplate_organization_id" ON "email_templates" ("organization_id");
-- Create index "emailtemplate_organization_id_type_locale" to table: "email_templates"
CREATE UNIQUE INDEX "emailtemplate_organization_id_type_locale" ON "email_templates" ("organization_id", "type", "locale");
-- Create index "emailtemplate_type" to table: "email_templates"
CREATE INDEX "emailtemplate_type" ON "email_templates" ("type");
-- Create "organizations" table
CREATE TABLE "organizations" ("id" character varying NOT NULL, "created_at" timestamptz NOT NULL, "updated_at" timestamptz NOT NULL, "name" character varying NOT NULL, "slug" character varying NOT NULL, "domain" character varying NULL, "logo_url" character varying NULL, "plan" character varying NOT NULL DEFAULT 'free', "active" boolean NOT NULL DEFAULT true, "metadata" jsonb NULL, "trial_ends_at" timestamptz NULL, "trial_used" boolean NOT NULL DEFAULT false, PRIMARY KEY ("id"));
-- Create index "organization_domain" to table: "organizations"
CREATE INDEX "organization_domain" ON "organizations" ("domain");
-- Create index "organization_slug" to table: "organizations"
CREATE INDEX "organization_slug" ON "organizations" ("slug");
-- Create index "organizations_slug_key" to table: "organizations"
CREATE UNIQUE INDEX "organizations_slug_key" ON "organizations" ("slug");
-- Create "sso_states" table
CREATE TABLE "sso_states" ("id" character varying NOT NULL, "created_at" timestamptz NOT NULL, "updated_at" timestamptz NOT NULL, "state" character varying NOT NULL, "data" character varying NOT NULL, "expires_at" timestamptz NOT NULL, PRIMARY KEY ("id"));
-- Create index "sso_states_state_key" to table: "sso_states"
CREATE UNIQUE INDEX "sso_states_state_key" ON "sso_states" ("state");
-- Create index "ssostate_expires_at" to table: "sso_states"
CREATE INDEX "ssostate_expires_at" ON "sso_states" ("expires_at");
-- Create "users" table
CREATE TABLE "users" ("id" character varying NOT NULL, "created_at" timestamptz NOT NULL, "updated_at" timestamptz NOT NULL, "email" character varying NOT NULL, "phone_number" character varying NULL, "first_name" character varying NULL, "last_name" character varying NULL, "password_hash" character varying NULL, "email_verified" boolean NOT NULL DEFAULT false, "phone_verified" boolean NOT NULL DEFAULT false, "active" boolean NOT NULL DEFAULT true, "last_login" timestamptz NULL, "last_password_change" timestamptz NULL, "metadata" jsonb NULL, "profile_image_url" character varying NULL, "primary_organization_id" character varying NULL, "locale" character varying NOT NULL DEFAULT 'en', PRIMARY KEY ("id"));
-- Create index "user_email" to table: "users"
CREATE INDEX "user_email" ON "users" ("email");
-- Create index "user_phone_number" to table: "users"
CREATE UNIQUE INDEX "user_phone_number" ON "users" ("phone_number");
-- Create index "users_email_key" to table: "users"
CREATE UNIQUE INDEX "users_email_key" ON "users" ("email");
-- Create "api_keys" table
CREATE TABLE "api_keys" ("id" character varying NOT NULL, "created_at" timestamptz NOT NULL, "updated_at" timestamptz NOT NULL, "name" character varying NOT NULL, "key" character varying NOT NULL, "hashed_key" character varying NOT NULL, "type" character varying NOT NULL DEFAULT 'server', "active" boolean NOT NULL DEFAULT true, "permissions" jsonb NULL, "scopes" jsonb NULL, "metadata" jsonb NULL, "last_used" timestamptz NULL, "expires_at" timestamptz NULL, "organization_id" character varying NULL, "user_id" character varying NULL, PRIMARY KEY ("id"), CONSTRAINT "api_keys_organizations_api_keys" FOREIGN KEY ("organization_id") REFERENCES "organizations" ("id") ON UPDATE NO ACTION ON DELETE SET NULL, CONSTRAINT "api_keys_users_api_keys" FOREIGN KEY ("user_id") REFERENCES "users" ("id") ON UPDATE NO ACTION ON DELETE SET NULL);
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
-- Create "identity_providers" table
CREATE TABLE "identity_providers" ("id" character varying NOT NULL, "created_at" timestamptz NOT NULL, "updated_at" timestamptz NOT NULL, "name" character varying NOT NULL, "provider_type" character varying NOT NULL, "client_id" character varying NULL, "client_secret" character varying NULL, "issuer" character varying NULL, "authorization_endpoint" character varying NULL, "token_endpoint" character varying NULL, "userinfo_endpoint" character varying NULL, "jwks_uri" character varying NULL, "metadata_url" character varying NULL, "redirect_uri" character varying NULL, "certificate" character varying NULL, "private_key" character varying NULL, "active" boolean NOT NULL DEFAULT true, "primary" boolean NOT NULL DEFAULT false, "domains" jsonb NULL, "attributes_mapping" jsonb NULL, "metadata" jsonb NULL, "organization_id" character varying NOT NULL, PRIMARY KEY ("id"), CONSTRAINT "identity_providers_organizations_identity_providers" FOREIGN KEY ("organization_id") REFERENCES "organizations" ("id") ON UPDATE NO ACTION ON DELETE NO ACTION);
-- Create index "identityprovider_organization_id" to table: "identity_providers"
CREATE INDEX "identityprovider_organization_id" ON "identity_providers" ("organization_id");
-- Create index "identityprovider_provider_type" to table: "identity_providers"
CREATE INDEX "identityprovider_provider_type" ON "identity_providers" ("provider_type");
-- Create "mf_as" table
CREATE TABLE "mf_as" ("id" character varying NOT NULL, "created_at" timestamptz NOT NULL, "updated_at" timestamptz NOT NULL, "method" character varying NOT NULL, "secret" character varying NOT NULL, "verified" boolean NOT NULL DEFAULT false, "active" boolean NOT NULL DEFAULT true, "backup_codes" jsonb NULL, "phone_number" character varying NULL, "email" character varying NULL, "last_used" timestamptz NULL, "metadata" jsonb NULL, "user_id" character varying NOT NULL, PRIMARY KEY ("id"), CONSTRAINT "mf_as_users_mfa_methods" FOREIGN KEY ("user_id") REFERENCES "users" ("id") ON UPDATE NO ACTION ON DELETE NO ACTION);
-- Create index "mfa_method_user_id" to table: "mf_as"
CREATE UNIQUE INDEX "mfa_method_user_id" ON "mf_as" ("method", "user_id");
-- Create index "mfa_user_id" to table: "mf_as"
CREATE INDEX "mfa_user_id" ON "mf_as" ("user_id");
-- Create "oauth_clients" table
CREATE TABLE "oauth_clients" ("id" character varying NOT NULL, "created_at" timestamptz NOT NULL, "updated_at" timestamptz NOT NULL, "client_id" character varying NOT NULL, "client_secret" character varying NOT NULL, "client_name" character varying NOT NULL, "client_description" character varying NULL, "client_uri" character varying NULL, "logo_uri" character varying NULL, "redirect_uris" jsonb NOT NULL, "post_logout_redirect_uris" jsonb NULL, "public" boolean NOT NULL DEFAULT false, "active" boolean NOT NULL DEFAULT true, "allowed_cors_origins" jsonb NULL, "allowed_grant_types" jsonb NOT NULL, "token_expiry_seconds" bigint NOT NULL DEFAULT 3600, "refresh_token_expiry_seconds" bigint NOT NULL DEFAULT 2592000, "auth_code_expiry_seconds" bigint NOT NULL DEFAULT 600, "requires_pkce" boolean NOT NULL DEFAULT true, "requires_consent" boolean NOT NULL DEFAULT true, "organization_id" character varying NULL, PRIMARY KEY ("id"), CONSTRAINT "oauth_clients_organizations_oauth_clients" FOREIGN KEY ("organization_id") REFERENCES "organizations" ("id") ON UPDATE NO ACTION ON DELETE SET NULL);
-- Create index "oauth_clients_client_id_key" to table: "oauth_clients"
CREATE UNIQUE INDEX "oauth_clients_client_id_key" ON "oauth_clients" ("client_id");
-- Create index "oauthclient_client_id" to table: "oauth_clients"
CREATE INDEX "oauthclient_client_id" ON "oauth_clients" ("client_id");
-- Create index "oauthclient_organization_id" to table: "oauth_clients"
CREATE INDEX "oauthclient_organization_id" ON "oauth_clients" ("organization_id");
-- Create "oauth_authorizations" table
CREATE TABLE "oauth_authorizations" ("id" character varying NOT NULL, "created_at" timestamptz NOT NULL, "updated_at" timestamptz NOT NULL, "organization_id" character varying NULL, "code" character varying NULL, "code_challenge" character varying NULL, "code_challenge_method" character varying NULL, "redirect_uri" character varying NOT NULL, "scope_names" jsonb NULL, "used" boolean NOT NULL DEFAULT false, "used_at" timestamptz NOT NULL, "expires_at" timestamptz NOT NULL, "state" character varying NULL, "nonce" character varying NULL, "client_id" character varying NOT NULL, "user_id" character varying NOT NULL, PRIMARY KEY ("id"), CONSTRAINT "oauth_authorizations_oauth_clients_authorizations" FOREIGN KEY ("client_id") REFERENCES "oauth_clients" ("id") ON UPDATE NO ACTION ON DELETE NO ACTION, CONSTRAINT "oauth_authorizations_users_oauth_authorizations" FOREIGN KEY ("user_id") REFERENCES "users" ("id") ON UPDATE NO ACTION ON DELETE NO ACTION);
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
CREATE TABLE "oauth_scopes" ("id" character varying NOT NULL, "created_at" timestamptz NOT NULL, "updated_at" timestamptz NOT NULL, "name" character varying NOT NULL, "description" character varying NOT NULL, "default_scope" boolean NOT NULL DEFAULT false, "public" boolean NOT NULL DEFAULT true, PRIMARY KEY ("id"));
-- Create index "oauth_scopes_name_key" to table: "oauth_scopes"
CREATE UNIQUE INDEX "oauth_scopes_name_key" ON "oauth_scopes" ("name");
-- Create index "oauthscope_name" to table: "oauth_scopes"
CREATE INDEX "oauthscope_name" ON "oauth_scopes" ("name");
-- Create "oauth_authorization_scopes" table
CREATE TABLE "oauth_authorization_scopes" ("oauth_authorization_id" character varying NOT NULL, "oauth_scope_id" character varying NOT NULL, PRIMARY KEY ("oauth_authorization_id", "oauth_scope_id"), CONSTRAINT "oauth_authorization_scopes_oauth_authorization_id" FOREIGN KEY ("oauth_authorization_id") REFERENCES "oauth_authorizations" ("id") ON UPDATE NO ACTION ON DELETE CASCADE, CONSTRAINT "oauth_authorization_scopes_oauth_scope_id" FOREIGN KEY ("oauth_scope_id") REFERENCES "oauth_scopes" ("id") ON UPDATE NO ACTION ON DELETE CASCADE);
-- Create "oauth_client_scopes" table
CREATE TABLE "oauth_client_scopes" ("oauth_client_id" character varying NOT NULL, "oauth_scope_id" character varying NOT NULL, PRIMARY KEY ("oauth_client_id", "oauth_scope_id"), CONSTRAINT "oauth_client_scopes_oauth_client_id" FOREIGN KEY ("oauth_client_id") REFERENCES "oauth_clients" ("id") ON UPDATE NO ACTION ON DELETE CASCADE, CONSTRAINT "oauth_client_scopes_oauth_scope_id" FOREIGN KEY ("oauth_scope_id") REFERENCES "oauth_scopes" ("id") ON UPDATE NO ACTION ON DELETE CASCADE);
-- Create "oauth_tokens" table
CREATE TABLE "oauth_tokens" ("id" character varying NOT NULL, "created_at" timestamptz NOT NULL, "updated_at" timestamptz NOT NULL, "access_token" character varying NOT NULL, "refresh_token" character varying NULL, "token_type" character varying NOT NULL DEFAULT 'bearer', "organization_id" character varying NULL, "scope_names" jsonb NULL, "expires_in" bigint NOT NULL DEFAULT 3600, "expires_at" timestamptz NOT NULL, "refresh_token_expires_at" timestamptz NULL, "revoked" boolean NOT NULL DEFAULT false, "revoked_at" timestamptz NULL, "ip_address" character varying NULL, "user_agent" character varying NULL, "client_id" character varying NOT NULL, "user_id" character varying NOT NULL, PRIMARY KEY ("id"), CONSTRAINT "oauth_tokens_oauth_clients_tokens" FOREIGN KEY ("client_id") REFERENCES "oauth_clients" ("id") ON UPDATE NO ACTION ON DELETE NO ACTION, CONSTRAINT "oauth_tokens_users_oauth_tokens" FOREIGN KEY ("user_id") REFERENCES "users" ("id") ON UPDATE NO ACTION ON DELETE NO ACTION);
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
CREATE TABLE "feature_flags" ("id" character varying NOT NULL, "created_at" timestamptz NOT NULL, "updated_at" timestamptz NOT NULL, "name" character varying NOT NULL, "key" character varying NOT NULL, "description" character varying NULL, "enabled" boolean NOT NULL DEFAULT false, "is_premium" boolean NOT NULL DEFAULT false, "component" character varying NOT NULL, PRIMARY KEY ("id"));
-- Create index "feature_flags_key_key" to table: "feature_flags"
CREATE UNIQUE INDEX "feature_flags_key_key" ON "feature_flags" ("key");
-- Create index "feature_flags_name_key" to table: "feature_flags"
CREATE UNIQUE INDEX "feature_flags_name_key" ON "feature_flags" ("name");
-- Create index "featureflag_component" to table: "feature_flags"
CREATE INDEX "featureflag_component" ON "feature_flags" ("component");
-- Create index "featureflag_key" to table: "feature_flags"
CREATE INDEX "featureflag_key" ON "feature_flags" ("key");
-- Create "organization_features" table
CREATE TABLE "organization_features" ("id" character varying NOT NULL, "created_at" timestamptz NOT NULL, "updated_at" timestamptz NOT NULL, "enabled" boolean NOT NULL DEFAULT true, "settings" jsonb NULL, "organization_id" character varying NOT NULL, "feature_id" character varying NOT NULL, PRIMARY KEY ("id"), CONSTRAINT "organization_features_feature_flags_feature" FOREIGN KEY ("feature_id") REFERENCES "feature_flags" ("id") ON UPDATE NO ACTION ON DELETE NO ACTION, CONSTRAINT "organization_features_organizations_feature_flags" FOREIGN KEY ("organization_id") REFERENCES "organizations" ("id") ON UPDATE NO ACTION ON DELETE NO ACTION);
-- Create index "organizationfeature_feature_id" to table: "organization_features"
CREATE INDEX "organizationfeature_feature_id" ON "organization_features" ("feature_id");
-- Create index "organizationfeature_organization_id" to table: "organization_features"
CREATE INDEX "organizationfeature_organization_id" ON "organization_features" ("organization_id");
-- Create index "organizationfeature_organization_id_feature_id" to table: "organization_features"
CREATE UNIQUE INDEX "organizationfeature_organization_id_feature_id" ON "organization_features" ("organization_id", "feature_id");
-- Create "organization_users" table
CREATE TABLE "organization_users" ("organization_id" character varying NOT NULL, "user_id" character varying NOT NULL, PRIMARY KEY ("organization_id", "user_id"), CONSTRAINT "organization_users_organization_id" FOREIGN KEY ("organization_id") REFERENCES "organizations" ("id") ON UPDATE NO ACTION ON DELETE CASCADE, CONSTRAINT "organization_users_user_id" FOREIGN KEY ("user_id") REFERENCES "users" ("id") ON UPDATE NO ACTION ON DELETE CASCADE);
-- Create "passkeys" table
CREATE TABLE "passkeys" ("id" character varying NOT NULL, "created_at" timestamptz NOT NULL, "updated_at" timestamptz NOT NULL, "name" character varying NOT NULL, "credential_id" character varying NOT NULL, "public_key" bytea NOT NULL, "sign_count" bigint NOT NULL DEFAULT 0, "active" boolean NOT NULL DEFAULT true, "device_type" character varying NULL, "aaguid" character varying NULL, "last_used" timestamptz NULL, "transports" jsonb NULL, "attestation" jsonb NULL, "user_id" character varying NOT NULL, PRIMARY KEY ("id"), CONSTRAINT "passkeys_users_passkeys" FOREIGN KEY ("user_id") REFERENCES "users" ("id") ON UPDATE NO ACTION ON DELETE NO ACTION);
-- Create index "passkey_credential_id" to table: "passkeys"
CREATE INDEX "passkey_credential_id" ON "passkeys" ("credential_id");
-- Create index "passkey_user_id" to table: "passkeys"
CREATE INDEX "passkey_user_id" ON "passkeys" ("user_id");
-- Create index "passkeys_credential_id_key" to table: "passkeys"
CREATE UNIQUE INDEX "passkeys_credential_id_key" ON "passkeys" ("credential_id");
-- Create "permissions" table
CREATE TABLE "permissions" ("id" character varying NOT NULL, "created_at" timestamptz NOT NULL, "updated_at" timestamptz NOT NULL, "name" character varying NOT NULL, "description" character varying NOT NULL, "resource" character varying NOT NULL, "action" character varying NOT NULL, "conditions" character varying NULL, "system" boolean NOT NULL DEFAULT false, PRIMARY KEY ("id"));
-- Create index "permission_name" to table: "permissions"
CREATE INDEX "permission_name" ON "permissions" ("name");
-- Create index "permission_resource_action" to table: "permissions"
CREATE UNIQUE INDEX "permission_resource_action" ON "permissions" ("resource", "action");
-- Create index "permissions_name_key" to table: "permissions"
CREATE UNIQUE INDEX "permissions_name_key" ON "permissions" ("name");
-- Create "roles" table
CREATE TABLE "roles" ("id" character varying NOT NULL, "created_at" timestamptz NOT NULL, "updated_at" timestamptz NOT NULL, "name" character varying NOT NULL, "description" character varying NULL, "organization_id" character varying NULL, "system" boolean NOT NULL DEFAULT false, "is_default" boolean NOT NULL DEFAULT false, PRIMARY KEY ("id"));
-- Create index "role_organization_id" to table: "roles"
CREATE INDEX "role_organization_id" ON "roles" ("organization_id");
-- Create index "role_organization_id_name" to table: "roles"
CREATE UNIQUE INDEX "role_organization_id_name" ON "roles" ("organization_id", "name");
-- Create "role_permissions" table
CREATE TABLE "role_permissions" ("role_id" character varying NOT NULL, "permission_id" character varying NOT NULL, PRIMARY KEY ("role_id", "permission_id"), CONSTRAINT "role_permissions_permission_id" FOREIGN KEY ("permission_id") REFERENCES "permissions" ("id") ON UPDATE NO ACTION ON DELETE CASCADE, CONSTRAINT "role_permissions_role_id" FOREIGN KEY ("role_id") REFERENCES "roles" ("id") ON UPDATE NO ACTION ON DELETE CASCADE);
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
-- Create "user_roles" table
CREATE TABLE "user_roles" ("user_id" character varying NOT NULL, "role_id" character varying NOT NULL, PRIMARY KEY ("user_id", "role_id"), CONSTRAINT "user_roles_role_id" FOREIGN KEY ("role_id") REFERENCES "roles" ("id") ON UPDATE NO ACTION ON DELETE CASCADE, CONSTRAINT "user_roles_user_id" FOREIGN KEY ("user_id") REFERENCES "users" ("id") ON UPDATE NO ACTION ON DELETE CASCADE);
-- Create "verifications" table
CREATE TABLE "verifications" ("id" character varying NOT NULL, "created_at" timestamptz NOT NULL, "updated_at" timestamptz NOT NULL, "type" character varying NOT NULL, "token" character varying NOT NULL, "email" character varying NULL, "phone_number" character varying NULL, "redirect_url" character varying NULL, "used" boolean NOT NULL DEFAULT false, "used_at" timestamptz NULL, "attempts" bigint NOT NULL DEFAULT 0, "expires_at" timestamptz NOT NULL, "ip_address" character varying NULL, "user_agent" character varying NULL, "attestation" jsonb NULL, "user_id" character varying NOT NULL, PRIMARY KEY ("id"), CONSTRAINT "verifications_users_verifications" FOREIGN KEY ("user_id") REFERENCES "users" ("id") ON UPDATE NO ACTION ON DELETE NO ACTION);
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
CREATE TABLE "webhooks" ("id" character varying NOT NULL, "created_at" timestamptz NOT NULL, "updated_at" timestamptz NOT NULL, "name" character varying NOT NULL, "url" character varying NOT NULL, "secret" character varying NOT NULL, "active" boolean NOT NULL DEFAULT true, "event_types" jsonb NOT NULL, "version" character varying NOT NULL DEFAULT 'v1', "retry_count" bigint NOT NULL DEFAULT 3, "timeout_ms" bigint NOT NULL DEFAULT 5000, "format" character varying NOT NULL DEFAULT 'json', "metadata" jsonb NULL, "organization_id" character varying NOT NULL, PRIMARY KEY ("id"), CONSTRAINT "webhooks_organizations_webhooks" FOREIGN KEY ("organization_id") REFERENCES "organizations" ("id") ON UPDATE NO ACTION ON DELETE NO ACTION);
-- Create index "webhook_organization_id" to table: "webhooks"
CREATE INDEX "webhook_organization_id" ON "webhooks" ("organization_id");
-- Create "webhook_events" table
CREATE TABLE "webhook_events" ("id" character varying NOT NULL, "event_type" character varying NOT NULL, "headers" jsonb NULL, "payload" jsonb NULL, "delivered" boolean NOT NULL DEFAULT false, "delivered_at" timestamptz NULL, "attempts" bigint NOT NULL DEFAULT 0, "next_retry" timestamptz NULL, "status_code" bigint NULL, "response_body" character varying NULL, "error" character varying NULL, "created_at" timestamptz NOT NULL, "updated_at" timestamptz NOT NULL, "webhook_id" character varying NOT NULL, PRIMARY KEY ("id"), CONSTRAINT "webhook_events_webhooks_events" FOREIGN KEY ("webhook_id") REFERENCES "webhooks" ("id") ON UPDATE NO ACTION ON DELETE NO ACTION);
-- Create index "webhookevent_delivered" to table: "webhook_events"
CREATE INDEX "webhookevent_delivered" ON "webhook_events" ("delivered");
-- Create index "webhookevent_event_type" to table: "webhook_events"
CREATE INDEX "webhookevent_event_type" ON "webhook_events" ("event_type");
-- Create index "webhookevent_next_retry" to table: "webhook_events"
CREATE INDEX "webhookevent_next_retry" ON "webhook_events" ("next_retry");
-- Create index "webhookevent_webhook_id" to table: "webhook_events"
CREATE INDEX "webhookevent_webhook_id" ON "webhook_events" ("webhook_id");
