-- reverse: create index "webhookevent_webhook_id" to table: "webhook_events"
DROP INDEX "webhookevent_webhook_id";
-- reverse: create index "webhookevent_next_retry" to table: "webhook_events"
DROP INDEX "webhookevent_next_retry";
-- reverse: create index "webhookevent_event_type" to table: "webhook_events"
DROP INDEX "webhookevent_event_type";
-- reverse: create index "webhookevent_delivered" to table: "webhook_events"
DROP INDEX "webhookevent_delivered";
-- reverse: create "webhook_events" table
DROP TABLE "webhook_events";
-- reverse: create index "webhook_organization_id" to table: "webhooks"
DROP INDEX "webhook_organization_id";
-- reverse: create "webhooks" table
DROP TABLE "webhooks";
-- reverse: create index "verifications_token_key" to table: "verifications"
DROP INDEX "verifications_token_key";
-- reverse: create index "verification_user_id" to table: "verifications"
DROP INDEX "verification_user_id";
-- reverse: create index "verification_token" to table: "verifications"
DROP INDEX "verification_token";
-- reverse: create index "verification_phone_number" to table: "verifications"
DROP INDEX "verification_phone_number";
-- reverse: create index "verification_expires_at" to table: "verifications"
DROP INDEX "verification_expires_at";
-- reverse: create index "verification_email" to table: "verifications"
DROP INDEX "verification_email";
-- reverse: create "verifications" table
DROP TABLE "verifications";
-- reverse: create "user_system_roles" table
DROP TABLE "user_system_roles";
-- reverse: create index "userrole_user_id_role_id_context_type_context_id" to table: "user_roles"
DROP INDEX "userrole_user_id_role_id_context_type_context_id";
-- reverse: create index "userrole_user_id_context_type_context_id" to table: "user_roles"
DROP INDEX "userrole_user_id_context_type_context_id";
-- reverse: create index "userrole_user_id" to table: "user_roles"
DROP INDEX "userrole_user_id";
-- reverse: create index "userrole_role_id" to table: "user_roles"
DROP INDEX "userrole_role_id";
-- reverse: create index "userrole_expires_at" to table: "user_roles"
DROP INDEX "userrole_expires_at";
-- reverse: create index "userrole_context_type_context_id" to table: "user_roles"
DROP INDEX "userrole_context_type_context_id";
-- reverse: create index "userrole_context_type" to table: "user_roles"
DROP INDEX "userrole_context_type";
-- reverse: create index "userrole_context_id" to table: "user_roles"
DROP INDEX "userrole_context_id";
-- reverse: create index "userrole_assigned_by" to table: "user_roles"
DROP INDEX "userrole_assigned_by";
-- reverse: create index "userrole_active" to table: "user_roles"
DROP INDEX "userrole_active";
-- reverse: create "user_roles" table
DROP TABLE "user_roles";
-- reverse: create index "userpermission_user_id_resource_type_resource_id" to table: "user_permissions"
DROP INDEX "userpermission_user_id_resource_type_resource_id";
-- reverse: create index "userpermission_user_id_permiss_29e6bf1065fb7a61fc9825b79f34a10e" to table: "user_permissions"
DROP INDEX "userpermission_user_id_permiss_29e6bf1065fb7a61fc9825b79f34a10e";
-- reverse: create index "userpermission_user_id_context_type_context_id" to table: "user_permissions"
DROP INDEX "userpermission_user_id_context_type_context_id";
-- reverse: create index "userpermission_user_id" to table: "user_permissions"
DROP INDEX "userpermission_user_id";
-- reverse: create index "userpermission_resource_type" to table: "user_permissions"
DROP INDEX "userpermission_resource_type";
-- reverse: create index "userpermission_resource_id" to table: "user_permissions"
DROP INDEX "userpermission_resource_id";
-- reverse: create index "userpermission_permission_type" to table: "user_permissions"
DROP INDEX "userpermission_permission_type";
-- reverse: create index "userpermission_permission_id" to table: "user_permissions"
DROP INDEX "userpermission_permission_id";
-- reverse: create index "userpermission_expires_at" to table: "user_permissions"
DROP INDEX "userpermission_expires_at";
-- reverse: create index "userpermission_context_type_context_id_active" to table: "user_permissions"
DROP INDEX "userpermission_context_type_context_id_active";
-- reverse: create index "userpermission_context_type" to table: "user_permissions"
DROP INDEX "userpermission_context_type";
-- reverse: create index "userpermission_context_id" to table: "user_permissions"
DROP INDEX "userpermission_context_id";
-- reverse: create index "userpermission_assigned_by" to table: "user_permissions"
DROP INDEX "userpermission_assigned_by";
-- reverse: create index "userpermission_active" to table: "user_permissions"
DROP INDEX "userpermission_active";
-- reverse: create "user_permissions" table
DROP TABLE "user_permissions";
-- reverse: create index "smstemplate_usage_count" to table: "sms_templates"
DROP INDEX "smstemplate_usage_count";
-- reverse: create index "smstemplate_type" to table: "sms_templates"
DROP INDEX "smstemplate_type";
-- reverse: create index "smstemplate_system" to table: "sms_templates"
DROP INDEX "smstemplate_system";
-- reverse: create index "smstemplate_organization_id_type_locale" to table: "sms_templates"
DROP INDEX "smstemplate_organization_id_type_locale";
-- reverse: create index "smstemplate_organization_id_type" to table: "sms_templates"
DROP INDEX "smstemplate_organization_id_type";
-- reverse: create index "smstemplate_organization_id" to table: "sms_templates"
DROP INDEX "smstemplate_organization_id";
-- reverse: create index "smstemplate_message_type" to table: "sms_templates"
DROP INDEX "smstemplate_message_type";
-- reverse: create index "smstemplate_last_used_at" to table: "sms_templates"
DROP INDEX "smstemplate_last_used_at";
-- reverse: create index "smstemplate_active" to table: "sms_templates"
DROP INDEX "smstemplate_active";
-- reverse: create "sms_templates" table
DROP TABLE "sms_templates";
-- reverse: create "role_permissions" table
DROP TABLE "role_permissions";
-- reverse: create "permission_required_permissions" table
DROP TABLE "permission_required_permissions";
-- reverse: create index "permissiondependency_required_permission_id" to table: "permission_dependencies"
DROP INDEX "permissiondependency_required_permission_id";
-- reverse: create index "permissiondependency_permission_id_required_permission_id" to table: "permission_dependencies"
DROP INDEX "permissiondependency_permission_id_required_permission_id";
-- reverse: create index "permissiondependency_permission_id" to table: "permission_dependencies"
DROP INDEX "permissiondependency_permission_id";
-- reverse: create index "permissiondependency_dependency_type" to table: "permission_dependencies"
DROP INDEX "permissiondependency_dependency_type";
-- reverse: create index "permissiondependency_created_by" to table: "permission_dependencies"
DROP INDEX "permissiondependency_created_by";
-- reverse: create index "permissiondependency_active" to table: "permission_dependencies"
DROP INDEX "permissiondependency_active";
-- reverse: create "permission_dependencies" table
DROP TABLE "permission_dependencies";
-- reverse: create index "permissions_name_key" to table: "permissions"
DROP INDEX "permissions_name_key";
-- reverse: create index "permission_system" to table: "permissions"
DROP INDEX "permission_system";
-- reverse: create index "permission_risk_level" to table: "permissions"
DROP INDEX "permission_risk_level";
-- reverse: create index "permission_resource_action" to table: "permissions"
DROP INDEX "permission_resource_action";
-- reverse: create index "permission_permission_group" to table: "permissions"
DROP INDEX "permission_permission_group";
-- reverse: create index "permission_name" to table: "permissions"
DROP INDEX "permission_name";
-- reverse: create index "permission_dangerous" to table: "permissions"
DROP INDEX "permission_dangerous";
-- reverse: create index "permission_created_by" to table: "permissions"
DROP INDEX "permission_created_by";
-- reverse: create index "permission_category" to table: "permissions"
DROP INDEX "permission_category";
-- reverse: create index "permission_active" to table: "permissions"
DROP INDEX "permission_active";
-- reverse: create "permissions" table
DROP TABLE "permissions";
-- reverse: create index "passkeys_credential_id_key" to table: "passkeys"
DROP INDEX "passkeys_credential_id_key";
-- reverse: create index "passkey_user_id" to table: "passkeys"
DROP INDEX "passkey_user_id";
-- reverse: create index "passkey_credential_id" to table: "passkeys"
DROP INDEX "passkey_credential_id";
-- reverse: create "passkeys" table
DROP TABLE "passkeys";
-- reverse: create index "organizationprovider_usage_count" to table: "organization_providers"
DROP INDEX "organizationprovider_usage_count";
-- reverse: create index "organizationprovider_template_key_enabled" to table: "organization_providers"
DROP INDEX "organizationprovider_template_key_enabled";
-- reverse: create index "organizationprovider_template_key" to table: "organization_providers"
DROP INDEX "organizationprovider_template_key";
-- reverse: create index "organizationprovider_template_id_enabled" to table: "organization_providers"
DROP INDEX "organizationprovider_template_id_enabled";
-- reverse: create index "organizationprovider_template_id" to table: "organization_providers"
DROP INDEX "organizationprovider_template_id";
-- reverse: create index "organizationprovider_success_rate" to table: "organization_providers"
DROP INDEX "organizationprovider_success_rate";
-- reverse: create index "organizationprovider_provider_id" to table: "organization_providers"
DROP INDEX "organizationprovider_provider_id";
-- reverse: create index "organizationprovider_organization_id_template_key" to table: "organization_providers"
DROP INDEX "organizationprovider_organization_id_template_key";
-- reverse: create index "organizationprovider_organization_id_template_id" to table: "organization_providers"
DROP INDEX "organizationprovider_organization_id_template_id";
-- reverse: create index "organizationprovider_organization_id_provider_id" to table: "organization_providers"
DROP INDEX "organizationprovider_organization_id_provider_id";
-- reverse: create index "organizationprovider_organization_id_enabled" to table: "organization_providers"
DROP INDEX "organizationprovider_organization_id_enabled";
-- reverse: create index "organizationprovider_organization_id" to table: "organization_providers"
DROP INDEX "organizationprovider_organization_id";
-- reverse: create index "organizationprovider_last_used" to table: "organization_providers"
DROP INDEX "organizationprovider_last_used";
-- reverse: create index "organizationprovider_enabled_at" to table: "organization_providers"
DROP INDEX "organizationprovider_enabled_at";
-- reverse: create index "organizationprovider_enabled" to table: "organization_providers"
DROP INDEX "organizationprovider_enabled";
-- reverse: create "organization_providers" table
DROP TABLE "organization_providers";
-- reverse: create index "providertemplate_type_active" to table: "provider_templates"
DROP INDEX "providertemplate_type_active";
-- reverse: create index "providertemplate_type" to table: "provider_templates"
DROP INDEX "providertemplate_type";
-- reverse: create index "providertemplate_popularity_rank" to table: "provider_templates"
DROP INDEX "providertemplate_popularity_rank";
-- reverse: create index "providertemplate_popular" to table: "provider_templates"
DROP INDEX "providertemplate_popular";
-- reverse: create index "providertemplate_key" to table: "provider_templates"
DROP INDEX "providertemplate_key";
-- reverse: create index "providertemplate_category_popular" to table: "provider_templates"
DROP INDEX "providertemplate_category_popular";
-- reverse: create index "providertemplate_category" to table: "provider_templates"
DROP INDEX "providertemplate_category";
-- reverse: create index "providertemplate_active" to table: "provider_templates"
DROP INDEX "providertemplate_active";
-- reverse: create index "provider_templates_key_key" to table: "provider_templates"
DROP INDEX "provider_templates_key_key";
-- reverse: create "provider_templates" table
DROP TABLE "provider_templates";
-- reverse: create index "organizationfeature_organization_id_feature_id" to table: "organization_features"
DROP INDEX "organizationfeature_organization_id_feature_id";
-- reverse: create index "organizationfeature_organization_id" to table: "organization_features"
DROP INDEX "organizationfeature_organization_id";
-- reverse: create index "organizationfeature_feature_id" to table: "organization_features"
DROP INDEX "organizationfeature_feature_id";
-- reverse: create "organization_features" table
DROP TABLE "organization_features";
-- reverse: create index "featureflag_key" to table: "feature_flags"
DROP INDEX "featureflag_key";
-- reverse: create index "featureflag_component" to table: "feature_flags"
DROP INDEX "featureflag_component";
-- reverse: create index "feature_flags_name_key" to table: "feature_flags"
DROP INDEX "feature_flags_name_key";
-- reverse: create index "feature_flags_key_key" to table: "feature_flags"
DROP INDEX "feature_flags_key_key";
-- reverse: create "feature_flags" table
DROP TABLE "feature_flags";
-- reverse: create "oauth_token_scopes" table
DROP TABLE "oauth_token_scopes";
-- reverse: create index "oauthtoken_user_id" to table: "oauth_tokens"
DROP INDEX "oauthtoken_user_id";
-- reverse: create index "oauthtoken_refresh_token" to table: "oauth_tokens"
DROP INDEX "oauthtoken_refresh_token";
-- reverse: create index "oauthtoken_organization_id" to table: "oauth_tokens"
DROP INDEX "oauthtoken_organization_id";
-- reverse: create index "oauthtoken_expires_at" to table: "oauth_tokens"
DROP INDEX "oauthtoken_expires_at";
-- reverse: create index "oauthtoken_client_id" to table: "oauth_tokens"
DROP INDEX "oauthtoken_client_id";
-- reverse: create index "oauthtoken_access_token" to table: "oauth_tokens"
DROP INDEX "oauthtoken_access_token";
-- reverse: create index "oauth_tokens_refresh_token_key" to table: "oauth_tokens"
DROP INDEX "oauth_tokens_refresh_token_key";
-- reverse: create index "oauth_tokens_access_token_key" to table: "oauth_tokens"
DROP INDEX "oauth_tokens_access_token_key";
-- reverse: create "oauth_tokens" table
DROP TABLE "oauth_tokens";
-- reverse: create "oauth_client_scopes" table
DROP TABLE "oauth_client_scopes";
-- reverse: create "oauth_authorization_scopes" table
DROP TABLE "oauth_authorization_scopes";
-- reverse: create index "oauthscope_name" to table: "oauth_scopes"
DROP INDEX "oauthscope_name";
-- reverse: create index "oauth_scopes_name_key" to table: "oauth_scopes"
DROP INDEX "oauth_scopes_name_key";
-- reverse: create "oauth_scopes" table
DROP TABLE "oauth_scopes";
-- reverse: create index "oauthauthorization_user_id" to table: "oauth_authorizations"
DROP INDEX "oauthauthorization_user_id";
-- reverse: create index "oauthauthorization_organization_id" to table: "oauth_authorizations"
DROP INDEX "oauthauthorization_organization_id";
-- reverse: create index "oauthauthorization_expires_at" to table: "oauth_authorizations"
DROP INDEX "oauthauthorization_expires_at";
-- reverse: create index "oauthauthorization_code" to table: "oauth_authorizations"
DROP INDEX "oauthauthorization_code";
-- reverse: create index "oauthauthorization_client_id" to table: "oauth_authorizations"
DROP INDEX "oauthauthorization_client_id";
-- reverse: create index "oauth_authorizations_code_key" to table: "oauth_authorizations"
DROP INDEX "oauth_authorizations_code_key";
-- reverse: create "oauth_authorizations" table
DROP TABLE "oauth_authorizations";
-- reverse: create index "oauthclient_organization_id" to table: "oauth_clients"
DROP INDEX "oauthclient_organization_id";
-- reverse: create index "oauthclient_client_id" to table: "oauth_clients"
DROP INDEX "oauthclient_client_id";
-- reverse: create index "oauth_clients_client_id_key" to table: "oauth_clients"
DROP INDEX "oauth_clients_client_id_key";
-- reverse: create "oauth_clients" table
DROP TABLE "oauth_clients";
-- reverse: create index "mfa_user_id" to table: "mf_as"
DROP INDEX "mfa_user_id";
-- reverse: create index "mfa_method_user_id" to table: "mf_as"
DROP INDEX "mfa_method_user_id";
-- reverse: create "mf_as" table
DROP TABLE "mf_as";
-- reverse: create index "membership_user_id_organization_id" to table: "memberships"
DROP INDEX "membership_user_id_organization_id";
-- reverse: create index "membership_user_id" to table: "memberships"
DROP INDEX "membership_user_id";
-- reverse: create index "membership_status" to table: "memberships"
DROP INDEX "membership_status";
-- reverse: create index "membership_role_id" to table: "memberships"
DROP INDEX "membership_role_id";
-- reverse: create index "membership_organization_id" to table: "memberships"
DROP INDEX "membership_organization_id";
-- reverse: create index "membership_invited_by" to table: "memberships"
DROP INDEX "membership_invited_by";
-- reverse: create index "membership_invitation_token" to table: "memberships"
DROP INDEX "membership_invitation_token";
-- reverse: create index "membership_expires_at" to table: "memberships"
DROP INDEX "membership_expires_at";
-- reverse: create "memberships" table
DROP TABLE "memberships";
-- reverse: create index "role_system" to table: "roles"
DROP INDEX "role_system";
-- reverse: create index "role_role_type_organization_id" to table: "roles"
DROP INDEX "role_role_type_organization_id";
-- reverse: create index "role_role_type_application_id" to table: "roles"
DROP INDEX "role_role_type_application_id";
-- reverse: create index "role_role_type" to table: "roles"
DROP INDEX "role_role_type";
-- reverse: create index "role_priority" to table: "roles"
DROP INDEX "role_priority";
-- reverse: create index "role_parent_id_active" to table: "roles"
DROP INDEX "role_parent_id_active";
-- reverse: create index "role_parent_id" to table: "roles"
DROP INDEX "role_parent_id";
-- reverse: create index "role_organization_id_is_default" to table: "roles"
DROP INDEX "role_organization_id_is_default";
-- reverse: create index "role_organization_id" to table: "roles"
DROP INDEX "role_organization_id";
-- reverse: create index "role_name_role_type_organization_id_application_id" to table: "roles"
DROP INDEX "role_name_role_type_organization_id_application_id";
-- reverse: create index "role_is_default" to table: "roles"
DROP INDEX "role_is_default";
-- reverse: create index "role_created_by" to table: "roles"
DROP INDEX "role_created_by";
-- reverse: create index "role_application_id" to table: "roles"
DROP INDEX "role_application_id";
-- reverse: create index "role_active" to table: "roles"
DROP INDEX "role_active";
-- reverse: create "roles" table
DROP TABLE "roles";
-- reverse: create index "identityprovider_provider_type" to table: "identity_providers"
DROP INDEX "identityprovider_provider_type";
-- reverse: create index "identityprovider_organization_id" to table: "identity_providers"
DROP INDEX "identityprovider_organization_id";
-- reverse: create "identity_providers" table
DROP TABLE "identity_providers";
-- reverse: create index "emailtemplate_type" to table: "email_templates"
DROP INDEX "emailtemplate_type";
-- reverse: create index "emailtemplate_organization_id_type_locale" to table: "email_templates"
DROP INDEX "emailtemplate_organization_id_type_locale";
-- reverse: create index "emailtemplate_organization_id" to table: "email_templates"
DROP INDEX "emailtemplate_organization_id";
-- reverse: create "email_templates" table
DROP TABLE "email_templates";
-- reverse: create index "audit_user_id_timestamp" to table: "audits"
DROP INDEX "audit_user_id_timestamp";
-- reverse: create index "audit_user_id" to table: "audits"
DROP INDEX "audit_user_id";
-- reverse: create index "audit_timestamp" to table: "audits"
DROP INDEX "audit_timestamp";
-- reverse: create index "audit_status" to table: "audits"
DROP INDEX "audit_status";
-- reverse: create index "audit_session_id" to table: "audits"
DROP INDEX "audit_session_id";
-- reverse: create index "audit_resource_type_resource_id" to table: "audits"
DROP INDEX "audit_resource_type_resource_id";
-- reverse: create index "audit_resource_type" to table: "audits"
DROP INDEX "audit_resource_type";
-- reverse: create index "audit_resource_id" to table: "audits"
DROP INDEX "audit_resource_id";
-- reverse: create index "audit_organization_id_timestamp" to table: "audits"
DROP INDEX "audit_organization_id_timestamp";
-- reverse: create index "audit_organization_id" to table: "audits"
DROP INDEX "audit_organization_id";
-- reverse: create index "audit_ip_address_timestamp" to table: "audits"
DROP INDEX "audit_ip_address_timestamp";
-- reverse: create index "audit_action_timestamp" to table: "audits"
DROP INDEX "audit_action_timestamp";
-- reverse: create index "audit_action" to table: "audits"
DROP INDEX "audit_action";
-- reverse: create "audits" table
DROP TABLE "audits";
-- reverse: create index "apikeyactivity_timestamp_success" to table: "api_key_activities"
DROP INDEX "apikeyactivity_timestamp_success";
-- reverse: create index "apikeyactivity_timestamp_key_id" to table: "api_key_activities"
DROP INDEX "apikeyactivity_timestamp_key_id";
-- reverse: create index "apikeyactivity_timestamp_action" to table: "api_key_activities"
DROP INDEX "apikeyactivity_timestamp_action";
-- reverse: create index "apikeyactivity_timestamp" to table: "api_key_activities"
DROP INDEX "apikeyactivity_timestamp";
-- reverse: create index "apikeyactivity_success_timestamp" to table: "api_key_activities"
DROP INDEX "apikeyactivity_success_timestamp";
-- reverse: create index "apikeyactivity_success" to table: "api_key_activities"
DROP INDEX "apikeyactivity_success";
-- reverse: create index "apikeyactivity_status_code" to table: "api_key_activities"
DROP INDEX "apikeyactivity_status_code";
-- reverse: create index "apikeyactivity_method" to table: "api_key_activities"
DROP INDEX "apikeyactivity_method";
-- reverse: create index "apikeyactivity_key_id_timestamp" to table: "api_key_activities"
DROP INDEX "apikeyactivity_key_id_timestamp";
-- reverse: create index "apikeyactivity_key_id_success" to table: "api_key_activities"
DROP INDEX "apikeyactivity_key_id_success";
-- reverse: create index "apikeyactivity_key_id_endpoint" to table: "api_key_activities"
DROP INDEX "apikeyactivity_key_id_endpoint";
-- reverse: create index "apikeyactivity_key_id_action" to table: "api_key_activities"
DROP INDEX "apikeyactivity_key_id_action";
-- reverse: create index "apikeyactivity_key_id" to table: "api_key_activities"
DROP INDEX "apikeyactivity_key_id";
-- reverse: create index "apikeyactivity_ip_address" to table: "api_key_activities"
DROP INDEX "apikeyactivity_ip_address";
-- reverse: create index "apikeyactivity_endpoint" to table: "api_key_activities"
DROP INDEX "apikeyactivity_endpoint";
-- reverse: create index "apikeyactivity_action_timestamp" to table: "api_key_activities"
DROP INDEX "apikeyactivity_action_timestamp";
-- reverse: create index "apikeyactivity_action" to table: "api_key_activities"
DROP INDEX "apikeyactivity_action";
-- reverse: create "api_key_activities" table
DROP TABLE "api_key_activities";
-- reverse: create index "apikey_user_id_type" to table: "api_keys"
DROP INDEX "apikey_user_id_type";
-- reverse: create index "apikey_user_id_active" to table: "api_keys"
DROP INDEX "apikey_user_id_active";
-- reverse: create index "apikey_user_id" to table: "api_keys"
DROP INDEX "apikey_user_id";
-- reverse: create index "apikey_updated_at" to table: "api_keys"
DROP INDEX "apikey_updated_at";
-- reverse: create index "apikey_type" to table: "api_keys"
DROP INDEX "apikey_type";
-- reverse: create index "apikey_organization_id_type" to table: "api_keys"
DROP INDEX "apikey_organization_id_type";
-- reverse: create index "apikey_organization_id_active" to table: "api_keys"
DROP INDEX "apikey_organization_id_active";
-- reverse: create index "apikey_organization_id" to table: "api_keys"
DROP INDEX "apikey_organization_id";
-- reverse: create index "apikey_name" to table: "api_keys"
DROP INDEX "apikey_name";
-- reverse: create index "apikey_last_used" to table: "api_keys"
DROP INDEX "apikey_last_used";
-- reverse: create index "apikey_hashed_key" to table: "api_keys"
DROP INDEX "apikey_hashed_key";
-- reverse: create index "apikey_expires_at" to table: "api_keys"
DROP INDEX "apikey_expires_at";
-- reverse: create index "apikey_created_at" to table: "api_keys"
DROP INDEX "apikey_created_at";
-- reverse: create index "apikey_active_expires_at" to table: "api_keys"
DROP INDEX "apikey_active_expires_at";
-- reverse: create index "apikey_active" to table: "api_keys"
DROP INDEX "apikey_active";
-- reverse: create index "api_keys_key_key" to table: "api_keys"
DROP INDEX "api_keys_key_key";
-- reverse: create index "api_keys_hashed_key_key" to table: "api_keys"
DROP INDEX "api_keys_hashed_key_key";
-- reverse: create "api_keys" table
DROP TABLE "api_keys";
-- reverse: create index "activity_user_id_timestamp" to table: "activities"
DROP INDEX "activity_user_id_timestamp";
-- reverse: create index "activity_user_id_resource_type_timestamp" to table: "activities"
DROP INDEX "activity_user_id_resource_type_timestamp";
-- reverse: create index "activity_user_id" to table: "activities"
DROP INDEX "activity_user_id";
-- reverse: create index "activity_user_agent" to table: "activities"
DROP INDEX "activity_user_agent";
-- reverse: create index "activity_timestamp_success" to table: "activities"
DROP INDEX "activity_timestamp_success";
-- reverse: create index "activity_timestamp_resource_type" to table: "activities"
DROP INDEX "activity_timestamp_resource_type";
-- reverse: create index "activity_timestamp_action" to table: "activities"
DROP INDEX "activity_timestamp_action";
-- reverse: create index "activity_timestamp" to table: "activities"
DROP INDEX "activity_timestamp";
-- reverse: create index "activity_success" to table: "activities"
DROP INDEX "activity_success";
-- reverse: create index "activity_status_code" to table: "activities"
DROP INDEX "activity_status_code";
-- reverse: create index "activity_source" to table: "activities"
DROP INDEX "activity_source";
-- reverse: create index "activity_session_id" to table: "activities"
DROP INDEX "activity_session_id";
-- reverse: create index "activity_resource_type_timestamp_success" to table: "activities"
DROP INDEX "activity_resource_type_timestamp_success";
-- reverse: create index "activity_resource_type_resource_id_timestamp" to table: "activities"
DROP INDEX "activity_resource_type_resource_id_timestamp";
-- reverse: create index "activity_resource_type_resource_id" to table: "activities"
DROP INDEX "activity_resource_type_resource_id";
-- reverse: create index "activity_resource_type_action_timestamp" to table: "activities"
DROP INDEX "activity_resource_type_action_timestamp";
-- reverse: create index "activity_resource_type_action" to table: "activities"
DROP INDEX "activity_resource_type_action";
-- reverse: create index "activity_organization_id_timestamp" to table: "activities"
DROP INDEX "activity_organization_id_timestamp";
-- reverse: create index "activity_organization_id_resource_type_timestamp" to table: "activities"
DROP INDEX "activity_organization_id_resource_type_timestamp";
-- reverse: create index "activity_organization_id" to table: "activities"
DROP INDEX "activity_organization_id";
-- reverse: create index "activity_method" to table: "activities"
DROP INDEX "activity_method";
-- reverse: create index "activity_ip_address" to table: "activities"
DROP INDEX "activity_ip_address";
-- reverse: create index "activity_expires_at" to table: "activities"
DROP INDEX "activity_expires_at";
-- reverse: create index "activity_endpoint" to table: "activities"
DROP INDEX "activity_endpoint";
-- reverse: create index "activity_category" to table: "activities"
DROP INDEX "activity_category";
-- reverse: create index "activity_action" to table: "activities"
DROP INDEX "activity_action";
-- reverse: create "activities" table
DROP TABLE "activities";
-- reverse: create index "sessions_token_key" to table: "sessions"
DROP INDEX "sessions_token_key";
-- reverse: create index "session_user_id" to table: "sessions"
DROP INDEX "session_user_id";
-- reverse: create index "session_token" to table: "sessions"
DROP INDEX "session_token";
-- reverse: create index "session_organization_id" to table: "sessions"
DROP INDEX "session_organization_id";
-- reverse: create index "session_expires_at" to table: "sessions"
DROP INDEX "session_expires_at";
-- reverse: create "sessions" table
DROP TABLE "sessions";
-- reverse: create index "user_username" to table: "users"
DROP INDEX "user_username";
-- reverse: create index "user_user_type_email" to table: "users"
DROP INDEX "user_user_type_email";
-- reverse: create index "user_user_type_active" to table: "users"
DROP INDEX "user_user_type_active";
-- reverse: create index "user_user_type" to table: "users"
DROP INDEX "user_user_type";
-- reverse: create index "user_organization_id_user_type_username" to table: "users"
DROP INDEX "user_organization_id_user_type_username";
-- reverse: create index "user_organization_id_user_type_email" to table: "users"
DROP INDEX "user_organization_id_user_type_email";
-- reverse: create index "user_organization_id_user_type_auth_provider_external_id" to table: "users"
DROP INDEX "user_organization_id_user_type_auth_provider_external_id";
-- reverse: create index "user_organization_id_user_type" to table: "users"
DROP INDEX "user_organization_id_user_type";
-- reverse: create index "user_organization_id_active" to table: "users"
DROP INDEX "user_organization_id_active";
-- reverse: create index "user_organization_id" to table: "users"
DROP INDEX "user_organization_id";
-- reverse: create index "user_last_login" to table: "users"
DROP INDEX "user_last_login";
-- reverse: create index "user_is_platform_admin" to table: "users"
DROP INDEX "user_is_platform_admin";
-- reverse: create index "user_external_id" to table: "users"
DROP INDEX "user_external_id";
-- reverse: create index "user_email" to table: "users"
DROP INDEX "user_email";
-- reverse: create index "user_customer_id" to table: "users"
DROP INDEX "user_customer_id";
-- reverse: create index "user_created_by" to table: "users"
DROP INDEX "user_created_by";
-- reverse: create index "user_blocked" to table: "users"
DROP INDEX "user_blocked";
-- reverse: create index "user_auth_provider_external_id" to table: "users"
DROP INDEX "user_auth_provider_external_id";
-- reverse: create index "user_auth_provider" to table: "users"
DROP INDEX "user_auth_provider";
-- reverse: create index "user_active" to table: "users"
DROP INDEX "user_active";
-- reverse: create "users" table
DROP TABLE "users";
-- reverse: create index "ssostate_expires_at" to table: "sso_states"
DROP INDEX "ssostate_expires_at";
-- reverse: create index "sso_states_state_key" to table: "sso_states"
DROP INDEX "sso_states_state_key";
-- reverse: create "sso_states" table
DROP TABLE "sso_states";
-- reverse: create index "organizations_slug_key" to table: "organizations"
DROP INDEX "organizations_slug_key";
-- reverse: create index "organization_subscription_status" to table: "organizations"
DROP INDEX "organization_subscription_status";
-- reverse: create index "organization_subscription_id" to table: "organizations"
DROP INDEX "organization_subscription_id";
-- reverse: create index "organization_sso_domain" to table: "organizations"
DROP INDEX "organization_sso_domain";
-- reverse: create index "organization_slug" to table: "organizations"
DROP INDEX "organization_slug";
-- reverse: create index "organization_owner_id" to table: "organizations"
DROP INDEX "organization_owner_id";
-- reverse: create index "organization_org_type" to table: "organizations"
DROP INDEX "organization_org_type";
-- reverse: create index "organization_is_platform_organization" to table: "organizations"
DROP INDEX "organization_is_platform_organization";
-- reverse: create index "organization_domain" to table: "organizations"
DROP INDEX "organization_domain";
-- reverse: create index "organization_customer_id" to table: "organizations"
DROP INDEX "organization_customer_id";
-- reverse: create index "organization_auth_service_enabled" to table: "organizations"
DROP INDEX "organization_auth_service_enabled";
-- reverse: create index "organization_auth_domain" to table: "organizations"
DROP INDEX "organization_auth_domain";
-- reverse: create index "organization_active" to table: "organizations"
DROP INDEX "organization_active";
-- reverse: create "organizations" table
DROP TABLE "organizations";
