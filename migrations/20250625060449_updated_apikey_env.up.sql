-- modify "api_keys" table
ALTER TABLE "api_keys" ALTER COLUMN "key" DROP NOT NULL, ALTER COLUMN "hashed_key" DROP NOT NULL, ADD COLUMN "public_key" character varying NOT NULL, ADD COLUMN "secret_key" character varying NOT NULL, ADD COLUMN "hashed_secret_key" character varying NOT NULL, ADD COLUMN "environment" character varying NOT NULL DEFAULT 'test';
-- create index "api_keys_public_key_key" to table: "api_keys"
CREATE UNIQUE INDEX "api_keys_public_key_key" ON "api_keys" ("public_key");
-- create index "api_keys_secret_key_key" to table: "api_keys"
CREATE UNIQUE INDEX "api_keys_secret_key_key" ON "api_keys" ("secret_key");
-- create index "api_keys_hashed_secret_key_key" to table: "api_keys"
CREATE UNIQUE INDEX "api_keys_hashed_secret_key_key" ON "api_keys" ("hashed_secret_key");
-- create index "apikey_public_key" to table: "api_keys"
CREATE INDEX "apikey_public_key" ON "api_keys" ("public_key");
-- create index "apikey_hashed_secret_key" to table: "api_keys"
CREATE INDEX "apikey_hashed_secret_key" ON "api_keys" ("hashed_secret_key");
-- create index "apikey_environment" to table: "api_keys"
CREATE INDEX "apikey_environment" ON "api_keys" ("environment");
-- create index "apikey_user_id_environment" to table: "api_keys"
CREATE INDEX "apikey_user_id_environment" ON "api_keys" ("user_id", "environment");
-- create index "apikey_organization_id_environment" to table: "api_keys"
CREATE INDEX "apikey_organization_id_environment" ON "api_keys" ("organization_id", "environment");
-- create index "apikey_type_environment" to table: "api_keys"
CREATE INDEX "apikey_type_environment" ON "api_keys" ("type", "environment");
-- drop index "permission_resource_action" from table: "permissions"
DROP INDEX "permission_resource_action";
-- create index "permission_resource_action" to table: "permissions"
CREATE INDEX "permission_resource_action" ON "permissions" ("resource", "action");
