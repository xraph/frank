-- reverse: create index "permission_resource_action" to table: "permissions"
DROP INDEX "permission_resource_action";
-- reverse: drop index "permission_resource_action" from table: "permissions"
CREATE UNIQUE INDEX "permission_resource_action" ON "permissions" ("resource", "action");
-- reverse: create index "apikey_type_environment" to table: "api_keys"
DROP INDEX "apikey_type_environment";
-- reverse: create index "apikey_organization_id_environment" to table: "api_keys"
DROP INDEX "apikey_organization_id_environment";
-- reverse: create index "apikey_user_id_environment" to table: "api_keys"
DROP INDEX "apikey_user_id_environment";
-- reverse: create index "apikey_environment" to table: "api_keys"
DROP INDEX "apikey_environment";
-- reverse: create index "apikey_hashed_secret_key" to table: "api_keys"
DROP INDEX "apikey_hashed_secret_key";
-- reverse: create index "apikey_public_key" to table: "api_keys"
DROP INDEX "apikey_public_key";
-- reverse: create index "api_keys_hashed_secret_key_key" to table: "api_keys"
DROP INDEX "api_keys_hashed_secret_key_key";
-- reverse: create index "api_keys_secret_key_key" to table: "api_keys"
DROP INDEX "api_keys_secret_key_key";
-- reverse: create index "api_keys_public_key_key" to table: "api_keys"
DROP INDEX "api_keys_public_key_key";
-- reverse: modify "api_keys" table
ALTER TABLE "api_keys" DROP COLUMN "environment", DROP COLUMN "hashed_secret_key", DROP COLUMN "secret_key", DROP COLUMN "public_key", ALTER COLUMN "hashed_key" SET NOT NULL, ALTER COLUMN "key" SET NOT NULL;
