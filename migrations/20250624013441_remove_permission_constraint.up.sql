-- drop index "permission_resource_action" from table: "permissions"
DROP INDEX "permission_resource_action";
-- create index "permission_resource_action" to table: "permissions"
CREATE INDEX "permission_resource_action" ON "permissions" ("resource", "action");
