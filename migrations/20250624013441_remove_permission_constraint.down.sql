-- reverse: create index "permission_resource_action" to table: "permissions"
DROP INDEX "permission_resource_action";
-- reverse: drop index "permission_resource_action" from table: "permissions"
CREATE UNIQUE INDEX "permission_resource_action" ON "permissions" ("resource", "action");
