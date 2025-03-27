#!/bin/bash
set -eu
MIGRATION_NAME=${1:-}

#atlas migrate hash

# Generate the migration
#atlas migrate diff $MIGRATION_NAME --dev-url "postgres://postgres:postgres@localhost:5432/frank?sslmode=disable&search_path=public"

atlas migrate diff $MIGRATION_NAME \
  --dir "file://migrations" \
  --to "ent://ent/schema" \
  --dev-url "docker://postgres/15/test?search_path=public"
#  --dev-url "postgres://postgres:postgres@localhost:5432/frank?sslmode=disable&search_path=public"