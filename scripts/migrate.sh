#!/bin/bash
set -eu
MIGRATION_NAME=${1:-}

atlas migrate hash

# Generate the migration
atlas migrate diff $MIGRATION_NAME --env local