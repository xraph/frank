# Frank Auth SaaS - Migration System

This migration system uses **entgo's versioned migrations** with Atlas support, providing enterprise-grade database schema management for the multi-tenant authentication platform.

## 🏗️ Architecture

The migration system consists of three main components:

1. **Migration Generator** (`ent/migrate/main.go`) - Uses entgo + Atlas to generate migration files
2. **Migration CLI** (`cmd/migrate/main.go`) - Executes migrations using golang-migrate
3. **Migration Shell Script** (`scripts/migrate.sh`) - User-friendly wrapper with additional features

## 🚀 Quick Start

### 1. Install Dependencies

```bash
go mod tidy
```

Required dependencies:
- `entgo.io/ent` - ORM and schema definitions
- `ariga.io/atlas` - Schema migration generation
- `github.com/golang-migrate/migrate/v4` - Migration execution
- Database drivers (postgres, mysql, sqlite)

### 2. Generate Your First Migration

```bash
# Generate initial schema migration
go run -mod=mod ent/migrate/main.go initial_schema

# Or use the wrapper script
./scripts/migrate.sh create --name initial_schema
```

### 3. Apply Migrations

```bash
# Apply all pending migrations
./scripts/migrate.sh migrate

# Check status
./scripts/migrate.sh status
```

### 4. Seed Database

```bash
# Seed with default data
./scripts/migrate.sh seed
```

## 📁 File Structure

```
frank/
├── ent/
│   ├── migrate/
│   │   ├── main.go                 # Migration generator
│   │   └── migrations/             # Generated migration files
│   │       ├── 20231201120000_initial_schema.up.sql
│   │       ├── 20231201120000_initial_schema.down.sql
│   │       ├── 20231201120001_add_users.up.sql
│   │       └── 20231201120001_add_users.down.sql
│   └── schema/                     # Entgo schema definitions
├── cmd/migrate/main.go             # Migration CLI tool
├── scripts/migrate.sh              # Shell wrapper
└── migration/migration.go          # Additional utilities
```

## 🛠️ Commands

### Migration Management

```bash
# Generate new migration
./scripts/migrate.sh create --name "add_user_preferences"

# Apply all pending migrations
./scripts/migrate.sh migrate

# Apply migrations up to specific version
./scripts/migrate.sh migrate --version 20231201120001

# Rollback last N migrations
./scripts/migrate.sh rollback --steps 3

# Rollback to specific version
./scripts/migrate.sh rollback --version 20231201120000

# Check migration status
./scripts/migrate.sh status

# Show current version
./scripts/migrate.sh version
```

### Database Operations

```bash
# Seed database with default data
./scripts/migrate.sh seed

# Seed with custom file
./scripts/migrate.sh seed --seed-file custom_seed.sql

# Validate schema integrity
./scripts/migrate.sh validate

# Reset database (DANGEROUS - removes all data)
./scripts/migrate.sh reset --yes

# Drop all tables (DANGEROUS)
./scripts/migrate.sh drop --yes
```

### Development & Testing

```bash
# Dry run - see what would happen
./scripts/migrate.sh --dry-run migrate

# Verbose logging
./scripts/migrate.sh --verbose migrate

# Use different environment
./scripts/migrate.sh --env staging migrate

# Run in Docker
./scripts/migrate.sh --docker migrate
```

## 🏢 Multi-Tenant Support

The migration system supports multi-tenant operations:

```bash
# Tenant-specific operations
./scripts/migrate.sh migrate --tenant 01FZS6TV7KP869DR7RXNEHXQKX
./scripts/migrate.sh seed --tenant 01FZS6TV7KP869DR7RXNEHXQKX
```

## 🔧 Configuration

### Environment Variables

```bash
# Database configuration
export DATABASE_URL="postgres://user:pass@localhost:5432/frank"
export DATABASE_DRIVER="postgres"

# Migration configuration
export FRANK_ENVIRONMENT="development"
export FRANK_CONFIG_PATH="/path/to/config.yaml"

# Enable Docker BuildKit for Docker operations
export DOCKER_BUILDKIT=1
```

### Configuration File

```yaml
# config/config.yaml
database:
  driver: postgres
  host: localhost
  port: 5432
  user: frank
  password: frank
  database: frank
  ssl_mode: disable
  auto_migrate: false  # Disable auto-migration, use versioned migrations
```

## 📝 Creating Migrations

### 1. Update Your Entgo Schema

```go
// ent/schema/user.go
func (User) Fields() []ent.Field {
    return []ent.Field{
        field.String("email").Unique(),
        field.String("name"),
        field.String("preferences").Optional(), // <- New field
    }
}
```

### 2. Generate Migration

```bash
go run -mod=mod ent/migrate/main.go add_user_preferences
```

This creates:
- `20231201120001_add_user_preferences.up.sql`
- `20231201120001_add_user_preferences.down.sql`

### 3. Review Generated Files

```sql
-- 20231201120001_add_user_preferences.up.sql
ALTER TABLE users ADD COLUMN preferences VARCHAR(255);

-- 20231201120001_add_user_preferences.down.sql  
ALTER TABLE users DROP COLUMN preferences;
```

### 4. Apply Migration

```bash
./scripts/migrate.sh migrate
```

## 🌱 Seeding

The system provides comprehensive seeding capabilities:

### Default Seeding

```bash
./scripts/migrate.sh seed
```

Creates:
- ✅ System roles (super_admin, admin, org_owner, etc.)
- ✅ System permissions (view_users, manage_users, etc.)
- ✅ Default organization
- ✅ Admin user (if none exists)
- ✅ OAuth provider templates
- ✅ MFA method templates

### Custom Seeding

```bash
# Use custom seed file
./scripts/migrate.sh seed --seed-file custom_data.sql
```

```sql
-- custom_data.sql
INSERT INTO organizations (id, name, slug) VALUES 
  ('01FZS6TV7KP869DR7RXNEHXQKX', 'Acme Corp', 'acme');

INSERT INTO users (id, email, name, organization_id) VALUES
  ('01FZS6TV7KP869DR7RXNEHXQKY', 'john@acme.com', 'John Doe', '01FZS6TV7KP869DR7RXNEHXQKX');
```

## 🔍 Validation & Troubleshooting

### Schema Validation

```bash
# Validate current schema
./scripts/migrate.sh validate
```

Checks:
- Schema consistency with entgo definitions
- Database constraints and indexes
- Data integrity
- Foreign key relationships

### Common Issues

**Migration Lock Issues:**
```bash
# Force unlock if migration is stuck
./scripts/migrate.sh force-unlock --yes
```

**Dirty Database State:**
```bash
# Check status
./scripts/migrate.sh status

# If database is dirty, investigate and fix manually
# Then force to clean state
./scripts/migrate.sh force-unlock --yes
```

**Schema Drift:**
```bash
# Validate schema matches expectations
./scripts/migrate.sh validate

# Generate new migration if needed
go run -mod=mod ent/migrate/main.go fix_schema_drift
```

## 🚀 Production Deployment

### 1. CI/CD Pipeline

```yaml
# .github/workflows/migrate.yml
name: Database Migration
on:
  push:
    branches: [main]

jobs:
  migrate:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - uses: actions/setup-go@v3
        with:
          go-version: '1.21'
      
      - name: Run Migrations
        env:
          DATABASE_URL: ${{ secrets.DATABASE_URL }}
        run: |
          go build -o migrate ./cmd/migrate
          ./migrate migrate
```

### 2. Docker Deployment

```dockerfile
# migrations.Dockerfile
FROM golang:1.21-alpine AS builder
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN go build -o migrate ./cmd/migrate

FROM alpine:latest
RUN apk --no-cache add ca-certificates
WORKDIR /root/
COPY --from=builder /app/migrate .
COPY --from=builder /app/migrations ./migrations
CMD ["./migrate", "migrate"]
```

### 3. Production Checklist

- [ ] **Backup database** before running migrations
- [ ] **Test migrations** in staging environment
- [ ] **Review migration files** for destructive operations
- [ ] **Plan rollback strategy** for critical migrations
- [ ] **Monitor migration execution** in production
- [ ] **Validate schema** after migration completion

## 🔐 Security Considerations

### Database Permissions

```sql
-- Create migration user with limited permissions
CREATE USER frank_migrate WITH PASSWORD 'secure_password';
GRANT CREATE, ALTER, DROP ON SCHEMA public TO frank_migrate;
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO frank_migrate;
```

### Migration Safety

```bash
# Always use dry run first
./scripts/migrate.sh --dry-run migrate

# Validate before applying
./scripts/migrate.sh validate

# Use specific version targeting
./scripts/migrate.sh migrate --version 20231201120001
```

## 📊 Monitoring & Observability

### Migration Metrics

The migration system provides structured logging:

```json
{
  "level": "info",
  "msg": "Migration completed successfully",
  "applied_migrations": 3,
  "duration": "2.5s",
  "database": "frank_production"
}
```

### Health Checks

```bash
# Check migration status programmatically
./scripts/migrate.sh status --json
```

## 🤝 Contributing

When contributing schema changes:

1. **Create migration** for schema changes
2. **Test rollback** functionality
3. **Update seed data** if needed
4. **Document breaking changes**
5. **Test multi-tenant scenarios**

## 📚 Additional Resources

- [Entgo Documentation](https://entgo.io/docs/)
- [Atlas Documentation](https://atlasgo.io/docs/)
- [Golang-Migrate Documentation](https://github.com/golang-migrate/migrate)
- [Frank Auth SaaS Architecture](./ARCH.md)

---

**⚠️ Important Notes:**

- Always backup your database before running migrations in production
- Test migrations thoroughly in development and staging environments
- Review generated migration files before applying them
- Use version-specific migrations rather than `latest` in production
- Monitor migration execution and have rollback plans ready