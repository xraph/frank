# RBAC Seed System Documentation

This document describes the comprehensive Role-Based Access Control (RBAC) seed system for the multi-tenant authentication SaaS platform with advanced permission inheritance.

## Overview

The RBAC seed system initializes your database with a complete set of permissions and roles designed for a three-tier user system with inheritance support:

1. **Tier 1: Internal Users** (Platform Staff) - Manage the SaaS platform itself
2. **Tier 2: External Users** (Customer Organization Members) - Manage their organization's auth service
3. **Tier 3: End Users** (Auth Service Users) - Users of customer applications

## New Features in v2.0

### 🔗 **Permission Inheritance System**
- **Dependency Resolution**: Permissions automatically include their dependencies
- **Template System**: Reusable permission templates for common role patterns
- **Hierarchical Validation**: Ensures permission dependencies are satisfied
- **Conflict Detection**: Identifies conflicting permissions

### 📊 **Enhanced Permission Metadata**
- **Risk Levels**: 1-5 scale with automatic dependency calculation
- **Categories & Groups**: Better organization and filtering
- **User Type Restrictions**: Automatic validation of user type compatibility
- **Context Awareness**: Permissions know their required contexts

### 🏗️ **Role Template System**
- **Permission Templates**: Pre-defined permission sets for common patterns
- **Inheritance Chains**: Roles can inherit from multiple templates
- **Automatic Expansion**: Dependencies automatically included

## Permission Templates

### Basic Templates
```go
"basic_self_access": [
    "view:self", "update:self", 
    "view:personal:api:keys", "manage:personal:api:keys",
    "view:personal:sessions", "manage:personal:sessions",
    "view:personal:mfa", "manage:personal:mfa"
]

"organization_viewer": [
    "view:organization", "view:members"
]

"user_management": [
    "create:user", "read:user", "update:user", "list:users"
]

"end_user_management": [
    "view:end:users", "list:end:users", 
    "create:end:user", "update:end:user"
]
```

### Advanced Templates
```go
"security_management": [
    "view:sessions", "view:mfa", "view:audit:logs"
]

"platform_management": [
    "manage:all:organizations", "manage:all:users",
    "manage:customer:organizations", "manage:internal:users"
]
```

## Role Definitions with Inheritance

### System Roles (Enhanced)
```go
{
    Name: "platform_super_admin",
    Permissions: CombinePermissionTemplates(
        "basic_self_access",
        "platform_read_access",
        "platform_management",
    ),
    AdditionalPermissions: [
        "system:admin", "manage:platform",
        "delete:customer:organization"
    ]
}
```

### Organization Roles (Enhanced)
```go
{
    Name: "organization_owner",
    Permissions: CombinePermissionTemplates(
        "basic_self_access",
        "organization_basic_management",
        "user_management",
        "end_user_management",
        "security_management"
    ),
    AdditionalPermissions: [
        "delete:organization", "delete:end:user"
    ]
}
```

## Permission Categories (Expanded)

### 🏢 **Organization Management** (Enhanced)
- Create, view, update, delete organizations
- List organizations with proper filtering
- **New**: Customer organization management for platform staff

### 👥 **Membership Management** (Enhanced)
- Invite, view, manage, remove organization members
- **New**: Enhanced invitation workflows
- **New**: Membership analytics and reporting

### 👤 **User Management** (Expanded)
- Create, read, update, delete, list users
- **New**: End user management for auth services
- **New**: User blocking and suspension
- **New**: User analytics and session management

### 🔐 **Self-Access** (Enhanced)
- View, update, delete own profile
- **New**: Enhanced personal API key management
- **New**: Personal session management with security features
- **New**: Advanced MFA self-service

### 🔌 **API Management** (Enhanced)
- View, create, delete organization API keys
- **New**: API key scoping and permissions
- **New**: Personal API key management

### 🛡️ **Security Management** (Expanded)
- View, manage sessions and MFA
- **New**: End user session management
- **New**: Security analytics and threat detection
- **New**: Audit log analysis tools

### 🔧 **Auth Service Configuration** (New)
- Configure auth service settings
- Manage custom domains
- View service analytics
- Control end user policies

### 🏛️ **Platform Administration** (Enhanced)
- **New**: Internal user management
- **New**: Customer organization oversight
- **New**: Platform-wide analytics
- **New**: Billing and subscription management

## Inheritance Examples

### Permission Dependencies
```go
PermissionDeleteUser: {
    Dependencies: [PermissionViewUser, PermissionUpdateUser]
}
// When assigned "delete:user", automatically includes "view:user" and "update:user"
```

### Role Inheritance
```go
organization_admin → organization_member → organization_viewer
// Admin inherits all member permissions, member inherits all viewer permissions
```

### Template Inheritance
```go
// Organization Owner gets:
CombinePermissionTemplates(
    "basic_self_access",      // Personal management
    "organization_basic_management", // Org operations  
    "user_management",        // User CRUD
    "end_user_management",    // Auth service users
    "security_management"     // Security oversight
)
// Plus destructive permissions like delete operations
```

## API Usage

### Basic Seeding
```go
// Initialize with inheritance support
seeder := NewRBACSeeder(client, logger)
err := seeder.SeedRBACData(ctx)
```

### Permission Expansion
```go
// Get permissions with dependencies
basePerms := []Permission{"delete:user", "manage:organization"}
expandedPerms := ExpandPermissionsWithDependencies(basePerms)
// Returns: ["view:user", "update:user", "delete:user", 
//          "view:organization", "update:organization", "manage:organization"]
```

### Template Usage
```go
// Combine templates for custom roles
permissions := CombinePermissionTemplates(
    "basic_self_access",
    "user_management", 
    "security_management"
)
```

### Validation
```go
// Validate permission set
engine := NewPermissionInheritanceEngine()
isValid, missingDeps := engine.ValidatePermissionSet(permissions)
```

## Advanced Features

### 🔍 **Permission Analysis**
```go
// Get permission hierarchy
hierarchy := engine.GetPermissionHierarchy(PermissionDeleteUser)

// Find all dependents
dependents := GetPermissionDependents(PermissionViewUser)

// Risk analysis
riskLevel := GetPermissionRiskLevel(PermissionDeleteOrganization)
isDangerous := IsDangerousPermission(PermissionSystemAdmin)
```

### 🔎 **Permission Search**
```go
// Search by keyword
results := SearchPermissions("user management")

// Filter by category
userPerms := GetPermissionsByCategory(CategoryUserManagement)

// Filter by user type
internalPerms := GetPermissionsForUserType(UserTypeInternal)
```

### ✅ **Validation System**
```go
// Validate permission for context
err := ValidatePermissionForContext(
    PermissionDeleteUser, 
    ContextOrganization, 
    UserTypeExternal
)

// Check user type compatibility
canUse := IsUserTypeAllowed(PermissionSystemAdmin, UserTypeInternal)
```

## Database Schema Impact

### New Tables/Relationships
- Enhanced permission metadata storage
- Role hierarchy relationships
- Permission dependency tracking
- Template definitions
- Inheritance audit trails

### Migration Considerations
- Backward compatible with existing systems
- Automatic dependency resolution during migration
- Role hierarchy validation during seed

## Deployment

### Environment Variables
```bash
SEED_DATABASE=true              # Enable seeding
RBAC_INHERITANCE_MODE=full     # Enable full inheritance
RBAC_VALIDATION_STRICT=true    # Strict validation
```

### Kubernetes Deployment
```yaml
apiVersion: batch/v1
kind: Job
metadata:
  name: frank-seed-rbac-v2
spec:
  template:
    spec:
      containers:
      - name: frank-seed
        image: frank:v2.0
        command: ["./app"]
        args: ["seed", "--type=rbac", "--inheritance=full"]
```

## Performance Optimizations

### 🚀 **Permission Resolution Caching**
- Dependency trees cached at startup
- Role permission sets pre-computed
- Template expansions memoized

### 📊 **Database Optimizations**
- Indexed permission lookups
- Optimized role hierarchy queries
- Bulk permission assignments

### 🔄 **Lazy Loading**
- Permission dependencies loaded on-demand
- Role hierarchies computed as needed
- Template expansions cached

## Migration from v1.0

### Automatic Migration
```go
// Migrate existing roles to new system
migrator := NewRBACMigrator(client, logger)
err := migrator.MigrateToV2(ctx)
```

### Manual Migration Steps
1. **Backup existing RBAC data**
2. **Run dependency analysis** on current permissions
3. **Execute migration** with automatic dependency resolution
4. **Validate role assignments** after migration
5. **Update application code** to use new permission system

## Monitoring and Analytics

### 🔍 **Permission Usage Analytics**
```go
// Track permission usage
analytics := GetPermissionAnalytics(organizationID)

// Monitor role effectiveness  
roleStats := GetRoleUsageStats(roleID)

// Security analysis
riskAnalysis := GetPermissionRiskAnalysis(organizationID)
```

### 📈 **Inheritance Metrics**
- Dependency resolution performance
- Template usage patterns
- Role hierarchy effectiveness
- Permission conflict detection

## Conclusion

The enhanced RBAC seed system v2.0 provides:

- **🔗 Automatic Dependency Resolution**: No more missing permissions
- **📋 Template-Based Roles**: Consistent, maintainable role definitions
- **🛡️ Enhanced Security**: Risk-based permission classification
- **🏗️ Scalable Architecture**: Support for complex organizational structures
- **🔧 Easy Customization**: Template system for organization-specific needs
- **✅ Comprehensive Validation**: Prevent permission conflicts and inconsistencies

This system scales from simple setups to complex enterprise deployments while maintaining security and usability.

## Architecture

### Permission Structure

The permission system is organized hierarchically:

- **Categories**: High-level groupings (organization, security, etc.)
- **Groups**: Functional groupings for management
- **Actions**: What can be done (create, read, update, delete, etc.)
- **Resources**: What the action is performed on (user, role, etc.)
- **Contexts**: Where the permission applies (system, organization, self)

### Role Types

#### System Roles (Internal Users)

| Role | Description | Priority | Default |
|------|-------------|----------|---------|
| `platform_super_admin` | Full platform administrative access | 100 | No |
| `platform_admin` | Platform administration with limited destructive access | 90 | No |
| `platform_support` | Support role for assisting customers | 50 | Yes |

#### Organization Roles (External Users)

| Role | Description | Priority | Default | Parent |
|------|-------------|----------|---------|--------|
| `organization_owner` | Full ownership and control of organization | 100 | No | - |
| `organization_admin` | Administrative access without destructive permissions | 90 | No | member |
| `organization_member` | Standard member access | 50 | Yes | viewer |
| `organization_viewer` | Read-only access | 10 | No | - |

#### Application Roles (End Users)

| Role | Description | Priority | Default |
|------|-------------|----------|---------|
| `end_user_admin` | Administrative access for end user management | 90 | No |
| `end_user` | Standard end user access | 50 | Yes |
| `end_user_readonly` | Read-only access for end users | 10 | No |

## Permission Categories

### Organization Management
- Create, view, update, delete organizations
- List organizations user has access to

### Membership Management
- Invite, view, manage, remove organization members
- Control organization membership lifecycle

### User Management
- Create, read, update, delete, list users
- Manage user accounts within organizations

### Self-Access
- View, update, delete own profile
- Manage personal API keys, sessions, MFA

### API Management
- View, create, delete organization API keys
- Manage integration credentials

### RBAC Management
- View, create, update, delete roles
- Assign roles to users
- Manage permission assignments

### Security Management
- View, manage sessions
- Control MFA settings
- Access audit logs

### Integration Management
- Manage webhooks
- Control external integrations

### System Administration
- Full system access (internal users only)
- Manage global system settings
- Platform-wide user and organization management

## Permission Metadata

Each permission includes rich metadata:

```go
type PermissionDefinition struct {
    Name            string             // Unique permission identifier
    DisplayName     string             // Human-readable name
    Description     string             // Detailed description
    Resource        ResourceType       // What resource this applies to
    Action          PermissionAction   // What action is being performed
    Category        PermissionCategory // High-level category
    Group           PermissionGroup    // Functional grouping
    RiskLevel       int                // Risk level (1-5, 5 highest)
    Dangerous       bool               // Requires special handling
    System          bool               // System-managed permission
    UserTypes       []string           // Applicable user types
    RequiredContext []ContextType      // Required contexts
    Dependencies    []Permission       // Permission dependencies
    ConflictsWith   []Permission       // Conflicting permissions
    Tags            []string           // Additional metadata
}
```

## Usage

### Basic Usage

```go
// Initialize seeder
client := ent.NewClient() // Your ent client
logger := logging.NewLogger()
seeder := NewRBACSeeder(client, logger)

// Seed RBAC data
ctx := context.Background()
err := seeder.SeedRBACData(ctx)
if err != nil {
    log.Fatal("Failed to seed RBAC data:", err)
}
```

### CLI Integration

```bash
# Seed all data
./app seed --type=all

# Seed only RBAC data
./app seed --type=rbac
```

### Docker Integration

```dockerfile
# In your Dockerfile
COPY scripts/docker-entrypoint.sh /usr/local/bin/
RUN chmod +x /usr/local/bin/docker-entrypoint.sh
ENTRYPOINT ["docker-entrypoint.sh"]
```

```bash
# docker-entrypoint.sh
#!/bin/bash
set -e

# Wait for database
./wait-for-it.sh postgres:5432 --timeout=30

# Run migrations
./app migrate

# Seed database if specified
if [ "$SEED_DATABASE" = "true" ]; then
    ./app seed --type=all
fi

# Start application
exec ./app server
```

### Kubernetes Job

```yaml
apiVersion: batch/v1
kind: Job
metadata:
  name: frank-seed-rbac
spec:
  template:
    spec:
      containers:
      - name: frank-seed
        image: frank:latest
        command: ["./app"]
        args: ["seed", "--type=rbac"]
        env:
        - name: DATABASE_URL
          valueFrom:
            secretKeyRef:
              name: frank-secrets
              key: database-url
      restartPolicy: OnFailure
  backoffLimit: 3
```

## Testing

### Test Setup

```go
func TestRBACSystem(t *testing.T) {
    // Setup test database
    client := setupTestDB(t)
    defer client.Close()

    logger := logging.NewTestLogger()
    testSeeder := NewTestSeedManager(client, logger)

    // Seed test data
    ctx := context.Background()
    require.NoError(t, testSeeder.SeedForTesting(ctx))

    // Cleanup after test
    defer testSeeder.CleanupTestData(ctx)

    // Your tests here...
}
```

## Permission Hierarchy

### System Level (Internal Users)
```
platform_super_admin
├── All system permissions
├── All platform management permissions
└── All self-access permissions

platform_admin
├── View-only platform permissions
└── All self-access permissions

platform_support
├── Read-only customer support permissions
└── All self-access permissions
```

### Organization Level (External Users)
```
organization_owner
├── All organization management permissions
├── All membership management permissions
├── All user management permissions
├── All API management permissions
├── All RBAC management permissions
├── All security management permissions
├── All integration management permissions
└── All self-access permissions

organization_admin (inherits from member)
├── Most management permissions (no destructive)
└── Enhanced access permissions

organization_member (inherits from viewer)
├── Basic read permissions
└── Standard functionality access

organization_viewer
├── Read-only access
└── All self-access permissions
```

### Application Level (End Users)
```
end_user_admin
├── Enhanced self-management
└── Account deletion capability

end_user
├── Standard self-management
└── Session management

end_user_readonly
├── View-only self access
└── Minimal permissions
```

## Key Features

### 1. Comprehensive Permission Set
- 50+ carefully designed permissions
- Covers all major functional areas
- Proper risk classification

### 2. Role Hierarchy
- Parent-child relationships
- Permission inheritance
- Logical privilege escalation

### 3. Multi-Tenant Architecture
- Context-aware permissions
- Organization isolation
- Flexible resource scoping

### 4. Security-First Design
- Risk level classification
- Dangerous permission marking
- Dependency validation

### 5. Metadata Rich
- Detailed permission descriptions
- Categorization and grouping
- Tag-based organization

### 6. Extensible
- Easy to add new permissions
- Modular role definitions
- Template-based creation

## Best Practices

### 1. Permission Naming
- Follow `action:resource` pattern
- Use consistent terminology
- Be descriptive but concise

### 2. Role Design
- Follow principle of least privilege
- Use inheritance for common permissions
- Create specific roles for specific functions

### 3. Risk Management
- Mark dangerous permissions appropriately
- Set realistic risk levels
- Consider permission dependencies

### 4. Testing
- Always seed test data
- Test permission checks
- Validate role assignments

### 5. Deployment
- Use idempotent seeding
- Handle existing data gracefully
- Log all operations

## Customization

### Adding New Permissions

```go
// Add to AllPermissionDefinitions map
authz.PermissionNewFeature: {
    Name:            string(authz.PermissionNewFeature),
    DisplayName:     "New Feature Access",
    Description:     "Access to new feature functionality",
    Resource:        ResourceSystem,
    Action:          ActionManage,
    Category:        CategoryCustom,
    Group:           GroupCustomManagement,
    RiskLevel:       2,
    Dangerous:       false,
    System:          false,
    UserTypes:       []string{UserTypeExternal},
    RequiredContext: []ContextType{ContextOrganization},
    Tags:            []string{"feature", "custom"},
},
```

### Adding New Roles

```go
// Add to appropriate role slice
{
    Name:                "custom_role",
    DisplayName:         "Custom Role",
    Description:         "Custom role for specific functionality",
    RoleType:            role.RoleTypeOrganization,
    System:              false,
    IsDefault:           false,
    Priority:            75,
    Color:               "#6366f1",
    ApplicableUserTypes: []string{"external"},
    Permissions: []authz.Permission{
        authz.PermissionNewFeature,
        // ... other permissions
    },
},
```

## Monitoring and Maintenance

### 1. Audit Permissions
- Regularly review permission usage
- Identify unused permissions
- Monitor dangerous permission assignments

### 2. Role Effectiveness
- Analyze role assignment patterns
- Optimize role hierarchies
- Remove redundant roles

### 3. Security Review
- Review high-risk permissions
- Validate permission dependencies
- Check for privilege escalation paths

## Troubleshooting

### Common Issues

1. **Duplicate Key Errors**
    - Permissions already exist
    - Use idempotent seeding
    - Check for existing data

2. **Missing Dependencies**
    - Permission references unknown permission
    - Check permission definitions
    - Verify import statements

3. **Role Hierarchy Loops**
    - Circular parent-child relationships
    - Validate hierarchy setup
    - Check parent role assignments

## Conclusion

This RBAC seed system provides a comprehensive foundation for your multi-tenant authentication SaaS platform. It implements security best practices, supports complex organizational structures, and provides the flexibility needed for a growing platform.

The system is designed to be:
- **Secure**: Proper permission isolation and risk management
- **Scalable**: Support for multiple tenants and user types
- **Maintainable**: Clear structure and comprehensive documentation
- **Extensible**: Easy to add new permissions and roles
- **Production-Ready**: Robust error handling and logging

Start with the provided seed data and customize as needed for your specific requirements.