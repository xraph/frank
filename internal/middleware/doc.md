# Organization Validation Flow

## Request Flow Diagram

```
┌─────────────────────────────────────────────────────────────────┐
│                    Public Auth Request                         │
│  POST /api/v1/public/auth/register                            │
│  Headers: X-Publishable-Key: pk_test_org123_abc               │
│  Body: {"email":"user@example.com","user_type":"end_user"}    │
└─────────────────────────────────────────────────────────────────┘
                                │
                                ▼
┌─────────────────────────────────────────────────────────────────┐
│              1. User Type Detection Middleware                 │
│  • Analyzes API key prefix (pk_* = end_user)                  │
│  • Checks request body user_type field                        │
│  • Sets DetectedUserTypeKey = "end_user"                      │
└─────────────────────────────────────────────────────────────────┘
                                │
                                ▼
┌─────────────────────────────────────────────────────────────────┐
│           2. Optional Organization Detection                    │
│  • Extracts org ID from publishable key                       │
│  • Validates API key exists and is active                     │
│  • Sets OrganizationIDContextKey = org123                     │
│  • No enforcement - continues regardless                       │
└─────────────────────────────────────────────────────────────────┘
                                │
                                ▼
┌─────────────────────────────────────────────────────────────────┐
│              3. Auth Handler Validation                        │
│  • Gets user_type = "end_user" from request                   │
│  • Gets org_id from context                                   │
│  • Validates: org exists, is active, accepts end users        │
│  • Checks: end user limits not exceeded                       │
│  • Enforces: no platform org access for end users             │
└─────────────────────────────────────────────────────────────────┘
                                │
                    ┌───────────┴───────────┐
                    │                       │
                    ▼                       ▼
          ┌─────────────────┐    ┌─────────────────┐
          │   ✅ Success     │    │   ❌ Failure    │
          │ Continue with   │    │ Return 400/403  │
          │ registration    │    │ with error msg  │
          └─────────────────┘    └─────────────────┘
```

## Decision Matrix

| User Type | Org Context | Middleware Action | Handler Action | Result |
|-----------|-------------|-------------------|----------------|--------|
| `end_user` | ✅ Valid | Detect & Set | Validate & Enforce | ✅ Success |
| `end_user` | ❌ Missing | No Detection | Enforce Required | ❌ 400 Error |
| `end_user` | ❌ Invalid | Detect Invalid | Validate Fails | ❌ 403 Error |
| `external` | ✅ Present | Detect & Set | Skip Validation | ✅ Success |
| `external` | ❌ Missing | No Detection | Skip Validation | ✅ Success |
| `internal` | Any | Optional | Skip Validation | ✅ Success |

## Error Response Examples

### Missing Organization Context (End User)
```json
{
  "code": "bad_request",
  "message": "Organization context is required for end user registration. Please provide organization context via:\n- Publishable API key (X-Publishable-Key header)\n- Organization ID header (X-Org-ID)\n- Organization query parameter (?org=orgId)"
}
```

### Invalid Organization
```json
{
  "code": "not_found", 
  "message": "Organization not found"
}
```

### Inactive Organization
```json
{
  "code": "forbidden",
  "message": "Organization is inactive"
}
```

### End User Limit Exceeded
```json
{
  "code": "forbidden",
  "message": "Organization has reached end user limit"
}
```

## Implementation Considerations

### 1. **API Key Resolution Priority**
```
1. X-Publishable-Key header (pk_*)
2. X-API-Key header (sk_*)  
3. X-Org-ID header (explicit org ID)
4. ?org=orgId query parameter
5. Email domain detection (if enabled)
```

### 2. **Caching Strategy**
- Cache organization lookups for API key validation
- Cache user type detection results
- Invalidate on organization status changes

### 3. **Rate Limiting Considerations**
- Apply rate limiting per organization for end user registrations
- Separate limits for different user types
- Consider IP-based limiting for abuse prevention

### 4. **Audit Trail**
- Log all organization context validation attempts
- Track failed validations for security monitoring
- Include organization ID in all auth-related audit events

### 5. **Error Handling**
- Graceful degradation for organization service failures
- Clear error messages for different failure scenarios
- Consistent error response format across endpoints

### 6. **Performance Optimization**
- Batch organization validation for bulk operations
- Async organization metadata updates
- Connection pooling for organization service calls

## Edge Cases & Solutions

### Case 1: Organization Becomes Inactive During Registration
**Solution**: Validate organization status at registration time, not just detection time.

### Case 2: API Key Organization vs Header Organization Mismatch
**Solution**: API key organization takes precedence. Return error if explicit header conflicts.

### Case 3: Email Domain Detection Conflicts with API Key
**Solution**: API key organization takes precedence over email domain detection.

### Case 4: User Switches Organizations During Session
**Solution**: Require re-authentication when switching organization context.

### Case 5: Concurrent Registration Exceeds User Limits
**Solution**: Use database-level constraints and atomic operations for user count validation.

This comprehensive approach ensures secure, scalable organization validation for public auth endpoints while maintaining usability for different user types.