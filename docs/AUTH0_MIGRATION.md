# Auth0 Migration Guide

Complete guide for migrating from Auth0 to AuthOS using the built-in migration tools.

## Table of Contents

- [Overview](#overview)
- [Prerequisites](#prerequisites)
- [Quick Start](#quick-start)
- [Migration Process](#migration-process)
- [Password Migration Strategies](#password-migration-strategies)
- [Configuration](#configuration)
- [Console Commands](#console-commands)
- [Testing](#testing)
- [Troubleshooting](#troubleshooting)

## Overview

The Auth0 migration system provides comprehensive tools to migrate your data from an Auth0 tenant to AuthOS, including:

- **Organizations** - Multi-tenant structure with branding
- **Users** - Complete user profiles with metadata
- **Applications** - OAuth 2.0 clients with credentials
- **Roles & Permissions** - RBAC configuration
- **Social Accounts** - Linked social authentication
- **MFA Settings** - Multi-factor authentication

## Prerequisites

### 1. Auth0 Management API Token

Create a Machine-to-Machine application in Auth0 with the following scopes:

```
read:users
read:clients
read:organizations
read:roles
read:connections
read:users_app_metadata
read:user_idp_tokens
```

**How to create:**
1. Go to Auth0 Dashboard → Applications → APIs
2. Select "Auth0 Management API"
3. Go to "Machine to Machine Applications"
4. Authorize your application
5. Select the required scopes
6. Copy the Client ID and Client Secret
7. Generate token: `POST https://{domain}/oauth/token`

### 2. Target Organization (Optional)

If you want to import all data into a specific organization:

```bash
herd php artisan tinker
> Organization::find(1)
```

## Quick Start

### 1. Test Connection

Before migrating, test your Auth0 API connection:

```bash
herd php artisan migrate:auth0-test \
    --domain=your-tenant.auth0.com \
    --token=your-management-api-token
```

**Expected output:**
```
✓ Users API: OK (found X items)
✓ Clients API: OK (found X items)
✓ Organizations API: OK (found X items)
✓ Roles API: OK (found X items)
✓ Connections API: OK (found X items)
```

### 2. Dry Run Migration

Perform a dry run to see what will be imported:

```bash
herd php artisan migrate:auth0 \
    --domain=your-tenant.auth0.com \
    --token=your-management-api-token \
    --dry-run \
    --export=migration-plan.json
```

This will:
- Discover all resources from Auth0
- Display a summary of what will be migrated
- Export the plan to `migration-plan.json`
- **NOT** make any database changes

### 3. Execute Migration

Once you've reviewed the dry run:

```bash
herd php artisan migrate:auth0 \
    --domain=your-tenant.auth0.com \
    --token=your-management-api-token \
    --organization=1 \
    --strategy=lazy
```

## Migration Process

The migration happens in 4 phases:

### Phase 1: Organizations
- Imports organization structure
- Imports custom branding (logos, colors)
- Imports organization metadata

### Phase 2: Roles
- Imports custom roles
- Maps permissions to AuthOS permission system
- Skips system roles (admin, user, etc.)

### Phase 3: Applications
- Imports OAuth 2.0 clients
- Generates new client credentials
- Imports redirect URIs and settings
- Skips Auth0 system clients

### Phase 4: Users
- Imports user profiles
- Handles passwords based on strategy
- Imports social accounts
- Enables MFA if configured
- Imports user metadata

## Password Migration Strategies

Choose the appropriate strategy based on your needs:

### 1. Lazy Migration (Recommended)

```bash
--strategy=lazy
```

**How it works:**
- User imported with temporary password
- On first login, verify password against Auth0
- If successful, update local password
- Disable Auth0 verification after migration

**Pros:**
- Most secure
- No password reset required
- Seamless for users

**Cons:**
- Requires Auth0 to remain accessible temporarily
- Slightly more complex implementation

### 2. Password Reset

```bash
--strategy=reset
```

**How it works:**
- User imported with temporary password
- User marked for required password reset
- Password reset email sent automatically

**Pros:**
- Complete separation from Auth0
- Most secure long-term
- Good for security compliance

**Cons:**
- Users must reset passwords
- Potential support burden

### 3. Hash Import

```bash
--strategy=hash
```

**How it works:**
- Import password hash directly from Auth0
- Only works with database connections
- Not available for social connections

**Pros:**
- No user action required
- Seamless migration

**Cons:**
- Limited Auth0 API support
- May not work for all connection types

## Configuration

Edit `config/auth0-migration.php`:

```php
return [
    // Default password strategy
    'default_strategy' => 'lazy',

    // Batch size for API requests
    'batch_size' => 100,

    // API timeout (seconds)
    'timeout' => 300,

    // Backup before migration
    'backup_before_migration' => true,

    // Send welcome emails
    'send_welcome_emails' => false,

    // Continue on error
    'continue_on_error' => true,

    // Import options
    'import_social_accounts' => true,
    'import_mfa_settings' => true,
    'import_metadata' => true,
];
```

## Console Commands

### migrate:auth0-test

Test Auth0 API connection and permissions.

```bash
herd php artisan migrate:auth0-test \
    --domain=your-tenant.auth0.com \
    --token=your-token
```

### migrate:auth0

Execute Auth0 migration.

```bash
herd php artisan migrate:auth0 \
    --domain=your-tenant.auth0.com \
    --token=your-token \
    [--organization=ID] \
    [--dry-run] \
    [--strategy=lazy|reset|hash] \
    [--export=path/to/plan.json] \
    [--skip-validation]
```

**Options:**
- `--domain`: Auth0 tenant domain (e.g., example.auth0.com)
- `--token`: Auth0 Management API token
- `--organization`: Target organization ID (optional)
- `--dry-run`: Perform dry run without changes
- `--strategy`: Password migration strategy (default: lazy)
- `--export`: Export migration plan to JSON file
- `--skip-validation`: Skip post-migration validation

**Interactive mode:**
If options are not provided, the command will prompt for required values.

## Testing

Run the Auth0 migration tests:

```bash
# All Auth0 migration tests
./run-tests.sh tests/Unit/Services/Auth0/
./run-tests.sh tests/Feature/Services/Auth0/

# Specific test
herd php artisan test --filter=UserImporterTest
```

**Test coverage:**
- ✓ Auth0Client API wrapper
- ✓ DTOs (User, Client, Organization, Role)
- ✓ ImportResult tracking
- ✓ UserImporter with all strategies
- ✓ MigrationService orchestration

## Troubleshooting

### "Failed to connect to Auth0 API"

**Cause:** Invalid domain or token, or network issues.

**Solution:**
1. Verify domain format: `example.auth0.com` (no https://)
2. Check token is valid and not expired
3. Test connection: `migrate:auth0-test`
4. Verify API scopes are correct

### "User already exists"

**Cause:** User with same email already exists in database.

**Solution:**
- Users are automatically skipped
- Check migration summary for skipped count
- Delete existing users if re-importing is needed

### "Organization not found"

**Cause:** Specified organization ID doesn't exist.

**Solution:**
```bash
herd php artisan tinker
> Organization::all()
> Organization::find(1)
```

### "Validation failed after migration"

**Cause:** Data integrity issues detected.

**Solution:**
1. Review validation report
2. Choose to rollback or continue
3. Fix issues manually if needed

### "Memory limit exceeded"

**Cause:** Large dataset causing memory issues.

**Solution:**
1. Reduce batch size in config
2. Run migration in smaller chunks
3. Increase PHP memory limit

### "Rate limit exceeded"

**Cause:** Too many API requests to Auth0.

**Solution:**
1. Reduce batch size
2. Add delays between batches
3. Check Auth0 rate limits

## Rollback

If migration fails or you need to undo changes:

```php
use App\Services\Auth0\Migration\RollbackService;

$rollbackService = new RollbackService();
$rollbackService->rollback($migrationResult);
```

**What gets rolled back:**
- All imported users (with `imported_from_auth0` flag)
- All imported applications
- All imported roles
- All imported organizations

**Note:** Rollback only works for non-dry-run migrations.

## Post-Migration Checklist

After successful migration:

1. **Verify Data:**
   - Check user count matches
   - Verify applications imported correctly
   - Test role assignments

2. **Test Authentication:**
   - Test login with migrated user
   - Verify password strategy working
   - Test social login if applicable

3. **Configure Social Providers:**
   - Update OAuth callbacks in social providers
   - Point to new AuthOS URLs
   - Test social authentication

4. **Update Applications:**
   - Update application OAuth settings
   - Update client IDs/secrets in applications
   - Update callback URLs

5. **Notify Users (if needed):**
   - Send migration notification emails
   - Provide password reset instructions
   - Update documentation

6. **Monitor:**
   - Check authentication logs
   - Monitor error rates
   - Review support tickets

## Best Practices

1. **Always test first:**
   - Use `--dry-run` before actual migration
   - Test with small dataset first
   - Verify in staging environment

2. **Backup everything:**
   - Database backup before migration
   - Export Auth0 data as backup
   - Keep migration logs

3. **Plan migration window:**
   - Schedule during low traffic
   - Communicate with users
   - Have rollback plan ready

4. **Incremental migration:**
   - Migrate organizations first
   - Then roles and applications
   - Finally migrate users
   - Test between each phase

5. **Keep Auth0 running:**
   - Don't disable Auth0 immediately
   - Use lazy migration for seamless transition
   - Monitor both systems during transition

## Support

For issues or questions:
- Check logs: `storage/logs/laravel.log`
- Run tests: `./run-tests.sh tests/Feature/Services/Auth0/`
- Review migration report: `--export=report.json`

## Architecture

The migration system consists of:

```
Auth0Client (API wrapper)
├── UsersApi
├── ClientsApi
├── OrganizationsApi
├── RolesApi
└── ConnectionsApi

Auth0MigrationService (orchestrator)
├── Discovery phase
├── Migration phase
└── Validation phase

Importers
├── OrganizationImporter
├── RoleImporter
├── ApplicationImporter
└── UserImporter (with password strategies)

Support Services
├── MigrationValidator
├── RollbackService
└── ImportResult tracking
```

## Example: Complete Migration

```bash
# 1. Test connection
herd php artisan migrate:auth0-test \
    --domain=example.auth0.com \
    --token=eyJ...

# 2. Dry run with plan export
herd php artisan migrate:auth0 \
    --domain=example.auth0.com \
    --token=eyJ... \
    --dry-run \
    --export=migration-plan.json

# 3. Review the plan
cat migration-plan.json | jq

# 4. Execute migration
herd php artisan migrate:auth0 \
    --domain=example.auth0.com \
    --token=eyJ... \
    --organization=1 \
    --strategy=lazy

# 5. Verify results
herd php artisan tinker
> User::whereJsonContains('metadata->imported_from_auth0', true)->count()
> Application::whereJsonContains('metadata->imported_from_auth0', true)->count()
```

## Security Considerations

1. **Token Security:**
   - Never commit tokens to version control
   - Use environment variables
   - Rotate tokens after migration

2. **Password Handling:**
   - Use lazy migration for best security
   - Enforce password reset if needed
   - Monitor failed login attempts

3. **Data Privacy:**
   - Ensure GDPR compliance
   - Handle PII appropriately
   - Maintain audit trail

4. **Access Control:**
   - Limit who can run migrations
   - Log all migration activities
   - Review imported permissions

## Migration Timeline

**Typical timeline for 10,000 users:**

- Discovery: 2-5 minutes
- Organizations: 1-2 minutes
- Roles: 1-2 minutes
- Applications: 1-2 minutes
- Users: 10-30 minutes
- Validation: 2-5 minutes

**Total: 17-46 minutes**

Rate limits and batch sizes affect timing.
