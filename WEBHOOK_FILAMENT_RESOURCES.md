# Webhook Filament Resources Documentation

## Overview
Comprehensive Filament 4 admin resources for webhook management in Laravel 12 authentication service, with full multi-tenant organization isolation.

## Created Resources

### 1. WebhookResource
**Location:** `/app/Filament/Resources/WebhookResource.php`

#### Features:
- **Full CRUD Operations** (Create, Read, Update, Delete)
- **Organization Isolation** - Users only see webhooks from their organization
- **Super Admin Access** - Full cross-organization visibility

#### Table Columns:
- Webhook name with URL preview
- Organization badge
- Event count badge
- Active/Inactive status
- Success rate (30-day) with color coding:
  - Green: ≥90%
  - Yellow: 70-90%
  - Red: <70%
- Total deliveries count
- Last delivery timestamp
- Failure count badge

#### Filters:
- Organization selector (super admins only)
- Active/Inactive status
- Event type by category
- Success rate ranges

#### Form Fields:
- **Basic Configuration:**
  - Name (required)
  - URL (HTTPS in production, validated)
  - Description (optional)
  - Organization selector
  - Active/Inactive toggle

- **Event Subscription:**
  - Grouped checkbox list of 32 events
  - Categories: User, Authentication, Application, Organization, MFA, SSO, Role
  - Searchable and bulk toggleable

- **Advanced Settings:**
  - Auto-generated webhook secret (shown once on creation)
  - Timeout configuration (1-300 seconds)
  - Custom HTTP headers (KeyValue)
  - IP whitelist (optional)

#### Actions:
- **Test Webhook** - Send test event
- **Rotate Secret** - Generate new secret with confirmation
- **Enable/Disable** - Toggle webhook status
- **View Deliveries** - Filter delivery list
- **Delete** - With confirmation

#### Bulk Actions:
- Enable multiple webhooks
- Disable multiple webhooks
- Delete multiple webhooks

#### Pages:
1. **ListWebhooks** - Tabbed interface:
   - All Webhooks
   - Active (badge count)
   - Inactive (badge count)
   - Failing (failure_count > 0)

2. **CreateWebhook** - Form with auto-secret generation
   - Shows generated secret in persistent notification
   - Redirects to view page after creation

3. **EditWebhook** - Full form access
   - Secret masked (use rotate action)
   - Redirects to view page after save

4. **ViewWebhook** - Comprehensive infolist:
   - Webhook information
   - Subscribed events
   - Statistics (success rate, avg delivery time, failures)
   - Advanced settings (collapsed)
   - Timestamps (collapsed)

### 2. WebhookDeliveryResource
**Location:** `/app/Filament/Resources/WebhookDeliveryResource.php`

#### Features:
- **Read-Only Logs** - No create/edit/delete operations
- **Organization Isolation** - Via webhook relationship
- **Retry Functionality** - Manual retry for failed deliveries

#### Table Columns:
- Webhook name (link to webhook)
- Event type badge
- Status badge with color:
  - Pending: Gray
  - Sending: Blue
  - Success: Green
  - Failed: Red
  - Retrying: Yellow
- HTTP status code badge
- Request duration (ms) with color coding
- Attempt number (X/7)
- Next retry timestamp
- Created at with relative time

#### Filters:
- Webhook selector
- Event type
- Status (all 5 statuses)
- Date range (created_from, created_until)

#### Actions:
- **View Details** - Full delivery information
- **Retry** - For failed/retryable deliveries
- **View Payload** - Modal with JSON syntax highlighting

#### Bulk Actions:
- Retry multiple failed deliveries

#### Pages:
1. **ListWebhookDeliveries** - Tabbed interface:
   - All Deliveries
   - Success
   - Failed
   - Retrying
   - Pending (includes sending)
   - Last 24 Hours

2. **ViewWebhookDelivery** - Detailed infolist:
   - **Delivery Information:**
     - Webhook link
     - Event type
     - Status

   - **HTTP Response:**
     - Status code
     - Duration
     - Attempt count
     - Error message (if any)

   - **Request Payload:**
     - Pretty-printed JSON
     - Copyable
     - Collapsed for successful deliveries

   - **Response Details:**
     - Response body (auto-formatted JSON)
     - Response headers
     - Collapsed for successful deliveries

   - **Retry Information:**
     - Next retry time
     - Webhook signature
     - Visible for retrying deliveries

   - **Timestamps:**
     - Created, sent, completed
     - With relative times

### 3. WebhookStatsWidget
**Location:** `/app/Filament/Resources/WebhookResource/Widgets/WebhookStatsWidget.php`

#### Stats Overview (8 Stats):
1. **Total Webhooks** - With active count
2. **Active Webhooks** - Currently enabled
3. **Deliveries (24h)** - With success count
4. **Success Rate (24h)** - Percentage with trend icon
5. **Failed (24h)** - Failed deliveries
6. **Avg Response Time** - In milliseconds
7. **Failing Webhooks** - With failure_count > 0
8. **Retrying** - Pending retry count

All stats are:
- Organization-scoped
- Clickable (link to relevant page/filter)
- Color-coded based on values

### 4. WebhookActivityChart
**Location:** `/app/Filament/Widgets/WebhookActivityChart.php`

#### Features:
- Line chart showing last 7 days
- Three datasets:
  - Successful (green)
  - Failed (red)
  - Retrying (yellow)
- Organization-scoped data
- Interactive tooltips
- Smooth line tension

## Navigation

**Navigation Group:** Integration
**Order:**
1. Webhooks (badge: active count)
2. Webhook Deliveries (badge: failed in last 24h)

## Security & Isolation

### Organization Scoping:
```php
// Non-super admins see only their organization's data
if (!$user->isSuperAdmin() && $user->organization_id) {
    $query->where('organization_id', $user->organization_id);
}

// Delivery scoping via webhook relationship
$query->whereHas('webhook', function ($q) use ($user) {
    $q->where('organization_id', $user->organization_id);
});
```

### Webhook Secret:
- Auto-generated 40-character random string
- Encrypted in database (uses Laravel Crypt)
- Shown once on creation
- Masked in edit form
- Rotatable with confirmation

### Validation:
- HTTPS required in production
- No localhost webhooks
- No private IP ranges in production
- No credentials in URL
- Valid event selection required

## Database Schema

### Webhooks Table:
- `id` - Primary key
- `organization_id` - Foreign key (cascade delete)
- `name` - Varchar(255)
- `url` - Varchar(500)
- `secret` - TEXT (encrypted)
- `events` - JSON array
- `is_active` - Boolean
- `description` - TEXT (nullable)
- `headers` - JSON (nullable)
- `timeout_seconds` - Integer (default: 30)
- `ip_whitelist` - JSON (nullable)
- `last_delivered_at` - Timestamp (nullable)
- `last_failed_at` - Timestamp (nullable)
- `failure_count` - Integer (default: 0)
- `metadata` - JSON (nullable)
- `created_at`, `updated_at`, `deleted_at`

**Indexes:**
- `(organization_id, is_active)`
- `(organization_id, created_at)`
- `UNIQUE (organization_id, url)`

### Webhook Deliveries Table:
- `id` - Primary key
- `webhook_id` - Foreign key (cascade delete)
- `event_type` - Varchar(100)
- `payload` - JSON
- `status` - Enum (pending, sending, success, failed, retrying)
- `http_status_code` - Integer (nullable)
- `response_body` - TEXT (max 10KB, nullable)
- `response_headers` - JSON (nullable)
- `error_message` - TEXT (nullable)
- `attempt_number` - Integer (default: 1)
- `max_attempts` - Integer (default: 7)
- `next_retry_at` - Timestamp (nullable)
- `signature` - TEXT
- `request_duration_ms` - Integer (nullable)
- `sent_at`, `completed_at` - Timestamps (nullable)
- `created_at`, `updated_at`

**Indexes:**
- `(webhook_id, status)`
- `(webhook_id, created_at)`
- `(status, next_retry_at)` - For retry queue

### Webhook Events Table:
- `id` - Primary key
- `name` - Varchar(100) UNIQUE (e.g., 'user.created')
- `category` - Varchar(50) (user, auth, org, app, mfa, sso, role)
- `description` - TEXT
- `payload_schema` - JSON (nullable)
- `is_active` - Boolean (default: true)
- `version` - Varchar(20) (default: '1.0')
- `created_at`, `updated_at`

## Event Categories (32 Events Total)

1. **User (5):** created, updated, deleted, suspended, activated
2. **Authentication (5):** login, logout, failed, password_reset, session_expired
3. **Application (4):** created, updated, deleted, credentials_rotated
4. **Organization (5):** created, updated, member_added, member_removed, settings_changed
5. **MFA (5):** enabled, disabled, verified, recovery_used, backup_codes_regenerated
6. **SSO (4):** session_created, session_ended, configuration_created, configuration_updated
7. **Role (4):** assigned, revoked, created, updated

## Services Integration

### WebhookService:
- `createWebhook()` - With validation
- `updateWebhook()` - URL validation
- `deleteWebhook()` - Cascade cleanup
- `enableWebhook()` - Reset failure count
- `disableWebhook()` - Stop deliveries
- `rotateSecret()` - Generate new secret
- `testWebhook()` - Send test payload
- `getDeliveryStats()` - Calculate metrics
- `checkAutoDisable()` - Auto-disable on failures

### WebhookDeliveryService:
- `deliver()` - Send webhook with signature
- `scheduleRetry()` - Exponential backoff
- `requeueFailedDelivery()` - Manual retry
- `getRetryableDeliveries()` - For queue processing

## Usage Examples

### Access URLs:
```
Admin Panel:
- http://authos.test/admin/webhooks
- http://authos.test/admin/webhooks/create
- http://authos.test/admin/webhooks/{id}
- http://authos.test/admin/webhooks/{id}/edit

Webhook Deliveries:
- http://authos.test/admin/webhook-deliveries
- http://authos.test/admin/webhook-deliveries/{id}
```

### Creating Webhook via Service:
```php
$webhookService = app(WebhookService::class);
$webhook = $webhookService->createWebhook($organization, [
    'name' => 'Production Webhook',
    'url' => 'https://api.example.com/webhooks',
    'events' => ['user.created', 'user.updated'],
    'is_active' => true,
    'timeout_seconds' => 30,
    'headers' => [
        'X-Custom-Header' => 'value'
    ],
    'ip_whitelist' => ['192.168.1.1', '10.0.0.1']
]);

// Secret is auto-generated and encrypted
// Returns: Webhook model instance
```

### Testing Webhook:
```php
$webhookService->testWebhook($webhook);
// Sends test payload to configured URL
// Returns: WebhookDelivery model
```

### Getting Statistics:
```php
$stats = $webhookService->getDeliveryStats($webhook, 30);
// Returns:
// [
//     'total_deliveries' => 150,
//     'successful_deliveries' => 140,
//     'failed_deliveries' => 10,
//     'retrying_deliveries' => 0,
//     'success_rate' => 93.33,
//     'average_delivery_time_ms' => 245,
//     'period_days' => 30
// ]
```

## Permissions & Roles

- **Super Admin:** Full access to all webhooks and deliveries across organizations
- **Organization Owner/Admin:** Full access to their organization's webhooks
- **Regular User:** View-only access to organization's webhooks

## Best Practices

1. **Always use HTTPS** in production for webhook URLs
2. **Validate webhook signatures** on receiving endpoint
3. **Monitor failure rates** - webhooks auto-disable after 10 failures
4. **Review deliveries regularly** - check failed/retrying tabs
5. **Rotate secrets periodically** - use rotate action
6. **Test before deployment** - use test webhook action
7. **Set appropriate timeouts** - based on endpoint response time
8. **Use IP whitelist** - for enhanced security when possible

## Troubleshooting

### Webhook Not Receiving Events:
1. Check `is_active` status
2. Verify event subscription
3. Check failure_count (auto-disabled at 10)
4. Test webhook connectivity
5. Review delivery logs

### Failed Deliveries:
1. Check HTTP status code
2. Review error message
3. Verify endpoint availability
4. Check IP whitelist settings
5. Manual retry if needed

### Organization Isolation Issues:
1. Verify user's `organization_id`
2. Check super admin status
3. Review `getEloquentQuery()` scoping
4. Confirm webhook's `organization_id`

## Testing Checklist

- [x] Create webhook via admin panel
- [x] Edit webhook settings
- [x] Test webhook action
- [x] Rotate secret action
- [x] Enable/disable webhook
- [x] Delete webhook
- [x] View webhook details
- [x] List webhook deliveries
- [x] View delivery details
- [x] Retry failed delivery
- [x] Bulk enable/disable webhooks
- [x] Bulk retry deliveries
- [x] Organization isolation (non-super admin)
- [x] Super admin cross-org access
- [x] Widget statistics display
- [x] Activity chart rendering
- [x] Tab filtering
- [x] Success rate calculation

## Files Created

### Resources:
1. `/app/Filament/Resources/WebhookResource.php`
2. `/app/Filament/Resources/WebhookDeliveryResource.php`

### Pages:
3. `/app/Filament/Resources/WebhookResource/Pages/ListWebhooks.php`
4. `/app/Filament/Resources/WebhookResource/Pages/CreateWebhook.php`
5. `/app/Filament/Resources/WebhookResource/Pages/EditWebhook.php`
6. `/app/Filament/Resources/WebhookResource/Pages/ViewWebhook.php`
7. `/app/Filament/Resources/WebhookDeliveryResource/Pages/ListWebhookDeliveries.php`
8. `/app/Filament/Resources/WebhookDeliveryResource/Pages/ViewWebhookDelivery.php`

### Widgets:
9. `/app/Filament/Resources/WebhookResource/Widgets/WebhookStatsWidget.php`
10. `/app/Filament/Widgets/WebhookActivityChart.php`

### Views:
11. `/resources/views/filament/modals/webhook-payload.blade.php`

### Migrations:
12. Updated: `/database/migrations/2025_10_06_113712_create_webhooks_table.php` (secret field to TEXT)

## Migration Note

The `secret` column in `webhooks` table was updated from `VARCHAR(255)` to `TEXT` to accommodate encrypted secrets which can exceed 255 characters:

```sql
ALTER TABLE webhooks ALTER COLUMN secret TYPE TEXT;
```

This change has been applied to the migration file for future deployments.

## Summary

✅ **Completed:**
- Full CRUD webhook management
- Read-only delivery logs
- Organization isolation
- Super admin access
- Comprehensive filtering & search
- Test webhook functionality
- Secret rotation
- Manual retry for failed deliveries
- Bulk operations
- Dashboard widgets
- Activity charts
- Detailed infolists
- Event subscription management
- 32 webhook events across 7 categories

The webhook management system is fully functional and ready for production use!
