# Webhook Infrastructure Architecture - Phase 6.1

## Executive Summary

This document outlines the comprehensive webhook infrastructure for the Laravel 12 authentication service (Auth0 alternative). The system provides real-time event notifications to external services with production-grade reliability, security, and scalability.

## Architecture Overview

### System Components

```
┌─────────────────────────────────────────────────────────────────┐
│                     Event Source Layer                           │
│  (User Events, Auth Events, Organization Events, etc.)          │
└────────────────┬────────────────────────────────────────────────┘
                 │
                 v
┌─────────────────────────────────────────────────────────────────┐
│                   Webhook Dispatcher                             │
│  - Event detection and filtering                                │
│  - Organization webhook lookup                                   │
│  - Queue job creation                                            │
└────────────────┬────────────────────────────────────────────────┘
                 │
                 v
┌─────────────────────────────────────────────────────────────────┐
│                    Queue Layer (Redis)                           │
│  - webhook_delivery (default)                                   │
│  - webhook_retry (exponential backoff)                          │
│  - webhook_deadletter (failed after max retries)                │
└────────────────┬────────────────────────────────────────────────┘
                 │
                 v
┌─────────────────────────────────────────────────────────────────┐
│              Webhook Delivery Service                            │
│  - HTTP client with timeout/retry                               │
│  - HMAC-SHA256 signature generation                             │
│  - Response validation and logging                              │
└────────────────┬────────────────────────────────────────────────┘
                 │
                 v
┌─────────────────────────────────────────────────────────────────┐
│               External Service Endpoint                          │
│  - Signature verification                                        │
│  - Event processing                                              │
│  - 2xx response for success                                      │
└─────────────────────────────────────────────────────────────────┘
```

## Database Schema Design

### 1. webhooks Table

Primary table storing webhook configurations per organization.

**Columns:**
- `id` (bigint, PK) - Primary identifier
- `organization_id` (bigint, FK) - Organization owning this webhook
- `name` (string, 255) - Human-readable webhook name
- `url` (string, 500) - Destination URL (HTTPS required)
- `secret` (string, 255) - HMAC signing secret
- `events` (json) - Array of subscribed event types
- `is_active` (boolean) - Enable/disable webhook
- `description` (text, nullable) - Optional documentation
- `headers` (json, nullable) - Custom headers to include
- `timeout_seconds` (int, default 30) - HTTP timeout
- `ip_whitelist` (json, nullable) - Optional IP restrictions
- `last_delivered_at` (timestamp, nullable) - Last successful delivery
- `last_failed_at` (timestamp, nullable) - Last failed attempt
- `failure_count` (int, default 0) - Consecutive failures
- `metadata` (json, nullable) - Custom organization data
- `created_at`, `updated_at`, `deleted_at` (timestamps)

**Indexes:**
- PRIMARY: `id`
- FOREIGN: `organization_id` -> organizations(id) CASCADE DELETE
- INDEX: `(organization_id, is_active)` - Fast active webhook lookup
- INDEX: `(organization_id, created_at)` - Organization listing
- UNIQUE: `(organization_id, url)` - Prevent duplicate URLs per org

**Validation Rules:**
- URL must be HTTPS (no localhost/127.0.0.1/10.x.x.x/192.168.x.x)
- Events array must contain valid event types
- Timeout between 5-120 seconds
- IP whitelist must be valid CIDR notation

### 2. webhook_deliveries Table

Tracks every webhook delivery attempt with full audit trail.

**Columns:**
- `id` (bigint, PK) - Primary identifier
- `webhook_id` (bigint, FK) - Associated webhook
- `event_type` (string, 100) - Event that triggered webhook
- `payload` (json) - Full event payload sent
- `status` (string, 50) - pending, sending, success, failed, retrying
- `http_status_code` (int, nullable) - HTTP response code
- `response_body` (text, nullable) - Response from endpoint (truncated 10KB)
- `response_headers` (json, nullable) - Response headers
- `error_message` (text, nullable) - Error details
- `attempt_number` (int, default 1) - Current retry attempt
- `max_attempts` (int, default 6) - Maximum retry attempts
- `next_retry_at` (timestamp, nullable) - Scheduled retry time
- `signature` (string, 255) - HMAC signature sent
- `request_duration_ms` (int, nullable) - HTTP request duration
- `sent_at` (timestamp, nullable) - Actual send time
- `completed_at` (timestamp, nullable) - Success/final failure time
- `created_at`, `updated_at` (timestamps)

**Indexes:**
- PRIMARY: `id`
- FOREIGN: `webhook_id` -> webhooks(id) CASCADE DELETE
- INDEX: `(webhook_id, created_at)` - Webhook history
- INDEX: `(status, next_retry_at)` - Retry queue processing
- INDEX: `(event_type, created_at)` - Event type analytics
- INDEX: `(webhook_id, status, created_at)` - Delivery status queries

**Status Transitions:**
```
pending -> sending -> success (200-299)
pending -> sending -> failed (4xx/5xx) -> retrying -> ... -> failed (final)
pending -> sending -> failed (network error) -> retrying -> ...
```

### 3. webhook_events Table

Registry of all supported webhook events with metadata.

**Columns:**
- `id` (bigint, PK) - Primary identifier
- `name` (string, 100, UNIQUE) - Event type identifier (e.g., user.created)
- `category` (string, 50) - Event category (user, auth, org, etc.)
- `description` (text) - Human-readable description
- `payload_schema` (json, nullable) - JSON schema for validation
- `is_active` (boolean) - Enable/disable event type
- `version` (string, 20, default '1.0') - Schema version
- `created_at`, `updated_at` (timestamps)

**Indexes:**
- PRIMARY: `id`
- UNIQUE: `name`
- INDEX: `(category, is_active)` - Category filtering
- INDEX: `is_active` - Active events only

## Supported Event Types

### User Events (Category: user)
- `user.created` - New user account created
- `user.updated` - User profile/settings updated
- `user.deleted` - User account deleted
- `user.suspended` - User account suspended
- `user.activated` - User account activated

### Authentication Events (Category: authentication)
- `authentication.login` - Successful login
- `authentication.logout` - User logged out
- `authentication.failed` - Failed login attempt
- `authentication.password_reset` - Password reset completed
- `authentication.session_expired` - Session timeout/expiry

### Application Events (Category: application)
- `application.created` - New OAuth application created
- `application.updated` - Application settings modified
- `application.deleted` - Application removed
- `application.credentials_rotated` - Client secret regenerated

### Organization Events (Category: organization)
- `organization.created` - New organization created
- `organization.updated` - Organization settings changed
- `organization.member_added` - New member joined
- `organization.member_removed` - Member removed
- `organization.settings_changed` - Security/compliance settings

### MFA Events (Category: mfa)
- `mfa.enabled` - MFA enabled for user
- `mfa.disabled` - MFA disabled for user
- `mfa.verified` - MFA verification succeeded
- `mfa.recovery_used` - Recovery code used
- `mfa.backup_codes_regenerated` - New backup codes generated

### SSO Events (Category: sso)
- `sso.session_created` - SSO session established
- `sso.session_ended` - SSO session terminated
- `sso.configuration_created` - New SSO config added
- `sso.configuration_updated` - SSO config modified

### Role Events (Category: role)
- `role.assigned` - Role assigned to user
- `role.revoked` - Role removed from user
- `role.created` - New custom role created
- `role.updated` - Role permissions modified

## Security Architecture

### 1. HMAC-SHA256 Signature

**Generation Process:**
```php
$timestamp = time();
$payload = json_encode($event_data);
$signature_base = $timestamp . '.' . $payload;
$signature = hash_hmac('sha256', $signature_base, $webhook->secret);
```

**HTTP Headers Sent:**
```
X-Webhook-Signature: sha256={signature}
X-Webhook-Timestamp: {timestamp}
X-Webhook-Event: {event_type}
X-Webhook-Delivery-ID: {delivery_id}
X-Webhook-Attempt: {attempt_number}
```

**Verification (Client-Side):**
```php
// 1. Extract timestamp from header
$timestamp = request()->header('X-Webhook-Timestamp');

// 2. Reject if timestamp > 5 minutes old (replay attack prevention)
if (abs(time() - $timestamp) > 300) {
    throw new Exception('Webhook timestamp expired');
}

// 3. Reconstruct signature base
$payload = file_get_contents('php://input');
$signature_base = $timestamp . '.' . $payload;

// 4. Calculate expected signature
$expected = hash_hmac('sha256', $signature_base, $your_secret);

// 5. Compare signatures (timing-safe)
$received = str_replace('sha256=', '', request()->header('X-Webhook-Signature'));
if (!hash_equals($expected, $received)) {
    throw new Exception('Invalid webhook signature');
}
```

### 2. URL Validation

**Blocked Patterns:**
- Localhost: `127.0.0.1`, `localhost`, `::1`
- Private networks: `10.x.x.x`, `172.16-31.x.x`, `192.168.x.x`
- Link-local: `169.254.x.x`, `fe80::/10`
- Non-HTTPS URLs (except development mode)
- URLs with credentials: `https://user:pass@example.com`

**Implementation:**
```php
public function validateWebhookUrl(string $url): void
{
    // Parse URL
    $parsed = parse_url($url);

    // Require HTTPS in production
    if (app()->environment('production') && $parsed['scheme'] !== 'https') {
        throw new InvalidArgumentException('HTTPS required for webhook URLs');
    }

    // Block localhost
    if (in_array($parsed['host'], ['localhost', '127.0.0.1', '::1'])) {
        throw new InvalidArgumentException('Localhost webhooks not allowed');
    }

    // Resolve to IP and check private ranges
    $ip = gethostbyname($parsed['host']);
    if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE) === false) {
        throw new InvalidArgumentException('Private IP webhooks not allowed');
    }
}
```

### 3. Secret Key Management

**Secret Generation:**
```php
$secret = bin2hex(random_bytes(32)); // 64-character hex string
```

**Secret Rotation:**
- Organizations can rotate secrets at any time
- Old secret remains valid for 24 hours (grace period)
- New deliveries use new secret immediately
- Retries of old deliveries use original secret

**Secret Storage:**
- Encrypted at rest using Laravel's encryption
- Never logged or exposed in responses
- Shown only once during webhook creation

### 4. Rate Limiting

**Per Organization Limits:**
- 1000 webhook deliveries per minute
- 10,000 webhook deliveries per hour
- 100,000 webhook deliveries per day

**Implementation:**
```php
RateLimiter::for('webhook-delivery', function (object $job) {
    return Limit::perMinute(1000)
        ->by($job->webhook->organization_id)
        ->response(function () {
            // Push back to queue with delay
            return 60; // seconds
        });
});
```

### 5. IP Whitelist (Optional)

Organizations can restrict webhook sources to specific IP addresses.

**Configuration:**
```json
{
    "ip_whitelist": [
        "203.0.113.0/24",
        "198.51.100.50"
    ]
}
```

**Enforcement:**
- Applied at HTTP client level
- Supports CIDR notation
- Empty whitelist = no restriction

## Retry Mechanism

### Exponential Backoff Strategy

**Retry Schedule:**
| Attempt | Delay       | Time After Original |
|---------|-------------|---------------------|
| 1       | Immediate   | 0 minutes           |
| 2       | 1 minute    | 1 minute            |
| 3       | 5 minutes   | 6 minutes           |
| 4       | 15 minutes  | 21 minutes          |
| 5       | 1 hour      | 1h 21m              |
| 6       | 6 hours     | 7h 21m              |
| 7       | 24 hours    | 31h 21m (final)     |

**Maximum Attempts:** 6 retries (7 total attempts)

### Retry Conditions

**Retry Triggered For:**
- Network errors (DNS failure, connection timeout, etc.)
- HTTP 408 (Request Timeout)
- HTTP 429 (Too Many Requests) - respect Retry-After header
- HTTP 500-599 (Server Errors)
- Response timeout (configurable per webhook)

**No Retry For:**
- HTTP 200-299 (Success)
- HTTP 400-407, 410-428 (Client Errors - bad request, not found, etc.)
- HTTP 401, 403 (Authentication/Authorization failures)
- Invalid SSL certificate
- Webhook disabled during retry

### Dead Letter Queue

After final failure:
1. Move to `webhook_deadletter` queue
2. Send notification to organization owner
3. Set webhook `failure_count` counter
4. Auto-disable webhook after 10 consecutive failures
5. Require manual re-enable after review

## Service Architecture

### 1. WebhookService

**Responsibilities:**
- Webhook CRUD operations
- Organization scope enforcement
- URL validation and secret generation
- Webhook testing (manual trigger)

**Key Methods:**
```php
public function createWebhook(Organization $org, array $data): Webhook
public function updateWebhook(Webhook $webhook, array $data): Webhook
public function deleteWebhook(Webhook $webhook): bool
public function testWebhook(Webhook $webhook): WebhookDelivery
public function rotateSecret(Webhook $webhook): string
public function getDeliveryStats(Webhook $webhook, ?int $days = 30): array
public function enableWebhook(Webhook $webhook): bool
public function disableWebhook(Webhook $webhook): bool
```

### 2. WebhookDeliveryService

**Responsibilities:**
- HTTP delivery with timeout/retry logic
- Response validation and logging
- Status tracking and metrics

**Key Methods:**
```php
public function deliver(WebhookDelivery $delivery): bool
public function scheduleRetry(WebhookDelivery $delivery): void
public function markSuccess(WebhookDelivery $delivery, Response $response): void
public function markFailed(WebhookDelivery $delivery, Exception $e): void
public function moveToDeadLetter(WebhookDelivery $delivery): void
public function getDeliveryHistory(Webhook $webhook, int $limit = 50): Collection
```

### 3. WebhookSignatureService

**Responsibilities:**
- HMAC signature generation
- Signature verification helpers
- Header construction

**Key Methods:**
```php
public function generateSignature(string $payload, string $secret, int $timestamp): string
public function verifySignature(string $payload, string $signature, string $secret, int $timestamp): bool
public function buildHeaders(WebhookDelivery $delivery): array
public function validateTimestamp(int $timestamp, int $maxAge = 300): bool
```

### 4. WebhookEventDispatcher

**Responsibilities:**
- Event detection and filtering
- Webhook lookup for event type
- Queue job dispatching

**Key Methods:**
```php
public function dispatch(string $eventType, Model $subject, array $payload): void
public function getSubscribedWebhooks(Organization $org, string $eventType): Collection
public function buildPayload(string $eventType, Model $subject, array $extra = []): array
public function shouldDispatch(Webhook $webhook, string $eventType): bool
```

## Queue Jobs

### 1. DeliverWebhookJob

**Purpose:** Primary job for webhook delivery

**Properties:**
```php
public function __construct(
    public WebhookDelivery $delivery
) {}

public int $tries = 1; // Single attempt per job
public int $timeout = 60; // 60 seconds max
public int $maxExceptions = 3;
```

**Logic:**
1. Load webhook and validate still active
2. Generate signature
3. Build HTTP headers
4. Send HTTP POST with timeout
5. Validate response (2xx = success)
6. Update delivery status
7. On failure: schedule retry job

### 2. RetryWebhookDeliveryJob

**Purpose:** Scheduled retry with exponential backoff

**Properties:**
```php
public function __construct(
    public WebhookDelivery $delivery
) {}

public int $tries = 1;
public int $timeout = 60;
public int $backoff = 0; // Calculated based on attempt
```

**Logic:**
1. Check if max attempts reached
2. If yes: move to dead letter queue
3. If no: increment attempt counter
4. Dispatch DeliverWebhookJob
5. On failure: calculate next backoff and reschedule

### 3. ProcessDeadLetterWebhookJob

**Purpose:** Handle permanently failed webhooks

**Properties:**
```php
public function __construct(
    public WebhookDelivery $delivery
) {}

public int $tries = 1;
```

**Logic:**
1. Mark delivery as permanently failed
2. Increment webhook failure counter
3. Check if failure threshold reached (10 consecutive)
4. If threshold: disable webhook
5. Send notification to organization admins
6. Create audit log entry

## Payload Structure

### Standard Webhook Payload

```json
{
    "id": "wh_delivery_123456",
    "event": "user.created",
    "created_at": "2025-10-06T10:30:00Z",
    "organization_id": "org_789",
    "data": {
        "id": "user_123",
        "email": "user@example.com",
        "name": "John Doe",
        "created_at": "2025-10-06T10:30:00Z",
        "organization_id": "org_789",
        "metadata": {
            "ip_address": "203.0.113.50",
            "user_agent": "Mozilla/5.0..."
        }
    },
    "previous": null,
    "metadata": {
        "webhook_id": "webhook_456",
        "delivery_attempt": 1
    }
}
```

### Event-Specific Data

**user.updated:**
```json
{
    "data": {...},
    "previous": {
        "email": "old@example.com",
        "name": "Jane Doe"
    },
    "changes": ["email", "name"]
}
```

**authentication.failed:**
```json
{
    "data": {
        "user_id": "user_123",
        "email": "user@example.com",
        "reason": "invalid_password",
        "ip_address": "203.0.113.50",
        "user_agent": "...",
        "failed_at": "2025-10-06T10:30:00Z"
    }
}
```

## Performance Considerations

### Database Optimization

**Partitioning Strategy:**
```sql
-- Partition webhook_deliveries by month
CREATE TABLE webhook_deliveries_2025_10 PARTITION OF webhook_deliveries
FOR VALUES FROM ('2025-10-01') TO ('2025-11-01');
```

**Retention Policy:**
- Keep delivery records for 90 days
- Archive to S3/cold storage after 30 days
- Prune archived records after 1 year

**Indexes:**
- Composite indexes for common queries
- Partial indexes for active webhooks only
- Expression indexes for JSON fields

### Caching Strategy

**Cache Keys:**
- `webhook:org:{id}:active` - Active webhooks for organization (TTL: 5 min)
- `webhook:events:subscribed:{org}:{event}` - Subscribed webhooks per event (TTL: 5 min)
- `webhook:delivery:stats:{webhook_id}:{date}` - Daily delivery stats (TTL: 1 hour)

**Cache Invalidation:**
- On webhook create/update/delete
- On delivery status change (success/failed)
- Manual invalidation via admin panel

### Monitoring Metrics

**Key Metrics:**
1. Delivery success rate (per webhook, per org, global)
2. Average delivery time (p50, p95, p99)
3. Retry rate and failure reasons
4. Queue depth and processing lag
5. Dead letter queue size

**Alerting Thresholds:**
- Delivery success rate < 95% (warning)
- Delivery success rate < 90% (critical)
- Average delivery time > 5s (warning)
- Queue depth > 10,000 (warning)
- Dead letter queue > 100 (critical)

## Implementation Roadmap

### Phase 6.1.1 - Core Infrastructure (Week 1)
- [ ] Database migrations
- [ ] Model classes with relationships
- [ ] Basic CRUD services
- [ ] Event enum and constants
- [ ] Unit tests for models

### Phase 6.1.2 - Delivery System (Week 1-2)
- [ ] WebhookDeliveryService
- [ ] WebhookSignatureService
- [ ] DeliverWebhookJob
- [ ] RetryWebhookDeliveryJob
- [ ] Integration tests

### Phase 6.1.3 - Event System (Week 2)
- [ ] WebhookEventDispatcher
- [ ] Event listeners for all event types
- [ ] Payload builders
- [ ] Event-specific tests

### Phase 6.1.4 - Admin Interface (Week 2-3)
- [ ] Filament Webhook resource
- [ ] Filament WebhookDelivery resource
- [ ] Webhook testing UI
- [ ] Delivery logs viewer
- [ ] Statistics dashboard

### Phase 6.1.5 - API Endpoints (Week 3)
- [ ] Webhook CRUD endpoints
- [ ] Delivery history endpoints
- [ ] Webhook testing endpoint
- [ ] Secret rotation endpoint
- [ ] Statistics endpoints
- [ ] API tests

### Phase 6.1.6 - Security & Optimization (Week 3-4)
- [ ] URL validation hardening
- [ ] Rate limiting implementation
- [ ] IP whitelist enforcement
- [ ] Performance optimization
- [ ] Load testing
- [ ] Security audit

### Phase 6.1.7 - Documentation (Week 4)
- [ ] Developer documentation
- [ ] API documentation
- [ ] Integration examples
- [ ] Troubleshooting guide
- [ ] Migration guide

## Testing Strategy

### Unit Tests (Target: 100 tests)
- Model validation rules
- Service method logic
- Signature generation/verification
- URL validation
- Retry backoff calculation

### Feature Tests (Target: 80 tests)
- Webhook CRUD operations
- Event dispatching
- Delivery success/failure flows
- Retry mechanism
- Dead letter queue
- Admin panel interactions

### Integration Tests (Target: 20 tests)
- End-to-end webhook flow
- Multi-tenant isolation
- Rate limiting
- Queue processing
- Concurrent deliveries

### Load Tests
- 1000 webhooks/minute sustained
- 10,000 concurrent deliveries
- Queue depth under load
- Database performance

## Security Checklist

- [ ] HTTPS enforcement for production
- [ ] Private IP/localhost blocking
- [ ] HMAC-SHA256 signature verification
- [ ] Timestamp validation (5-minute window)
- [ ] Rate limiting per organization
- [ ] IP whitelist support
- [ ] Secret rotation mechanism
- [ ] SQL injection prevention
- [ ] XSS prevention in admin panel
- [ ] CSRF protection on all endpoints
- [ ] Organization scope enforcement
- [ ] Audit logging for all operations

## Compliance Considerations

### GDPR
- Webhook payloads may contain PII
- Organization controls event subscriptions
- Right to erasure: webhook data deleted with user
- Data retention: 90-day configurable limit

### SOC 2
- Comprehensive audit trail (webhook_deliveries)
- Access controls (organization isolation)
- Encryption in transit (HTTPS)
- Monitoring and alerting

### ISO 27001
- Security controls documented
- Regular security reviews
- Incident response procedures
- Continuous monitoring

## Conclusion

This webhook infrastructure provides enterprise-grade real-time event notifications with:

- **Reliability**: Exponential backoff, 7 retry attempts, dead letter queue
- **Security**: HMAC signatures, HTTPS enforcement, URL validation, rate limiting
- **Scalability**: Queue-based processing, caching, database optimization
- **Observability**: Comprehensive logging, metrics, alerting
- **Developer Experience**: Simple API, clear documentation, testing tools

The system is designed to handle high-volume events (1000+/minute) while maintaining delivery guarantees and providing full visibility into webhook operations.
