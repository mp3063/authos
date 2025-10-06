# Webhook API Documentation

## Overview

Comprehensive REST API endpoints for webhook management in the Laravel 12 authentication service. This implementation provides full CRUD operations, delivery management, event subscriptions, and analytics.

## Implementation Summary

### Files Created

**Controllers (3 files):**
- `/app/Http/Controllers/Api/WebhookController.php` - Main CRUD + action endpoints
- `/app/Http/Controllers/Api/WebhookDeliveryController.php` - Delivery management
- `/app/Http/Controllers/Api/WebhookEventController.php` - Event listing

**FormRequests (2 files):**
- `/app/Http/Requests/Webhook/StoreWebhookRequest.php` - Create validation
- `/app/Http/Requests/Webhook/UpdateWebhookRequest.php` - Update validation

**Resources (3 files):**
- `/app/Http/Resources/WebhookResource.php` - Webhook transformation
- `/app/Http/Resources/WebhookDeliveryResource.php` - Delivery transformation
- `/app/Http/Resources/WebhookEventResource.php` - Event transformation

**Routes:**
- Updated `/routes/api.php` with 13 new webhook endpoints

---

## API Endpoints

### 1. Webhook Management (5 endpoints)

#### List Webhooks
```
GET /api/v1/webhooks
```

**Query Parameters:**
- `page` (integer, min: 1) - Page number
- `per_page` (integer, min: 1, max: 100) - Items per page (default: 15)
- `search` (string) - Search by name, URL, or description
- `sort` (string) - Sort field: name, url, created_at, updated_at, last_delivered_at
- `order` (string) - asc or desc (default: desc)
- `is_active` (boolean) - Filter by active status
- `event` (string) - Filter by subscribed event

**Response:**
```json
{
  "success": true,
  "data": [
    {
      "id": 1,
      "name": "User Events Webhook",
      "url": "https://example.com/webhooks",
      "events": ["user.created", "user.updated"],
      "is_active": true,
      "custom_headers": {"X-Custom": "value"},
      "timeout_seconds": 15,
      "failure_count": 0,
      "created_at": "2025-10-06T10:00:00Z"
    }
  ],
  "meta": {
    "current_page": 1,
    "last_page": 5,
    "per_page": 15,
    "total": 75
  }
}
```

**Middleware:** `auth:api`, `throttle:api`, `org.boundary`, `api.cache:300`

---

#### Create Webhook
```
POST /api/v1/webhooks
```

**Request Body:**
```json
{
  "name": "User Events Webhook",
  "url": "https://example.com/webhooks",
  "events": ["user.created", "user.updated"],
  "is_active": true,
  "description": "Webhook for user lifecycle events",
  "custom_headers": {
    "X-Custom-Header": "value"
  },
  "timeout_seconds": 15,
  "ip_whitelist": ["192.168.1.1", "10.0.0.1"],
  "metadata": {
    "team": "backend",
    "environment": "production"
  }
}
```

**Validation Rules:**
- `name` (required, string, max: 255)
- `url` (required, url, max: 2048) - Must be HTTPS in production
- `events` (required, array, min: 1) - Valid webhook events
- `is_active` (optional, boolean, default: true)
- `description` (optional, string, max: 1000)
- `custom_headers` (optional, array, max: 10 headers)
- `timeout_seconds` (optional, integer, min: 1, max: 30, default: 15)
- `ip_whitelist` (optional, array, max: 20 IPs)
- `metadata` (optional, array)

**Response (201 Created):**
```json
{
  "success": true,
  "data": {
    "id": 1,
    "name": "User Events Webhook",
    "url": "https://example.com/webhooks",
    "secret": "whsec_abc123...", // Only shown on creation
    "events": ["user.created", "user.updated"],
    "is_active": true,
    "created_at": "2025-10-06T10:00:00Z"
  },
  "message": "Webhook created successfully"
}
```

**Middleware:** `auth:api`, `throttle:api`, `org.boundary`

---

#### Get Webhook Details
```
GET /api/v1/webhooks/{id}
```

**Response:**
```json
{
  "success": true,
  "data": {
    "id": 1,
    "name": "User Events Webhook",
    "url": "https://example.com/webhooks",
    "events": ["user.created", "user.updated"],
    "is_active": true,
    "description": "Webhook for user lifecycle events",
    "custom_headers": {"X-Custom": "value"},
    "timeout_seconds": 15,
    "ip_whitelist": ["192.168.1.1"],
    "last_delivered_at": "2025-10-06T09:30:00Z",
    "last_failed_at": null,
    "failure_count": 0,
    "metadata": {"team": "backend"},
    "organization": {
      "id": 1,
      "name": "TechCorp"
    },
    "created_at": "2025-10-06T10:00:00Z",
    "updated_at": "2025-10-06T10:00:00Z"
  }
}
```

**Middleware:** `auth:api`, `throttle:api`, `org.boundary`, `api.cache:600`

---

#### Update Webhook
```
PUT /api/v1/webhooks/{id}
```

**Request Body:** (All fields optional)
```json
{
  "name": "Updated Webhook Name",
  "url": "https://example.com/new-webhook",
  "events": ["user.created", "user.updated", "user.deleted"],
  "is_active": true,
  "description": "Updated description",
  "custom_headers": {"X-New-Header": "value"},
  "timeout_seconds": 20
}
```

**Response:**
```json
{
  "success": true,
  "data": {
    "id": 1,
    "name": "Updated Webhook Name",
    // ... updated fields
  },
  "message": "Webhook updated successfully"
}
```

**Middleware:** `auth:api`, `throttle:api`, `org.boundary`

---

#### Delete Webhook
```
DELETE /api/v1/webhooks/{id}
```

**Response (200):**
```json
{
  "success": true,
  "message": "Webhook deleted successfully"
}
```

**Middleware:** `auth:api`, `throttle:api`, `org.boundary`

---

### 2. Webhook Actions (4 endpoints)

#### Send Test Webhook
```
POST /api/v1/webhooks/{id}/test
```

**Response:**
```json
{
  "success": true,
  "data": {
    "message": "Test webhook sent successfully",
    "delivery_id": 123,
    "status": "pending",
    "sent_at": "2025-10-06T10:15:00Z"
  },
  "message": "Test webhook sent successfully"
}
```

**Rate Limit:** 5 requests per minute

**Middleware:** `auth:api`, `throttle:5,1`, `org.boundary`

---

#### Rotate Webhook Secret
```
POST /api/v1/webhooks/{id}/rotate-secret
```

**Response:**
```json
{
  "success": true,
  "data": {
    "secret": "whsec_new_abc123...",
    "message": "Webhook secret rotated successfully"
  },
  "message": "Webhook secret rotated successfully"
}
```

**Note:** This invalidates the old secret and revokes all existing tokens.

**Middleware:** `auth:api`, `throttle:api`, `org.boundary`

---

#### Enable Webhook
```
POST /api/v1/webhooks/{id}/enable
```

**Response:**
```json
{
  "success": true,
  "data": {
    "is_active": true
  },
  "message": "Webhook enabled successfully"
}
```

**Middleware:** `auth:api`, `throttle:api`, `org.boundary`

---

#### Disable Webhook
```
POST /api/v1/webhooks/{id}/disable
```

**Response:**
```json
{
  "success": true,
  "data": {
    "is_active": false
  },
  "message": "Webhook disabled successfully"
}
```

**Middleware:** `auth:api`, `throttle:api`, `org.boundary`

---

### 3. Delivery Management (3 endpoints)

#### List Webhook Deliveries
```
GET /api/v1/webhooks/{id}/deliveries
```

**Query Parameters:**
- `page` (integer) - Page number
- `per_page` (integer, max: 100) - Items per page (default: 20)
- `status` (string) - Filter by: pending, sending, success, failed, retrying
- `event_type` (string) - Filter by event type

**Response:**
```json
{
  "success": true,
  "data": [
    {
      "id": 123,
      "webhook_id": 1,
      "event_type": "user.created",
      "status": "success",
      "http_status_code": 200,
      "attempt_number": 1,
      "max_attempts": 6,
      "request_duration_ms": 245,
      "sent_at": "2025-10-06T10:00:00Z",
      "completed_at": "2025-10-06T10:00:00Z",
      "created_at": "2025-10-06T10:00:00Z"
    }
  ],
  "meta": {
    "current_page": 1,
    "total": 150
  }
}
```

**Middleware:** `auth:api`, `throttle:api`, `org.boundary`

---

#### Get Delivery Statistics
```
GET /api/v1/webhooks/{id}/stats
```

**Query Parameters:**
- `days` (integer, min: 1, max: 90, default: 30) - Statistics period

**Response:**
```json
{
  "success": true,
  "data": {
    "total_deliveries": 1250,
    "successful_deliveries": 1200,
    "failed_deliveries": 30,
    "retrying_deliveries": 20,
    "success_rate": 96.0,
    "average_delivery_time_ms": 234,
    "period_days": 30
  }
}
```

**Middleware:** `auth:api`, `throttle:api`, `org.boundary`, `api.cache:300`

---

#### Retry Failed Delivery
```
POST /api/v1/webhook-deliveries/{id}/retry
```

**Response:**
```json
{
  "success": true,
  "data": {
    "id": 123,
    "status": "retrying",
    "attempt_number": 2,
    "next_retry_at": "2025-10-06T10:20:00Z"
  },
  "message": "Webhook delivery retry initiated successfully"
}
```

**Rate Limit:** 10 requests per minute

**Middleware:** `auth:api`, `throttle:10,1`, `org.boundary`

---

### 4. Webhook Events (3 endpoints)

#### List Available Events
```
GET /api/v1/webhook-events
```

**Query Parameters:**
- `category` (string) - Filter by: user, organization, application, auth, sso, system
- `is_active` (boolean) - Filter by active status
- `include_schema` (boolean) - Include payload schemas

**Response:**
```json
{
  "success": true,
  "data": [
    {
      "id": 1,
      "name": "user.created",
      "category": "user",
      "description": "Triggered when a new user is created",
      "is_active": true,
      "version": "1.0",
      "created_at": "2025-01-01T00:00:00Z"
    },
    {
      "id": 2,
      "name": "user.updated",
      "category": "user",
      "description": "Triggered when a user is updated",
      "is_active": true,
      "version": "1.0",
      "created_at": "2025-01-01T00:00:00Z"
    }
  ]
}
```

**Cache:** 1 hour

**Middleware:** `auth:api`, `throttle:api`, `api.cache:3600`

---

#### List Events Grouped by Category
```
GET /api/v1/webhook-events/grouped
```

**Response:**
```json
{
  "success": true,
  "data": [
    {
      "category": "user",
      "events": [
        {"id": 1, "name": "user.created", "description": "..."},
        {"id": 2, "name": "user.updated", "description": "..."}
      ]
    },
    {
      "category": "organization",
      "events": [
        {"id": 3, "name": "organization.created", "description": "..."}
      ]
    }
  ]
}
```

**Cache:** 1 hour

**Middleware:** `auth:api`, `throttle:api`, `api.cache:3600`

---

#### Get Event Details
```
GET /api/v1/webhook-events/{id}
```

**Response:**
```json
{
  "success": true,
  "data": {
    "id": 1,
    "name": "user.created",
    "category": "user",
    "description": "Triggered when a new user is created",
    "is_active": true,
    "version": "1.0",
    "payload_schema": {
      "type": "object",
      "properties": {
        "user_id": {"type": "integer"},
        "email": {"type": "string"}
      }
    },
    "created_at": "2025-01-01T00:00:00Z"
  }
}
```

**Cache:** 1 hour

**Middleware:** `auth:api`, `throttle:api`, `api.cache:3600`

---

## Security Features

### Authentication & Authorization
- **OAuth 2.0:** All endpoints require `auth:api` middleware
- **Permission Gates:**
  - `webhooks.create` - Create webhooks
  - `webhooks.read` - View webhooks
  - `webhooks.update` - Modify webhooks
  - `webhooks.delete` - Delete webhooks

### Multi-Tenant Isolation
- **Organization Boundary:** `org.boundary` middleware enforces organization-level data isolation
- Non-super-admin users only see webhooks from their organization
- Super admins can view/manage all webhooks across organizations

### Rate Limiting
- **Standard endpoints:** `throttle:api` (100 requests/minute)
- **Test webhook:** 5 requests/minute
- **Retry delivery:** 10 requests/minute

### URL Validation
- HTTPS required in production
- Blocks localhost and private IP ranges
- No credentials allowed in URLs
- Maximum 10 custom headers per webhook

---

## Response Format

All endpoints follow the standardized API response format:

**Success Response:**
```json
{
  "success": true,
  "data": {...},
  "message": "Optional message"
}
```

**Error Response:**
```json
{
  "success": false,
  "error": {
    "message": "Error description",
    "code": "error_code"
  }
}
```

**Validation Error:**
```json
{
  "success": false,
  "error": "validation_failed",
  "error_description": "The given data was invalid.",
  "errors": {
    "url": ["The url field is required."]
  }
}
```

---

## Caching Strategy

- **Webhook list:** 5 minutes (300 seconds)
- **Webhook details:** 10 minutes (600 seconds)
- **Delivery stats:** 5 minutes (300 seconds)
- **Webhook events:** 1 hour (3600 seconds)

---

## Example Usage

### Create a Webhook
```bash
curl -X POST https://authos.test/api/v1/webhooks \
  -H "Authorization: Bearer {token}" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Production User Events",
    "url": "https://api.example.com/webhooks/users",
    "events": ["user.created", "user.updated", "user.deleted"],
    "custom_headers": {
      "X-API-Key": "your-api-key"
    }
  }'
```

### Test a Webhook
```bash
curl -X POST https://authos.test/api/v1/webhooks/1/test \
  -H "Authorization: Bearer {token}"
```

### Get Delivery Statistics
```bash
curl -X GET "https://authos.test/api/v1/webhooks/1/stats?days=7" \
  -H "Authorization: Bearer {token}"
```

### Retry Failed Delivery
```bash
curl -X POST https://authos.test/api/v1/webhook-deliveries/123/retry \
  -H "Authorization: Bearer {token}"
```

---

## Integration with Existing Infrastructure

### Models Used
- `Webhook` - Main webhook configuration
- `WebhookDelivery` - Delivery attempts and status
- `WebhookEvent` - Available event types

### Services Used
- `WebhookService` - Business logic for webhook operations
- `WebhookDeliveryService` - Handles delivery attempts
- `WebhookSignatureService` - HMAC signature generation

### Middleware Applied
- `auth:api` - OAuth 2.0 authentication
- `throttle:api` - Rate limiting
- `org.boundary` - Multi-tenant isolation
- `api.cache` - Response caching

---

## Testing Recommendations

1. **Unit Tests:**
   - Request validation (StoreWebhookRequest, UpdateWebhookRequest)
   - Resource transformations (WebhookResource, etc.)

2. **Feature Tests:**
   - CRUD operations with proper authorization
   - Organization isolation enforcement
   - Rate limiting behavior
   - Error handling scenarios

3. **Integration Tests:**
   - Webhook delivery flow
   - Secret rotation and token invalidation
   - Event filtering and statistics

---

## Performance Considerations

- **Database Indexes:** Ensure indexes on `organization_id`, `is_active`, `events` (JSON)
- **Query Optimization:** Uses eager loading for relationships
- **Caching:** Aggressive caching for read-heavy endpoints
- **Pagination:** Default 15-20 items per page, max 100

---

## Total Endpoint Count

**New Endpoints:** 13
- Webhook CRUD: 5
- Webhook Actions: 4
- Delivery Management: 3
- Webhook Events: 3 (including grouped endpoint)

**Updated Total:** 144 + 13 = **157 REST endpoints**

---

## Files Summary

**Created Files (8):**
1. `app/Http/Controllers/Api/WebhookController.php` (476 lines)
2. `app/Http/Controllers/Api/WebhookDeliveryController.php` (107 lines)
3. `app/Http/Controllers/Api/WebhookEventController.php` (125 lines)
4. `app/Http/Requests/Webhook/StoreWebhookRequest.php` (107 lines)
5. `app/Http/Requests/Webhook/UpdateWebhookRequest.php` (88 lines)
6. `app/Http/Resources/WebhookResource.php` (63 lines)
7. `app/Http/Resources/WebhookDeliveryResource.php` (57 lines)
8. `app/Http/Resources/WebhookEventResource.php` (38 lines)

**Modified Files (1):**
1. `routes/api.php` (Added 33 lines of webhook routes)

---

## Compatibility

- **Laravel:** 12.25.0
- **PHP:** 8.4+
- **Filament:** 4.x (Admin panel integration ready)
- **PostgreSQL:** JSON column support required for events array
- **Redis/Database:** Caching layer

---

## Next Steps

1. **Seeding:** Create webhook event seeders for available events
2. **Testing:** Write comprehensive feature tests for all endpoints
3. **Documentation:** Add API documentation to OpenAPI/Swagger spec
4. **Monitoring:** Set up alerts for webhook failure rates
5. **Dashboard:** Add webhook analytics to Filament admin panel

---

Generated: 2025-10-06
Version: 1.0
