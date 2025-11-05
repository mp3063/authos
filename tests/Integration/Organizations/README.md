# Organizations Integration Tests

## Purpose
Test complete organization management flows including CRUD, settings, users, analytics, and reporting.

## What Belongs Here
- Organization CRUD tests
- Settings management tests
- User management within organization tests
- Analytics and metrics tests
- Invitation tests (create, resend, bulk, accept)
- Bulk operations tests
- Custom roles tests
- Reports tests (user activity, app usage, security audit)

## Test Naming Convention
```php
public function test_organization_owner_can_update_settings()
public function test_user_invitation_flow_completes()
public function test_organization_analytics_returns_correct_metrics()
```

## Required Annotations
```php
/**
 * @test
 * @group integration
 * @group organizations
 */
```
