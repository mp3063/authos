# Background Jobs Integration Tests

## Purpose
Test background job execution and failure handling.

## What Belongs Here
- Webhook delivery job tests
- LDAP sync job tests
- Audit export job tests
- Compliance report job tests
- Bulk import/export job tests
- Migration job tests
- Job retry/failure tests

## Required Annotations
```php
/**
 * @test
 * @group integration
 * @group jobs
 */
```
