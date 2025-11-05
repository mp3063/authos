# Monitoring Integration Tests

## Purpose
Test health checks, metrics collection, and error tracking.

## What Belongs Here
- Health check tests (basic, detailed, component-specific)
- Metrics collection tests (auth, oauth, api, webhooks)
- Error tracking tests
- Custom metrics recording tests
- Performance metrics tests

## Required Annotations
```php
/**
 * @test
 * @group integration
 * @group monitoring
 */
```
