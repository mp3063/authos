# Webhook Integration Tests

## Purpose
Test webhook delivery flows including creation, pattern matching, retry logic, and circuit breaker.

## What Belongs Here
- Webhook CRUD tests
- Webhook delivery flow tests
- Retry logic tests (exponential backoff)
- Pattern matching tests (wildcards)
- Event dispatch tests
- Circuit breaker tests (auto-disable after failures)

## Test Naming Convention
```php
public function test_webhook_delivers_successfully_on_event()
public function test_failed_delivery_retries_with_exponential_backoff()
public function test_wildcard_pattern_matches_all_events()
```

## Required Annotations
```php
/**
 * @test
 * @group integration
 * @group webhooks
 */
```
