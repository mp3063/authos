# Model Lifecycle Integration Tests

## Purpose
Test model lifecycle events, observers, and side effects.

## What Belongs Here
- Application lifecycle tests (auto-generate credentials)
- SSO session lifecycle tests
- Cache invalidation observer tests
- Model event tests
- Observer trigger tests

## Required Annotations
```php
/**
 * @test
 * @group integration
 * @group models
 */
```
