# Bulk Operations Integration Tests

## Purpose
Test bulk user import/export functionality.

## What Belongs Here
- User import tests (CSV/Excel/JSON)
- User export tests with filtering
- Job management tests (status, errors, retry, cancel)
- Data validation tests
- Error handling tests

## Required Annotations
```php
/**
 * @test
 * @group integration
 * @group bulk
 */
```
