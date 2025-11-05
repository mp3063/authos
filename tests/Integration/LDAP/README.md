# LDAP Integration Tests

## Purpose
Test LDAP/Active Directory authentication and synchronization.

## What Belongs Here
- LDAP connection tests
- User bind/authentication tests
- User discovery tests
- User sync tests (create/update)
- Auto email verification tests
- Connection failure handling tests

## Required Annotations
```php
/**
 * @test
 * @group integration
 * @group ldap
 */
```
