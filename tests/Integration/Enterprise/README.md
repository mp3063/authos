# Enterprise Integration Tests

## Purpose
Test enterprise features including LDAP, domain verification, audit exports, and compliance reports.

## What Belongs Here
- LDAP authentication and sync tests
- Domain verification tests (DNS TXT records)
- Audit export tests (CSV, JSON, Excel)
- Compliance report tests (SOC2, ISO 27001, GDPR)
- Branding tests (logo, colors, custom CSS)

## Required Annotations
```php
/**
 * @test
 * @group integration
 * @group enterprise
 */
```
