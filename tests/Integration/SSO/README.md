# SSO Integration Tests

## Purpose
Test Single Sign-On flows including OIDC and SAML 2.0 authentication.

## What Belongs Here
- OIDC SSO flow tests
- SAML 2.0 flow tests
- SSO configuration tests
- Token refresh tests
- Synchronized logout tests
- Redirect validation tests
- SSO metadata tests

## Test Naming Convention
```php
public function test_oidc_sso_login_creates_session()
public function test_saml_response_validation_succeeds()
public function test_synchronized_logout_revokes_all_sessions()
```

## Required Annotations
```php
/**
 * @test
 * @group integration
 * @group sso
 */
```
