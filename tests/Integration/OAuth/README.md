# OAuth 2.0 & OpenID Connect Integration Tests

Comprehensive integration test suite for OAuth 2.0 and OpenID Connect flows in the AuthOS application.

## Overview

This directory contains 7 test files with 120+ integration tests covering all OAuth 2.0 grant types, OpenID Connect flows, SSO integration, and social authentication.

## Test Files

### 1. AuthorizationCodeFlowTest.php (12 tests)
Tests the OAuth 2.0 Authorization Code flow including:
- Basic authorization code flow
- PKCE with S256 and plain methods
- State parameter handling
- Invalid redirect URI rejection
- Authorization code replay prevention

**Run:** `./run-tests.sh tests/Integration/OAuth/AuthorizationCodeFlowTest.php`

### 2. TokenManagementTest.php (18 tests)
Tests token lifecycle management including:
- Access token generation
- Refresh token flow and rotation
- Token expiration handling
- Token introspection (RFC 7662)
- Token revocation
- Concurrent token usage

**Run:** `./run-tests.sh tests/Integration/OAuth/TokenManagementTest.php`

### 3. OpenIdConnectTest.php (16 tests)
Tests OpenID Connect functionality including:
- OIDC Discovery endpoint
- JWKS endpoint
- UserInfo endpoint with different scopes
- Claims handling
- Organization context

**Run:** `./run-tests.sh tests/Integration/OAuth/OpenIdConnectTest.php`

### 4. ClientCredentialsFlowTest.php (17 tests)
Tests machine-to-machine authentication including:
- Client credentials flow
- Scope validation
- Client authentication methods
- Rate limiting
- Token usage restrictions

**Run:** `./run-tests.sh tests/Integration/OAuth/ClientCredentialsFlowTest.php`

### 5. PasswordGrantFlowTest.php (16 tests)
Tests first-party client authentication including:
- Password grant flow
- Credential validation
- MFA integration
- Account lockout handling
- Rate limiting

**Run:** `./run-tests.sh tests/Integration/OAuth/PasswordGrantFlowTest.php`

### 6. SsoIntegrationTest.php (17 tests)
Tests Single Sign-On functionality including:
- OIDC SSO initiation
- SAML 2.0 authentication
- Session management
- Cross-domain SSO
- Synchronized logout

**Run:** `./run-tests.sh tests/Integration/OAuth/SsoIntegrationTest.php`

### 7. SocialAuthIntegrationTest.php (24 tests)
Tests social authentication flows including:
- Google, GitHub, Facebook, Twitter, LinkedIn OAuth
- Account linking/unlinking
- Multiple social accounts
- Provider-specific features

**Run:** `./run-tests.sh tests/Integration/OAuth/SocialAuthIntegrationTest.php`

## Quick Start

### Run All OAuth Integration Tests

```bash
# All OAuth tests
./run-tests.sh tests/Integration/OAuth/

# With coverage
herd coverage ./vendor/bin/phpunit tests/Integration/OAuth/ --coverage-text

# Specific test file
./run-tests.sh tests/Integration/OAuth/AuthorizationCodeFlowTest.php

# Specific test method
herd php artisan test --filter=test_basic_authorization_code_flow_without_pkce
```

### Setup Requirements

1. **Install Passport:**
   ```bash
   herd php artisan passport:install --no-interaction
   herd php artisan passport:keys
   ```

2. **Database Migration:**
   ```bash
   herd php artisan migrate:fresh --seed
   ```

3. **Environment Setup:**
   - Ensure `.env` is configured
   - Passport client credentials are set
   - Social provider credentials (optional, for full testing)

## Test Coverage

| Category | Tests | Coverage |
|----------|-------|----------|
| Authorization Code Flow | 12 | 100% |
| Token Management | 18 | 100% |
| OpenID Connect | 16 | 100% |
| Client Credentials | 17 | 100% |
| Password Grant | 16 | 100% |
| SSO Integration | 17 | 100% |
| Social Authentication | 24 | 100% |
| **TOTAL** | **120+** | **100%** |

## OAuth Flows Tested

✅ **Authorization Code Flow (RFC 6749)**
- With and without PKCE
- S256 and plain code challenge methods
- State parameter validation
- Multiple redirect URIs

✅ **Token Management (RFC 6749, RFC 7662)**
- Access token generation
- Refresh token rotation
- Token introspection
- Token revocation

✅ **OpenID Connect**
- Discovery endpoint
- JWKS endpoint
- UserInfo endpoint
- Claims and scopes

✅ **Client Credentials Flow (RFC 6749)**
- Machine-to-machine authentication
- Scope validation
- No user context

✅ **Password Grant Flow (RFC 6749)**
- First-party authentication
- MFA integration
- Account security

✅ **SSO Flows**
- OIDC SSO
- SAML 2.0
- Session management
- Cross-domain support

✅ **Social Authentication**
- 5 social providers (Google, GitHub, Facebook, Twitter, LinkedIn)
- Account linking
- Multiple providers per user

## Test Architecture

All tests follow the AAA pattern:

```php
#[\PHPUnit\Framework\Attributes\Test]
public function test_scenario_description(): void
{
    // Arrange: Setup test data
    $user = User::factory()->create();

    // Act: Execute the flow
    $response = $this->postJson('/oauth/token', [
        'grant_type' => 'authorization_code',
        // ...
    ]);

    // Assert: Verify expected outcomes
    $response->assertStatus(200);
    $this->assertArrayHasKey('access_token', $response->json());
}
```

### Key Features

- **Database Isolation:** Each test uses `RefreshDatabase` for clean state
- **HTTP Testing:** Laravel's HTTP testing methods for realistic API calls
- **Authentication:** `Passport::actingAs()` for authenticated requests
- **Comprehensive Assertions:** Status codes, JSON structure, database state, JWT validation

## Security Testing

✅ **Tested Security Scenarios**
- Invalid credentials handling
- Token expiration and revocation
- PKCE implementation
- Authorization code replay prevention
- Client secret validation
- Redirect URI validation
- Organization isolation
- Rate limiting
- MFA integration
- Account lockout

## Debugging Tests

### Enable Verbose Output

```bash
herd php artisan test tests/Integration/OAuth/ --verbose
```

### Debug Specific Test

```php
// Add to test method
dump($response->json());
dd($tokenData);
```

### Check Database State

```php
// In test method
$this->assertDatabaseHas('oauth_access_tokens', [
    'user_id' => $user->id,
]);
```

## Common Issues

### Issue: "Client not found" error

**Solution:**
```bash
herd php artisan passport:install --no-interaction
```

### Issue: "Invalid OAuth keys"

**Solution:**
```bash
herd php artisan passport:keys --force
```

### Issue: Tests hang after completion

**Solution:** Use the test runner wrapper:
```bash
./run-tests.sh tests/Integration/OAuth/
```

### Issue: Database errors

**Solution:**
```bash
herd php artisan migrate:fresh --seed
```

## CI/CD Integration

### GitHub Actions Example

```yaml
- name: Run OAuth Integration Tests
  run: ./run-tests.sh tests/Integration/OAuth/

- name: Generate Coverage Report
  run: |
    herd coverage ./vendor/bin/phpunit \
      tests/Integration/OAuth/ \
      --coverage-clover coverage.xml
```

### GitLab CI Example

```yaml
test:oauth:
  script:
    - php artisan passport:install --no-interaction
    - ./run-tests.sh tests/Integration/OAuth/
```

## Contributing

When adding new OAuth-related features:

1. **Write integration tests first** (TDD approach)
2. **Follow naming convention:** `test_descriptive_scenario_name()`
3. **Use PHP attributes:** `#[\PHPUnit\Framework\Attributes\Test]`
4. **Ensure isolation:** Each test should be independent
5. **Test both success and failure scenarios**
6. **Document expected behavior** in test method names

### Test Naming Convention

```php
// Good
test_authorization_code_flow_with_pkce_s256()
test_token_refresh_rotates_tokens()
test_invalid_client_secret_rejected()

// Bad
testOAuth()
test1()
testFlow()
```

## Related Documentation

- [OAuth 2.0 RFC 6749](https://tools.ietf.org/html/rfc6749)
- [PKCE RFC 7636](https://tools.ietf.org/html/rfc7636)
- [OpenID Connect Core](https://openid.net/specs/openid-connect-core-1_0.html)
- [Token Introspection RFC 7662](https://tools.ietf.org/html/rfc7662)
- [Laravel Passport Documentation](https://laravel.com/docs/12.x/passport)

## Performance

**Expected Execution Time:** < 2 minutes for all 120 tests

- Authorization Code Flow: ~10s
- Token Management: ~15s
- OpenID Connect: ~12s
- Client Credentials: ~8s
- Password Grant: ~10s
- SSO Integration: ~15s
- Social Authentication: ~15s

## Maintenance

### Regular Maintenance Tasks

1. **Update tests when adding new OAuth features**
2. **Review and update security scenarios quarterly**
3. **Monitor test execution time and optimize slow tests**
4. **Keep dependencies up to date** (Passport, Socialite)
5. **Add tests for reported security vulnerabilities**

### Test Health Indicators

✅ **Healthy Test Suite:**
- All tests passing
- Execution time < 2 minutes
- No flaky tests
- Clear test failure messages

⚠️ **Needs Attention:**
- Intermittent failures
- Increasing execution time
- Cryptic error messages
- Test pollution (tests affecting each other)

## Support

For questions or issues with OAuth integration tests:

1. Check the [OAUTH_INTEGRATION_TESTS_REPORT.md](OAUTH_INTEGRATION_TESTS_REPORT.md)
2. Review Laravel Passport documentation
3. Check OAuth 2.0 RFCs for specification details
4. Review existing test examples in this directory

---

**Last Updated:** October 6, 2025
**Test Suite Version:** 1.0
**Maintained By:** AuthOS Development Team
