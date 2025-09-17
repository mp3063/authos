# End-to-End Testing Infrastructure

This directory contains the foundational infrastructure and examples for comprehensive end-to-end testing of the Laravel authentication service.

## Overview

The E2E testing infrastructure provides a robust foundation for testing complete user workflows, complex integration scenarios, and security-critical authentication flows. It extends the existing test infrastructure while providing specialized helpers for realistic testing scenarios.

## Architecture

### Base Class: `EndToEndTestCase`

The `EndToEndTestCase` class serves as the foundation for all E2E tests and provides:

- **Complete Test Environment Setup**: Realistic organizations, users, roles, and applications
- **OAuth Client Management**: Pre-configured OAuth clients for testing authorization flows
- **External Service Mocking**: Comprehensive mocking for social providers, email, and queues
- **Multi-Organization Support**: Tools for testing cross-tenant scenarios
- **Time Manipulation**: Helpers for testing token expiration and time-sensitive features
- **Audit Trail Testing**: Helpers for verifying security logs and audit trails
- **Performance Testing**: Tools for simulating high-load scenarios

### Key Features

#### 1. Realistic Test Data

```php
// Pre-configured test organizations
$this->defaultOrganization      // Standard security settings
$this->enterpriseOrganization   // High security (MFA required, IP whitelist)

// Pre-configured test users
$this->superAdmin              // Global access across all organizations
$this->organizationOwner       // Full organization management
$this->organizationAdmin       // User and application management
$this->regularUser            // Basic user access
```

#### 2. OAuth Testing Infrastructure

```php
// Pre-configured OAuth application and client
$this->oauthApplication        // Test application
$this->oauthClient            // Corresponding OAuth client

// Helper methods
$this->performOAuthFlow($user, $client, $scopes)
$this->createAuthorizationCode($user, $client, $scopes)
```

#### 3. Social Authentication Mocking

```php
// Mock successful social authentication
$user = $this->mockSuccessfulSocialAuth('google');

// Create social user with provider data
$user = $this->createSocialUser([], 'github');
```

#### 4. Time Manipulation for Token Testing

```php
// Test token expiration
$this->travelToFuture(60); // 60 minutes
$this->travelToFutureHours(24); // 24 hours
$this->returnToPresent();
```

#### 5. Multi-Organization Testing

```php
// Setup complete multi-org scenario
$organizations = $this->setupMultiOrganizationScenario();

// Test data isolation
$this->assertOrganizationDataIsolation($user, $organization);
```

## Example Test Classes

### 1. `CompleteUserJourneyTest`

Demonstrates testing complete user workflows:
- User registration and onboarding
- OAuth authorization flows
- Social authentication workflows
- Multi-organization data isolation
- Token expiration scenarios
- High-load testing
- Security audit trail verification

### 2. `OAuthSecurityFlowsTest`

Focuses on OAuth 2.0 security scenarios:
- PKCE (Proof Key for Code Exchange) flows
- Refresh token rotation
- Token introspection endpoint testing
- Scope-based access control
- Cross-organization security
- Protection against common attack vectors
- Rate limiting verification
- OpenID Connect discovery

### 3. `SocialAuthMfaFlowsTest`

Covers social authentication and MFA:
- Social provider registration flows
- MFA setup and verification
- Backup code management
- Social account linking
- Organization-specific provider restrictions
- MFA recovery flows
- Rate limiting on social endpoints

## Writing New E2E Tests

### Basic Structure

```php
<?php

namespace Tests\Integration\EndToEnd;

class YourE2ETest extends EndToEndTestCase
{
    public function test_your_complete_workflow(): void
    {
        // Use pre-configured test data
        $user = $this->actingAsTestUser('regular');

        // Test your workflow
        $response = $this->getJson('/api/v1/your-endpoint');

        // Assert using unified response format
        $this->assertUnifiedApiResponse($response, 200);

        // Verify audit logs
        $this->assertAuditLogExists($user, 'your_event');
    }
}
```

### Best Practices

1. **Use Pre-configured Data**: Leverage the existing test organizations, users, and applications rather than creating new ones unless specifically needed.

2. **Test Complete Workflows**: Focus on end-to-end scenarios rather than individual API endpoints.

3. **Verify Security**: Always check audit logs, data isolation, and security implications.

4. **Test Error Scenarios**: Include testing of failure cases and edge conditions.

5. **Use Unified Assertions**: Use `assertUnifiedApiResponse()` to verify consistent API response formats.

6. **Mock External Services**: Use the provided mocking infrastructure for social providers and external services.

### Common Patterns

#### Testing OAuth Flows

```php
public function test_oauth_authorization_flow(): void
{
    $user = $this->actingAsTestUser('regular');

    // Use helper to perform complete OAuth flow
    $tokens = $this->performOAuthFlow($user, $this->oauthClient, ['openid', 'profile']);

    // Test token usage
    $response = $this->getJson('/oauth/userinfo', [
        'Authorization' => 'Bearer ' . $tokens['access_token'],
    ]);

    $response->assertStatus(200);
}
```

#### Testing Social Authentication

```php
public function test_social_authentication(): void
{
    // Mock successful social auth
    $user = $this->mockSuccessfulSocialAuth('google');

    // Test the callback
    $response = $this->getJson('/api/v1/auth/social/google/callback');
    $this->assertUnifiedApiResponse($response, 200);

    // Verify audit log
    $this->assertAuditLogExists($user, 'social_login_success');
}
```

#### Testing Multi-Organization Scenarios

```php
public function test_organization_isolation(): void
{
    $organizations = $this->setupMultiOrganizationScenario();

    foreach ($organizations as $orgData) {
        $user = $orgData['users'][0];
        $organization = $orgData['organization'];

        $this->assertOrganizationDataIsolation($user, $organization);
    }
}
```

#### Testing Token Expiration

```php
public function test_token_expiration(): void
{
    $user = $this->actingAsTestUser('regular');
    $token = $user->createToken('Test', ['*'], now()->addMinutes(5));

    // Travel to future
    $this->travelToFuture(10);

    // Verify token is expired
    $response = $this->getJson('/api/v1/auth/user', [
        'Authorization' => 'Bearer ' . $token->accessToken,
    ]);
    $response->assertStatus(401);

    $this->returnToPresent();
}
```

## Running E2E Tests

### Run Basic Infrastructure Tests (Recommended)

```bash
# Test the core infrastructure
herd php artisan test tests/Integration/EndToEnd/BasicE2EWorkflowTest.php

# Test specific basic workflows
herd php artisan test tests/Integration/EndToEnd/BasicE2EWorkflowTest.php --filter=test_basic_user_authentication_workflow
herd php artisan test tests/Integration/EndToEnd/BasicE2EWorkflowTest.php --filter=test_preconfigured_test_data
```

### Run All E2E Tests (Some may need additional configuration)

```bash
herd php artisan test tests/Integration/EndToEnd/
```

### Run Specific Test Class

```bash
herd php artisan test tests/Integration/EndToEnd/CompleteUserJourneyTest.php
```

### Run with Coverage

```bash
herd coverage ./vendor/bin/phpunit tests/Integration/EndToEnd/
```

### Debug Mode

```bash
herd php artisan test tests/Integration/EndToEnd/ --stop-on-failure
```

## Configuration

### Test Environment Variables

The E2E tests automatically configure test-specific settings:

```php
// High rate limits for testing
Config::set('app.rate_limits.api', 1000);

// Test social provider configuration
Config::set('services.google.client_id', 'test_google_client_id');

// Debug mode for detailed errors
Config::set('app.debug', true);
```

### Customizing Test Environment

You can customize the test environment in your test classes:

```php
protected function setUp(): void
{
    parent::setUp();

    // Disable social providers for this test
    $this->socialProvidersEnabled = false;

    // Enable queue jobs for this test
    $this->queueJobsEnabled = true;
}
```

## Memory Optimization

The E2E infrastructure includes several memory optimizations:

- **Cached Seeding**: Expensive database seeding operations are cached
- **Selective Mocking**: External services are mocked only when needed
- **Garbage Collection**: Automatic cleanup between tests
- **Transaction Management**: Proper database transaction handling

## Security Considerations

The E2E tests include comprehensive security testing:

- **Data Isolation**: Multi-tenant security verification
- **OAuth Security**: PKCE, token rotation, introspection
- **Social Auth Security**: Provider validation, rate limiting
- **MFA Security**: TOTP validation, backup code management
- **Audit Logging**: Complete security event tracking

## Extending the Infrastructure

### Adding New Helper Methods

Add new helper methods to `EndToEndTestCase`:

```php
protected function createComplexScenario(): array
{
    // Your complex scenario setup
    return $scenarioData;
}
```

### Adding New Mock Services

```php
protected function setupYourServiceMocks(): void
{
    $this->mockYourService = Mockery::mock(YourService::class);
    $this->app->instance(YourService::class, $this->mockYourService);
}
```

### Custom Assertions

```php
protected function assertYourBusinessLogic($data): void
{
    // Your custom assertions
}
```

## Troubleshooting

### Common Issues

1. **Memory Exhaustion**: Use the memory optimization features and avoid creating too much test data
2. **Time Manipulation**: Always call `returnToPresent()` after time travel
3. **Mock Conflicts**: Ensure mocks are properly configured before test execution
4. **Database State**: Use the provided cleanup methods to ensure clean test state

### Debug Tips

1. **Enable Debug Mode**: Set `Config::set('app.debug', true)` for detailed error messages
2. **Check Audit Logs**: Use `AuthenticationLog` to verify security events
3. **Verify Test Data**: Use `dd()` to inspect the pre-configured test data
4. **Monitor Memory**: Use memory profiling if tests become slow

## Performance Considerations

- **Selective Testing**: Focus on critical paths rather than exhaustive coverage
- **Batch Operations**: Group related tests to minimize setup overhead
- **Mock External Calls**: Always mock external API calls and services
- **Database Optimization**: Use transactions and avoid unnecessary database hits

This E2E testing infrastructure provides a solid foundation for comprehensive testing of the authentication service's most critical workflows and security features.

## Current Status and Implementation Notes

### ✅ Working Infrastructure Components

The following components are fully functional and ready for use:

1. **Base Infrastructure (`EndToEndTestCase`)**:
   - Complete test environment setup with organizations, users, and roles
   - OAuth client and application management
   - External service mocking (social providers, email, queues)
   - Time manipulation for testing scenarios
   - Memory optimization and test cleanup

2. **Basic User Workflows (`BasicE2EWorkflowTest`)**:
   - User authentication and profile management
   - Pre-configured test data consistency
   - Time manipulation testing
   - High-load simulation
   - Authentication audit trail creation

3. **Helper Methods**:
   - `actingAsTestUser()` - Quick user authentication
   - `createSocialUser()` - Social provider user creation
   - `mockSuccessfulSocialAuth()` - Social authentication mocking
   - `assertValidApiResponse()` - Flexible response validation
   - `travelToFuture() / returnToPresent()` - Time manipulation

### ⚠️ Components Requiring Additional Configuration

Some advanced features require additional setup or configuration:

1. **OAuth Authorization Flows**:
   - Requires Laravel Passport authorization view configuration
   - May need additional service provider bindings
   - Complex PKCE flows need proper JWT token handling

2. **Multi-Tenant Data Isolation**:
   - Requires proper middleware configuration for organization filtering
   - May need additional permission setup for cross-organization access

3. **Social Authentication Endpoints**:
   - Requires proper social provider configuration in `.env`
   - Needs social authentication service implementation
   - Provider-specific callback handling may need setup

### 🛠️ Implementation Recommendations

1. **Start with Basic Tests**: Use `BasicE2EWorkflowTest` as your foundation and expand from there.

2. **Configure OAuth Gradually**: Add OAuth flows after ensuring basic authentication works.

3. **Implement Multi-Tenancy**: Ensure proper middleware and permission setup before testing cross-organization scenarios.

4. **Add Social Auth**: Configure social providers and implement service classes before testing social flows.

### 📋 Next Steps for Full Implementation

1. **OAuth Setup**:
   ```bash
   # Configure Laravel Passport views
   php artisan vendor:publish --tag=passport-views

   # Ensure proper authorization response bindings
   # Add to AppServiceProvider or dedicated service provider
   ```

2. **Multi-Tenant Middleware**:
   ```php
   // Ensure organization-scoped queries in middleware
   // Add organization context to all model queries
   ```

3. **Social Authentication**:
   ```bash
   # Configure social providers in .env
   GOOGLE_CLIENT_ID=your_client_id
   GOOGLE_CLIENT_SECRET=your_client_secret

   # Implement SocialAuthService with proper provider handling
   ```

This infrastructure provides a comprehensive foundation that can be extended as your authentication service evolves.