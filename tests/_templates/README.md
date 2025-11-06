# Test Templates & Documentation

This directory contains comprehensive test templates and documentation for Phase 7 of the test refactoring plan.

## Files Created

### Test Templates (tests/_templates/)

1. **E2EIntegrationTestTemplate.stub** (448 lines)
   - Complete end-to-end integration test template
   - Multi-step workflow testing
   - Side effect verification (database, cache, logs, notifications)
   - Multi-tenant isolation patterns
   - Authorization testing
   - Error handling examples

2. **UnitTestTemplate.stub** (96 lines)
   - Unit test template for services and business logic
   - Algorithm testing patterns
   - Edge case testing
   - Mocking patterns
   - Data transformation testing
   - Validation logic testing

3. **BackgroundJobTestTemplate.stub** (290 lines)
   - Background job testing patterns
   - Job dispatch and configuration testing
   - Successful execution verification
   - Failure handling and retry logic
   - External service mocking

4. **SecurityTestTemplate.stub** (378 lines)
   - Security-focused integration testing
   - Attack detection patterns (SQL injection, XSS, brute force)
   - Multi-tenant boundary testing
   - Progressive lockout testing
   - Intrusion detection patterns
   - Security incident verification

### Documentation (docs/)

1. **testing-patterns.md** (1,145 lines)
   - Comprehensive testing guide
   - Testing philosophy and principles
   - Common testing patterns with real examples
   - Helper method usage guide
   - Testing anti-patterns to avoid
   - Best practices checklist
   - Real-world examples from codebase

2. **test-quick-reference.md** (591 lines)
   - Quick command reference
   - Test execution commands (parallel, standard, by group)
   - Helper methods reference
   - Common assertions
   - Performance tips
   - Troubleshooting guide

## How to Use Templates

### Using E2EIntegrationTestTemplate.stub

Replace placeholders:
- `{{CATEGORY}}` - Test category (OAuth, Users, Organizations, etc.)
- `{{FEATURE_NAME}}` - Feature name (UserManagement, OAuthFlow, etc.)
- `{{FEATURE_SLUG}}` - Feature slug (user_management, oauth_flow, etc.)
- `{{MODEL_NAME}}` - Model class name (User, Application, etc.)
- `{{MODEL_VARIABLE}}` - Model variable name ($user, $application, etc.)
- `{{TEST_CLASS_NAME}}` - Test class name (UserManagementTest, etc.)
- `{{ENDPOINT}}` - API endpoint path (users, applications, etc.)
- `{{TABLE_NAME}}` - Database table name (users, applications, etc.)

Example:
```bash
cp tests/_templates/E2EIntegrationTestTemplate.stub tests/Integration/Users/UserProfileTest.php
# Replace placeholders manually or with sed
```

### Using UnitTestTemplate.stub

Replace placeholders:
- `{{SERVICE_NAME}}` - Service class name
- `{{SERVICE_SLUG}}` - Service slug for grouping
- `{{TEST_CLASS_NAME}}` - Test class name
- `{{MODEL_NAME}}` - Model class name
- `{{METHOD_NAME}}` - Method being tested
- `{{CALCULATION_METHOD}}` - Calculation method name
- `{{REPOSITORY_NAME}}` - Repository class name
- `{{EXTERNAL_SERVICE}}` - External service class name

### Using BackgroundJobTestTemplate.stub

Replace placeholders:
- `{{JOB_NAME}}` - Job class name
- `{{JOB_SLUG}}` - Job slug for grouping
- `{{TEST_CLASS_NAME}}` - Test class name
- `{{MODEL_NAME}}` - Model class name
- `{{SERVICE_NAME}}` - Service class name
- `{{QUEUE_NAME}}` - Queue name
- `{{TABLE_NAME}}` - Database table name

### Using SecurityTestTemplate.stub

Replace placeholders:
- `{{FEATURE_NAME}}` - Security feature name
- `{{TEST_CLASS_NAME}}` - Test class name
- `{{SECURITY_SERVICE}}` - Security service class name
- `{{ENDPOINT}}` - API endpoint path
- `{{MODEL_NAME}}` - Model class name

## Patterns Documented

### 1. Complete E2E Flow Testing
Testing entire user journeys from start to finish with multiple steps and side effect verification.

### 2. Multi-Tenant Isolation Testing
Ensuring users can only access their organization's data with proper boundary enforcement.

### 3. OAuth Authorization Flow Testing
Testing complete OAuth 2.0 flows with PKCE, including authorization, token exchange, and refresh.

### 4. Webhook Delivery and Retry Testing
Testing webhook event dispatch, delivery, failure handling, and exponential backoff retry logic.

### 5. Cache Invalidation Testing
Verifying that cache is properly invalidated when data changes.

### 6. Background Job Testing
Testing job dispatch, configuration, execution, and failure handling with mocked services.

### 7. Security Testing (Progressive Lockout)
Testing security features like progressive account lockout based on failed login attempts.

### 8. Side Effect Verification
Ensuring actions trigger expected side effects (database changes, audit logs, notifications, webhooks).

## Key Insights Discovered

### From Existing Tests

1. **IntegrationTestCase Structure**
   - Extends TestCase, adds integration-specific helpers
   - Uses RefreshDatabase for test isolation
   - Provides OAuth, PKCE, and authentication helpers
   - Includes security header assertions

2. **EndToEndTestCase Capabilities**
   - Comprehensive test environment setup
   - OAuth flow simulation helpers
   - Multi-organization scenario creation
   - Social auth mocking
   - Time travel for expiration testing

3. **Common Helper Methods**
   - `createUser()`, `createOrganization()`, `createOAuthApplication()`
   - `actingAsApiUser()`, `actingAsTestUser()`
   - `generatePkceChallenge()`, `performOAuthFlow()`
   - `assertAuthenticationLogged()`, `assertWebhookDeliveryCreated()`
   - `simulateFailedLoginAttempts()`, `setupMultiOrganizationScenario()`

4. **Testing Conventions**
   - PHP 8 attributes (#[Test]) used consistently
   - ARRANGE-ACT-ASSERT structure
   - Descriptive test method names
   - Inline comments for complex flows
   - Factory usage for test data

5. **Security Testing Patterns**
   - 5-tier progressive lockout (3→5min, 5→15min, 7→30min, 10→1hr, 15→24hr)
   - Multi-tenant boundary enforcement (404, not 403)
   - Security incident logging
   - Notification on lockout
   - Intrusion detection patterns

6. **Anti-Patterns Identified**
   - Over-mocking (test becomes mock setup)
   - Testing implementation details
   - Testing framework features
   - Brittle assertions (exact array matching)
   - Shared test state

## Test Execution Tips

### Fastest Execution
```bash
./fast-tests.sh  # Parallel execution, 4-10x faster
```

### Standard Execution
```bash
./run-tests.sh   # With timeout protection
```

### By Category
```bash
./run-tests.sh tests/Integration/OAuth/
./run-tests.sh tests/Unit/Services/
herd php artisan test --group=security
```

### Debugging
```bash
herd php artisan test --filter=test_name -vvv
herd php artisan test --stop-on-failure
```

## References

- Full patterns guide: `docs/testing-patterns.md`
- Quick reference: `docs/test-quick-reference.md`
- Example tests: `tests/Integration/EndToEnd/CompleteUserJourneyTest.php`
- Security example: `tests/Integration/Security/ProgressiveLockoutTest.php`
- OAuth example: `tests/Integration/OAuth/AuthorizationCodeFlowTest.php`
