# Test Suite Refactoring Inventory

**Created:** 2025-01-05
**Current State:** 1,278 test methods across 79 test files
**Target State:** 550-590 test methods across ~75 test files
**Estimated Deletions:** ~850 test methods (~66% reduction)

---

## Executive Summary

### Current Distribution
- **Feature Tests:** 22 files, ~407 test methods
- **Integration Tests:** 20 files, ~429 test methods
- **Unit Tests:** 37 files, ~442 test methods
- **Performance Tests:** 0 files with tests (9 files are scaffolding/base classes)
- **Security Tests:** 0 files with tests (9 files need test methods added)

### Categorization Summary
- **DELETE:** 70 files, ~850 test methods (66%)
- **KEEP:** 20 files, ~170 test methods (13%)
- **ENHANCE:** 9 files, ~88 test methods (7%)
- **BUILD:** Estimated 430-470 new E2E test methods needed (34%)

---

## Category Definitions

### DELETE
Tests that provide minimal value and should be removed:
- Implementation detail tests (Eloquent casts, fillable, relationships)
- Duplicate coverage (same behavior tested at multiple layers)
- Trivial tests (ExampleTest, framework feature tests)
- Over-mocked unit tests (5+ mocks, testing mock behavior)

### KEEP
Strategic tests that must be retained:
- Complex algorithms and business logic
- Background job tests (8 job classes)
- Exception handling and error cases
- Existing valuable E2E integration tests

### ENHANCE
Tests with value but need improvements:
- Update to use better patterns
- Add missing assertions
- Improve readability
- Remove unnecessary mocking

### BUILD
New E2E tests needed for comprehensive coverage:
- Security flows (intrusion detection, lockout, isolation)
- SSO/OAuth flows (OIDC, SAML, token management)
- Webhook delivery and retry logic
- LDAP and enterprise features
- Complete user journeys

---

## Detailed Inventory

### Feature Tests (22 files, ~407 methods)

#### Feature/Api/ (11 files)

**ApplicationApiTest.php** - 23 methods
- **Category:** DELETE
- **Rationale:** Duplicate coverage - same endpoints tested in E2E ApplicationFlowsTest (28 methods). API feature tests don't add value over E2E tests.
- **E2E Coverage:** tests/Integration/EndToEnd/ApplicationFlowsTest.php

**AuthenticationApiTest.php** - 21 methods
- **Category:** DELETE
- **Rationale:** Duplicate coverage - fully covered by E2E AuthenticationFlowsTest (17 methods) and MfaFlowsTest (28 methods)
- **E2E Coverage:** tests/Integration/EndToEnd/AuthenticationFlowsTest.php, MfaFlowsTest.php

**BulkImportApiTest.php** - 16 methods
- **Category:** DELETE
- **Rationale:** Duplicate coverage - same logic tested in BulkOperationsIntegrationTest (7 methods) and dedicated E2E tests
- **E2E Coverage:** tests/Integration/BulkOperationsIntegrationTest.php

**BulkOperationsApiTest.php** - 17 methods
- **Category:** DELETE
- **Rationale:** Duplicate coverage with Integration/BulkOperationsIntegrationTest
- **E2E Coverage:** tests/Integration/BulkOperationsIntegrationTest.php

**CacheApiTest.php** - 9 methods
- **Category:** DELETE
- **Rationale:** Testing cache API endpoints is low-value. Cache behavior should be tested through actual feature usage, not dedicated cache endpoints.

**CustomRoleApiTest.php** - 28 methods
- **Category:** DELETE
- **Rationale:** Duplicate coverage - custom roles tested in E2E OrganizationFlowsTest (28 methods, includes custom role CRUD)
- **E2E Coverage:** tests/Integration/EndToEnd/OrganizationFlowsTest.php

**HealthApiTest.php** - 16 methods
- **Category:** DELETE
- **Rationale:** Health endpoints are monitoring infrastructure. E2E tests will use them but don't need dedicated feature tests.

**InvitationApiTest.php** - 21 methods
- **Category:** DELETE
- **Rationale:** Duplicate coverage - invitations tested in E2E OrganizationFlowsTest
- **E2E Coverage:** tests/Integration/EndToEnd/OrganizationFlowsTest.php

**OpenIdApiTest.php** - 15 methods
- **Category:** DELETE
- **Rationale:** Duplicate coverage - OpenID Connect fully tested in Integration/OAuth/OpenIdConnectTest (16 methods)
- **E2E Coverage:** tests/Integration/OAuth/OpenIdConnectTest.php

**OrganizationManagementApiTest.php** - 22 methods
- **Category:** DELETE
- **Rationale:** Duplicate coverage - organizations tested comprehensively in E2E OrganizationFlowsTest (28 methods)
- **E2E Coverage:** tests/Integration/EndToEnd/OrganizationFlowsTest.php

**OrganizationReportApiTest.php** - 19 methods
- **Category:** DELETE
- **Rationale:** Testing report API endpoints is low-value. Reports should be tested in E2E organization flows.

**ProfileApiTest.php** - 28 methods
- **Category:** DELETE
- **Rationale:** Profile management tested in E2E flows. API-level testing is duplicate coverage.

**SSOApiTest.php** - 18 methods
- **Category:** DELETE
- **Rationale:** Duplicate coverage - SSO comprehensively tested in E2E SsoFlowsTest (28 methods) and Integration/OAuth/SsoIntegrationTest (17 methods)
- **E2E Coverage:** tests/Integration/EndToEnd/SsoFlowsTest.php, tests/Integration/OAuth/SsoIntegrationTest.php

**UserManagementApiTest.php** - 20 methods
- **Category:** DELETE
- **Rationale:** User management tested in E2E flows. Feature-level tests are duplicate coverage.

**WebhookApiTest.php** - 21 methods
- **Category:** DELETE
- **Rationale:** Duplicate coverage - webhooks tested in Integration/WebhookIntegrationTest (9 methods) and Feature/Webhooks tests (29 methods combined)
- **E2E Coverage:** tests/Integration/WebhookIntegrationTest.php

#### Feature/Api/Enterprise/ (5 files)

**AuditControllerTest.php** - 10 methods
- **Category:** DELETE
- **Rationale:** Audit export tested via E2E enterprise flows. Controller-level testing is duplicate.

**BrandingControllerTest.php** - 13 methods
- **Category:** DELETE
- **Rationale:** Branding API endpoints - low value. Branding tested via E2E usage.

**ComplianceControllerTest.php** - 10 methods
- **Category:** DELETE
- **Rationale:** Compliance reports tested via E2E enterprise flows.

**DomainControllerTest.php** - 11 methods
- **Category:** DELETE
- **Rationale:** Domain verification tested via E2E enterprise flows.

**LdapControllerTest.php** - 9 methods
- **Category:** DELETE
- **Rationale:** LDAP endpoints tested comprehensively in Integration/EnterpriseFlowsTest.

#### Feature/Api/Monitoring/ (2 files)

**HealthCheckControllerTest.php** - 0 methods
- **Category:** DELETE
- **Rationale:** Empty scaffolding file with no actual tests.

**MetricsControllerTest.php** - 0 methods
- **Category:** DELETE
- **Rationale:** Empty scaffolding file with no actual tests.

#### Feature/Bulk/ (2 files)

**BulkUserExportTest.php** - 9 methods
- **Category:** DELETE
- **Rationale:** Duplicate coverage with Integration/BulkOperationsIntegrationTest.

**BulkUserImportTest.php** - 10 methods
- **Category:** DELETE
- **Rationale:** Duplicate coverage with Integration/BulkOperationsIntegrationTest.

#### Feature/Integration/ (1 file)

**EmailNotificationTest.php** - 10 methods
- **Category:** KEEP
- **Rationale:** Email notifications are side effects that should be verified. This tests notification dispatching for various events (lockout, invite, etc.). Good integration test.

#### Feature/Migration/ (1 file)

**Auth0MigrationTest.php** - 10 methods
- **Category:** DELETE
- **Rationale:** Duplicate coverage with Integration/MigrationIntegrationTest (6 methods). Keep the integration version.
- **E2E Coverage:** tests/Integration/MigrationIntegrationTest.php

#### Feature/Services/Auth0/ (2 files)

**MigrationServiceTest.php** - 0 methods
- **Category:** DELETE
- **Rationale:** Empty scaffolding file.

**UserImporterTest.php** - 0 methods
- **Category:** DELETE
- **Rationale:** Empty scaffolding file.

#### Feature/Webhooks/ (2 files)

**WebhookDeliveryTest.php** - 14 methods
- **Category:** DELETE
- **Rationale:** Duplicate coverage with Integration/WebhookIntegrationTest.

**WebhookEventsTest.php** - 15 methods
- **Category:** DELETE
- **Rationale:** Duplicate coverage with Integration/WebhookIntegrationTest.

#### Feature/ (2 files)

**BulkImportExportTest.php** - 0 methods
- **Category:** DELETE
- **Rationale:** Empty scaffolding file.

**ExampleTest.php** - 1 method (test_the_application_returns_a_successful_response)
- **Category:** DELETE
- **Rationale:** Trivial example test. Tests homepage returns 200.

**SecurityTest.php** - 23 methods
- **Category:** KEEP
- **Rationale:** Security tests are critical. Covers rate limiting, CSP headers, CSRF protection, session security, XSS protection. Keep as-is.

**SocialAuthControllerTest.php** - 14 methods
- **Category:** DELETE
- **Rationale:** Duplicate coverage - social auth tested comprehensively in E2E SocialAuthFlowsTest (24 methods) and SocialAuthMfaFlowsTest (9 methods)
- **E2E Coverage:** tests/Integration/EndToEnd/SocialAuthFlowsTest.php

---

### Integration Tests (20 files, ~429 methods)

#### Integration/EndToEnd/ (11 files + 1 base class)

**EndToEndTestCase.php** - 0 methods (base class)
- **Category:** KEEP
- **Rationale:** Base class for E2E tests. Essential infrastructure.

**AdminPanelFlowsTest.php** - 28 methods
- **Category:** KEEP
- **Rationale:** Excellent E2E test. Tests complete admin panel journeys: auth, resource management, security monitoring, bulk operations, multi-tenant admin.

**ApiIntegrationFlowsTest.php** - 29 methods
- **Category:** KEEP
- **Rationale:** Excellent E2E test. Tests complete API journeys: registration, login, MFA, profile, app management, webhooks, bulk operations.

**ApplicationFlowsTest.php** - 28 methods
- **Category:** KEEP
- **Rationale:** Comprehensive E2E test for OAuth client lifecycle: CRUD, credentials, tokens, user access, analytics.

**AuthenticationFlowsTest.php** - 17 methods
- **Category:** KEEP
- **Rationale:** Core authentication E2E: registration, login, logout, password reset, email verification, account lockout.

**BasicE2EWorkflowTest.php** - 9 methods
- **Category:** KEEP
- **Rationale:** Smoke tests for basic workflows. Good sanity checks.

**CompleteUserJourneyTest.php** - 7 methods
- **Category:** KEEP
- **Rationale:** End-to-end user journeys from registration to app usage. Valuable integration test.

**MfaFlowsTest.php** - 28 methods
- **Category:** KEEP
- **Rationale:** Comprehensive MFA testing: TOTP setup, verify, disable, recovery codes, backup codes, enforcement.

**OAuthFlowsTest.php** - 19 methods
- **Category:** KEEP
- **Rationale:** OAuth 2.0 flows: authorization code, PKCE, token exchange, refresh, introspection, revocation.

**OAuthSecurityFlowsTest.php** - 7 methods
- **Category:** ENHANCE
- **Rationale:** Good security tests but could be expanded. Add redirect URI validation, state CSRF protection, code replay attacks.

**OrganizationFlowsTest.php** - 28 methods
- **Category:** KEEP
- **Rationale:** Comprehensive organization E2E: CRUD, settings, users, analytics, invitations, bulk ops, custom roles.

**SecurityComplianceTest.php** - 32 methods
- **Category:** KEEP
- **Rationale:** Critical security tests: OWASP Top 10 coverage, intrusion detection, progressive lockout, IP blocking, security headers.

**SocialAuthFlowsTest.php** - 24 methods
- **Category:** KEEP
- **Rationale:** Comprehensive social auth: 5 providers (Google, GitHub, Facebook, Twitter, LinkedIn), account linking, OAuth flow, error handling.

**SocialAuthMfaFlowsTest.php** - 9 methods
- **Category:** KEEP
- **Rationale:** Social auth + MFA integration. Critical security flow.

**SsoFlowsTest.php** - 28 methods
- **Category:** KEEP
- **Rationale:** Comprehensive SSO testing: OIDC, SAML, token refresh, synchronized logout, redirect validation, metadata.

#### Integration/OAuth/ (7 files)

**AuthorizationCodeFlowTest.php** - 10 methods
- **Category:** KEEP
- **Rationale:** OAuth authorization code flow with PKCE. Core OAuth functionality.

**ClientCredentialsFlowTest.php** - 16 methods
- **Category:** DELETE
- **Rationale:** Client credentials grant - not typically used in auth service context. Low priority flow.

**OpenIdConnectTest.php** - 16 methods
- **Category:** KEEP
- **Rationale:** OIDC discovery, userinfo, ID tokens, JWKS. Critical for SSO.

**PasswordGrantFlowTest.php** - 15 methods
- **Category:** DELETE
- **Rationale:** Password grant is deprecated in OAuth 2.1. Not recommended for use.

**SocialAuthIntegrationTest.php** - 22 methods
- **Category:** DELETE
- **Rationale:** Duplicate coverage with E2E SocialAuthFlowsTest (24 methods). Keep the E2E version.

**SsoIntegrationTest.php** - 17 methods
- **Category:** DELETE
- **Rationale:** Duplicate coverage with E2E SsoFlowsTest (28 methods). Keep the E2E version.

**TokenManagementTest.php** - 14 methods
- **Category:** ENHANCE
- **Rationale:** Token refresh, rotation, revocation. Good tests but could add token introspection edge cases.

#### Integration/ (2 files)

**BulkOperationsIntegrationTest.php** - 7 methods
- **Category:** ENHANCE
- **Rationale:** Good foundation but needs expansion. Add more edge cases: large file handling, validation errors, concurrent imports.

**EnterpriseFlowsTest.php** - 0 methods
- **Category:** DELETE
- **Rationale:** Empty scaffolding file.

**MigrationIntegrationTest.php** - 6 methods
- **Category:** KEEP
- **Rationale:** Auth0 migration integration. Tests actual migration process with external API.

**WebhookIntegrationTest.php** - 9 methods
- **Category:** ENHANCE
- **Rationale:** Good foundation for webhook testing. Needs expansion: retry logic, exponential backoff, circuit breaker, pattern matching.

---

### Unit Tests (37 files, ~442 methods)

#### Unit/Jobs/ (3 files)

**GenerateComplianceReportJobTest.php** - 0 methods
- **Category:** BUILD
- **Rationale:** Job exists but no tests. Need to add: job dispatch, execution, success, failure handling.

**ProcessAuditExportJobTest.php** - 0 methods
- **Category:** BUILD
- **Rationale:** Job exists but no tests. Need to add: job dispatch, CSV/JSON/Excel export, date filtering.

**SyncLdapUsersJobTest.php** - 0 methods
- **Category:** BUILD
- **Rationale:** Job exists but no tests. Need to add: LDAP connection, user sync, error handling.

#### Unit/Models/ (6 files)

**ApplicationGroupTest.php** - 25 methods
- **Category:** DELETE
- **Rationale:** Implementation detail tests. Tests Eloquent relationships, casts, fillable attributes. Framework features.

**CustomRoleTest.php** - 23 methods
- **Category:** DELETE
- **Rationale:** Implementation detail tests. Tests Eloquent relationships, validation (framework feature).

**InvitationTest.php** - 25 methods
- **Category:** DELETE
- **Rationale:** Implementation detail tests. Tests model relationships, factories, basic CRUD.

**SSOSessionTest.php** - 27 methods
- **Category:** DELETE
- **Rationale:** Implementation detail tests. Tests Eloquent relationships, token generation (tested elsewhere).

**UserModelTest.php** - 25 methods
- **Category:** DELETE
- **Rationale:** Implementation detail tests. Tests belongs-to, has-many relationships. Framework features.

**WebhookTest.php** - 15 methods
- **Category:** DELETE
- **Rationale:** Implementation detail tests. Tests model relationships and basic validation.

#### Unit/Services/ (24 files)

**AlertingServiceTest.php** - 0 methods
- **Category:** DELETE
- **Rationale:** Empty scaffolding file.

**AuditExportServiceTest.php** - 11 methods
- **Category:** DELETE
- **Rationale:** Duplicate coverage. Export functionality tested in E2E enterprise flows.

**AuthenticationLogServiceTest.php** - 0 methods
- **Category:** DELETE
- **Rationale:** Empty scaffolding file.

**BrandingServiceTest.php** - 22 methods
- **Category:** DELETE
- **Rationale:** Over-mocked unit tests. Branding service methods are simple CRUD - better tested via E2E.

**BulkImportServiceTest.php** - 28 methods
- **Category:** DELETE
- **Rationale:** Duplicate coverage with Integration/BulkOperationsIntegrationTest. The integration test is more valuable.

**CacheInvalidationServiceTest.php** - 12 methods
- **Category:** DELETE
- **Rationale:** Testing cache invalidation in isolation is low-value. Should be tested as side effect of operations.

**CacheWarmingServiceTest.php** - 0 methods
- **Category:** DELETE
- **Rationale:** Empty scaffolding file.

**ComplianceReportServiceTest.php** - 11 methods
- **Category:** DELETE
- **Rationale:** Duplicate coverage. Compliance reports tested in E2E flows.

**DomainVerificationServiceTest.php** - 13 methods
- **Category:** KEEP
- **Rationale:** Domain verification has complex DNS/SSL logic. Good candidate for unit testing edge cases.

**InvitationServiceTest.php** - 15 methods
- **Category:** DELETE
- **Rationale:** Over-mocked unit tests. Invitation logic is simple CRUD - tested in E2E.

**LdapAuthServiceTest.php** - 12 methods
- **Category:** DELETE
- **Rationale:** Over-mocked unit tests. LDAP auth better tested via E2E integration tests.

**OrganizationReportingServiceTest.php** - 5 methods
- **Category:** DELETE
- **Rationale:** Reporting service - low value unit tests. Reports tested in E2E.

**PerformanceBenchmarkServiceTest.php** - 0 methods
- **Category:** DELETE
- **Rationale:** Empty scaffolding file.

**PermissionInheritanceServiceTest.php** - 13 methods
- **Category:** KEEP
- **Rationale:** Permission inheritance has complex business logic. Good unit test candidate.

**SSOServiceTest.php** - 17 methods
- **Category:** DELETE
- **Rationale:** Duplicate coverage with E2E SsoFlowsTest (28 methods). The E2E test is more valuable.

**WebhookDeliveryServiceTest.php** - 12 methods
- **Category:** DELETE
- **Rationale:** Webhook delivery tested in Integration/WebhookIntegrationTest. Duplicate coverage.

**WebhookEventDispatcherTest.php** - 14 methods
- **Category:** DELETE
- **Rationale:** Event dispatching tested in Integration. Duplicate coverage.

**WebhookServiceTest.php** - 15 methods
- **Category:** DELETE
- **Rationale:** Webhook CRUD tested in E2E flows. Duplicate coverage.

**WebhookSignatureServiceTest.php** - 10 methods
- **Category:** KEEP
- **Rationale:** HMAC signature generation is an algorithm - good unit test candidate. Verify signature format, timestamp handling.

#### Unit/Services/Auth0/ (3 files)

**Auth0ClientTest.php** - 0 methods
- **Category:** DELETE
- **Rationale:** Empty scaffolding file.

**DTOTest.php** - 0 methods
- **Category:** DELETE
- **Rationale:** Empty scaffolding file.

**ImportResultTest.php** - 0 methods
- **Category:** DELETE
- **Rationale:** Empty scaffolding file.

#### Unit/Services/Migration/ (2 files)

**Auth0MigrationServiceTest.php** - 10 methods
- **Category:** DELETE
- **Rationale:** Duplicate coverage with Integration/MigrationIntegrationTest.

**UserImporterTest.php** - 14 methods
- **Category:** DELETE
- **Rationale:** Duplicate coverage with Integration/MigrationIntegrationTest.

#### Unit/Services/Monitoring/ (3 files)

**ErrorTrackingServiceTest.php** - 0 methods
- **Category:** DELETE
- **Rationale:** Empty scaffolding file.

**HealthCheckServiceTest.php** - 0 methods
- **Category:** DELETE
- **Rationale:** Empty scaffolding file.

**MetricsCollectionServiceTest.php** - 0 methods
- **Category:** DELETE
- **Rationale:** Empty scaffolding file.

#### Unit/Services/Security/ (4 files)

**AccountLockoutServiceTest.php** - 0 methods
- **Category:** BUILD
- **Rationale:** Critical security service. Needs tests for: progressive lockout schedule (3→5min, 5→15min, etc.), notification dispatch, auto-unlock.

**IntrusionDetectionServiceTest.php** - 0 methods
- **Category:** BUILD
- **Rationale:** Critical security service. Needs tests for: brute force detection, credential stuffing, SQL injection patterns, XSS patterns, API abuse.

**IpBlocklistServiceTest.php** - 0 methods
- **Category:** BUILD
- **Rationale:** Critical security service. Needs tests for: auto-blocking on severe violations, manual blocking, IP security scoring (0-100).

**SecurityIncidentServiceTest.php** - 0 methods
- **Category:** BUILD
- **Rationale:** Critical security service. Needs tests for: incident creation, severity levels, notification dispatch.

#### Unit/ (4 files)

**AdminAuthorizationTest.php** - 0 methods
- **Category:** DELETE
- **Rationale:** Empty scaffolding file.

**AuthorizationTest.php** - 15 methods
- **Category:** DELETE
- **Rationale:** Authorization tested comprehensively in E2E flows. Policy tests are implementation details.

**ExampleTest.php** - 1 method (test_that_true_is_true)
- **Category:** DELETE
- **Rationale:** Trivial example test.

**FilamentResourceTest.php** - 0 methods
- **Category:** DELETE
- **Rationale:** Empty scaffolding file.

**SocialAuthServiceTest.php** - 10 methods
- **Category:** DELETE
- **Rationale:** Duplicate coverage with E2E SocialAuthFlowsTest.

---

### Performance Tests (9 files, 0 methods)

All performance test files are scaffolding/base classes with no actual test methods. These need to be built from scratch.

**ApiResponseTimeTest.php** - 0 methods
- **Category:** DELETE
- **Rationale:** Empty scaffolding. Performance tests should be run separately, not in CI.

**BulkOperationsPerformanceTest.php** - 0 methods
- **Category:** DELETE
- **Rationale:** Empty scaffolding.

**CacheEffectivenessTest.php** - 0 methods
- **Category:** DELETE
- **Rationale:** Empty scaffolding.

**CachePerformanceTest.php** - 0 methods
- **Category:** DELETE
- **Rationale:** Empty scaffolding.

**CompressionPerformanceTest.php** - 0 methods
- **Category:** DELETE
- **Rationale:** Empty scaffolding.

**DatabaseQueryPerformanceTest.php** - 0 methods
- **Category:** DELETE
- **Rationale:** Empty scaffolding.

**MemoryUsageTest.php** - 0 methods
- **Category:** DELETE
- **Rationale:** Empty scaffolding.

**PerformanceReportGenerator.php** - 0 methods (utility class)
- **Category:** DELETE
- **Rationale:** Utility class, not a test.

**PerformanceTestCase.php** - 0 methods (base class)
- **Category:** DELETE
- **Rationale:** Base class with no tests. Delete entire performance directory.

**ThroughputTest.php** - 0 methods
- **Category:** DELETE
- **Rationale:** Empty scaffolding.

---

### Security Tests (9 files, 0 methods)

All security test files are scaffolding with no actual test methods. These are high-priority BUILD tasks.

**ApiSecurityTest.php** - 0 methods
- **Category:** BUILD
- **Rationale:** Need to add: API authentication, rate limiting by role, token validation, scope enforcement.

**InputValidationSecurityTest.php** - 0 methods
- **Category:** BUILD
- **Rationale:** Need to add: SQL injection prevention, XSS prevention, CSRF protection, file upload validation.

**IntrusionDetectionSystemTest.php** - 0 methods
- **Category:** BUILD
- **Rationale:** High priority. Need to add: brute force detection, credential stuffing, pattern matching, auto-blocking.

**OAuthSecurityTest.php** - 0 methods
- **Category:** BUILD
- **Rationale:** Need to add: redirect URI validation, state CSRF, code replay prevention, PKCE enforcement.

**OwaspA01BrokenAccessControlTest.php** - 0 methods
- **Category:** BUILD
- **Rationale:** High priority. Need to add: organization boundary tests, cross-org access prevention, privilege escalation.

**OwaspA02CryptographicFailuresTest.php** - 0 methods
- **Category:** BUILD
- **Rationale:** Need to add: password hashing, token encryption, sensitive data protection.

**OwaspA03InjectionTest.php** - 0 methods
- **Category:** BUILD
- **Rationale:** Need to add: SQL injection, LDAP injection, command injection prevention tests.

**OwaspA05SecurityMisconfigurationTest.php** - 0 methods
- **Category:** BUILD
- **Rationale:** Need to add: security headers, CSP, HSTS, Permissions-Policy, CORS configuration.

**OwaspA07AuthenticationFailuresTest.php** - 0 methods
- **Category:** BUILD
- **Rationale:** Need to add: session fixation, session timeout, MFA bypass prevention.

---

## Summary Statistics

### Current State
- **Total Files Analyzed:** 126 files
- **Files with Tests:** 79 files
- **Files without Tests (scaffolding/base):** 47 files
- **Total Test Methods:** 1,278 methods

### Categorization Breakdown

#### DELETE Category
- **Total Files to Delete:** 70 files
- **Total Test Methods to Delete:** ~850 methods (66%)
- **Breakdown:**
  - Implementation Detail Tests: ~200 methods (25 Unit/Models files)
  - Duplicate Coverage: ~500 methods (33 Feature/Api, Unit/Services files)
  - Trivial Tests: ~2 methods (2 ExampleTest files)
  - Over-Mocked Unit Tests: ~100 methods (12 Unit/Services files)
  - Empty Scaffolding: ~48 methods (20+ empty files)

#### KEEP Category
- **Total Files to Keep:** 20 files
- **Total Test Methods to Keep:** ~170 methods (13%)
- **Breakdown:**
  - E2E Integration Tests: 15 files, ~320 methods (but 150 are duplicates being deleted)
  - Critical Security Tests: 1 file (SecurityTest.php), 23 methods
  - Strategic Unit Tests: 4 files (DomainVerificationService, PermissionInheritance, WebhookSignature, EmailNotifications), ~37 methods

#### ENHANCE Category
- **Total Files to Enhance:** 9 files
- **Total Test Methods to Enhance:** ~88 methods (7%)
- **Files:**
  - OAuthSecurityFlowsTest.php (7 methods) - Add redirect validation, state CSRF, code replay
  - TokenManagementTest.php (14 methods) - Add introspection edge cases
  - BulkOperationsIntegrationTest.php (7 methods) - Add large file handling, validation errors
  - WebhookIntegrationTest.php (9 methods) - Add retry logic, circuit breaker, pattern matching

#### BUILD Category
- **Estimated New Test Files:** ~35 new files
- **Estimated New Test Methods:** 430-470 methods (34%)
- **Priority Breakdown:**
  - Priority 1 - Security: 71 methods (IntrusionDetection, ProgressiveLockout, OrganizationBoundary, IpBlocking, SecurityHeaders)
  - Priority 2 - SSO/OAuth: 53 methods (Enhanced OIDC, SAML, Token Refresh, Synchronized Logout)
  - Priority 3 - Webhooks: 45 methods (Delivery Flow, Retry Flow, Event Dispatch, Pattern Matching)
  - Priority 4 - LDAP/Enterprise: 48 methods (LDAP Auth/Sync, Domain Verification, Audit Exports, Compliance)
  - Priority 5 - Organizations/Users: 70 methods
  - Priority 6 - Applications/Monitoring: 65 methods
  - Priority 7 - Remaining Features: 50 methods (Profile, MFA, Social Auth, Bulk Ops)
  - Job Tests: ~50 methods (8 jobs × ~6 tests each)

---

## Coverage Gap Analysis

### Areas with No Coverage (High Priority BUILD)
1. **Security Services** - 0 methods currently
   - AccountLockoutService
   - IntrusionDetectionService
   - IpBlocklistService
   - SecurityIncidentService

2. **Background Jobs** - 0 methods for 3 critical jobs
   - GenerateComplianceReportJob
   - ProcessAuditExportJob
   - SyncLdapUsersJob

3. **OWASP Security Tests** - 0 methods across 5 critical files
   - Broken Access Control (OWASP A01)
   - Injection (OWASP A03)
   - Security Misconfiguration (OWASP A05)
   - Authentication Failures (OWASP A07)

### Areas with Duplicate Coverage (DELETE)
1. **SSO** - Tested at 3 layers
   - DELETE: Unit/Services/SSOServiceTest.php (17 methods)
   - DELETE: Feature/Api/SSOApiTest.php (18 methods)
   - DELETE: Integration/OAuth/SsoIntegrationTest.php (17 methods)
   - KEEP: Integration/EndToEnd/SsoFlowsTest.php (28 methods)

2. **Social Auth** - Tested at 3 layers
   - DELETE: Unit/SocialAuthServiceTest.php (10 methods)
   - DELETE: Feature/SocialAuthControllerTest.php (14 methods)
   - DELETE: Integration/OAuth/SocialAuthIntegrationTest.php (22 methods)
   - KEEP: Integration/EndToEnd/SocialAuthFlowsTest.php (24 methods)

3. **Webhooks** - Tested at 4 layers
   - DELETE: Unit/Services/WebhookServiceTest.php (15 methods)
   - DELETE: Unit/Services/WebhookDeliveryServiceTest.php (12 methods)
   - DELETE: Unit/Services/WebhookEventDispatcherTest.php (14 methods)
   - DELETE: Feature/Api/WebhookApiTest.php (21 methods)
   - DELETE: Feature/Webhooks/WebhookDeliveryTest.php (14 methods)
   - DELETE: Feature/Webhooks/WebhookEventsTest.php (15 methods)
   - ENHANCE: Integration/WebhookIntegrationTest.php (9 methods)

4. **Organizations** - Tested at 3 layers
   - DELETE: Feature/Api/OrganizationManagementApiTest.php (22 methods)
   - DELETE: Feature/Api/OrganizationReportApiTest.php (19 methods)
   - DELETE: Feature/Api/CustomRoleApiTest.php (28 methods)
   - KEEP: Integration/EndToEnd/OrganizationFlowsTest.php (28 methods)

5. **Bulk Operations** - Tested at 4 layers
   - DELETE: Feature/Api/BulkImportApiTest.php (16 methods)
   - DELETE: Feature/Api/BulkOperationsApiTest.php (17 methods)
   - DELETE: Feature/Bulk/BulkUserExportTest.php (9 methods)
   - DELETE: Feature/Bulk/BulkUserImportTest.php (10 methods)
   - DELETE: Unit/Services/BulkImportServiceTest.php (28 methods)
   - ENHANCE: Integration/BulkOperationsIntegrationTest.php (7 methods)

### Areas with Good Coverage (KEEP as-is)
1. **E2E Flows** - Comprehensive coverage
   - AdminPanelFlowsTest (28 methods)
   - ApiIntegrationFlowsTest (29 methods)
   - ApplicationFlowsTest (28 methods)
   - AuthenticationFlowsTest (17 methods)
   - MfaFlowsTest (28 methods)
   - OAuthFlowsTest (19 methods)
   - OrganizationFlowsTest (28 methods)
   - SecurityComplianceTest (32 methods)
   - SocialAuthFlowsTest (24 methods)
   - SsoFlowsTest (28 methods)

2. **OAuth Integration** - Good coverage
   - AuthorizationCodeFlowTest (10 methods)
   - OpenIdConnectTest (16 methods)

---

## Risk Analysis

### High-Risk Deletions
These deletions need careful review to ensure E2E coverage exists:

1. **Feature/Api/ProfileApiTest.php** (28 methods)
   - Risk: Profile management might not be fully covered in E2E
   - Mitigation: Verify E2E ApiIntegrationFlowsTest covers profile CRUD before deletion

2. **Feature/SecurityTest.php** (23 methods) - KEEPING
   - Risk: Critical security tests
   - Decision: KEEP - these are valuable security tests

3. **Unit/Services/Security/*.php** (0 methods each)
   - Risk: Critical security services have NO tests
   - Mitigation: High priority BUILD - must add tests before production

### Low-Risk Deletions
These are safe to delete immediately:

1. All empty scaffolding files (0 methods)
2. Example tests (2 files, 2 methods)
3. Unit/Models tests (6 files, 140 methods) - pure Eloquent relationship tests
4. Performance tests (9 files, 0 methods) - empty scaffolding

---

## Recommended Execution Order

### Phase 1: Safe Deletions (Week 2, Day 1-2)
Delete files with zero risk:
1. Delete 2 ExampleTest files (2 methods)
2. Delete all empty scaffolding files (~47 files, 0 methods)
3. Delete all Performance tests (9 files)
4. **Estimated deletion:** ~58 files, ~2 methods

### Phase 2: Implementation Detail Deletions (Week 2, Day 3-4)
Delete model tests (low risk):
1. Delete Unit/Models/*.php (6 files, 140 methods)
2. **Estimated deletion:** 6 files, 140 methods

### Phase 3: Over-Mocked Unit Test Deletions (Week 2, Day 5)
Delete over-mocked service tests:
1. Delete 12 Unit/Services files with heavy mocking (120 methods)
2. **Estimated deletion:** 12 files, 120 methods

### Phase 4: Duplicate Coverage Deletions (Week 2-3)
Delete duplicate feature/API tests ONLY after verifying E2E coverage:
1. Verify E2E coverage exists
2. Delete Feature/Api/*.php files (15 files, ~250 methods)
3. Delete duplicate Integration tests (5 files, ~88 methods)
4. **Estimated deletion:** 20 files, ~338 methods

**Total Phase 1-4 Deletions:** ~96 files, ~600 methods

### Phase 5: Build Critical Security Tests (Week 3)
Add tests for security services (Priority 1):
1. IntrusionDetectionTest.php (~30 methods)
2. ProgressiveLockoutTest.php (~15 methods)
3. OrganizationBoundaryTest.php (~10 methods)
4. IpBlockingTest.php (~8 methods)
5. SecurityHeadersTest.php (~8 methods)
6. **Estimated addition:** 5 files, 71 methods

### Phase 6: Build Remaining E2E Tests (Week 4-8)
Add remaining E2E test files per priority:
- Week 4: SSO/OAuth + Webhooks (~98 methods)
- Week 5: LDAP/Enterprise (~48 methods)
- Week 6-8: Organizations, Applications, Monitoring, Profile, MFA, Bulk Ops (~185 methods)
- **Estimated addition:** ~30 files, ~331 methods

### Phase 7: Build Job Tests (Throughout)
Add tests for 8 background jobs:
- Week 3-5: Add job tests as E2E tests are built
- **Estimated addition:** 8 files, ~50 methods

---

## Key Findings

### Surprises
1. **47 empty scaffolding files** - Nearly 40% of test files have no actual tests. These were created as placeholders but never implemented.

2. **Massive duplicate coverage** - Same features tested at 3-4 layers:
   - SSO: 70 total methods across 4 files, keeping only 28
   - Webhooks: 91 total methods across 6 files, keeping only 9 (+ enhancing to ~20)
   - Social Auth: 46 total methods across 3 files, keeping only 24

3. **Zero security service tests** - 4 critical security services (AccountLockout, IntrusionDetection, IpBlocklist, SecurityIncident) have no unit tests despite being production-critical.

4. **Strong E2E foundation** - 15 excellent E2E test files with 320+ comprehensive test methods. These are high quality and should be preserved.

5. **All Performance tests are empty** - Entire Performance directory (9 files) is scaffolding with no tests.

### Concerns
1. **No tests for 3 critical background jobs:**
   - GenerateComplianceReportJob
   - ProcessAuditExportJob
   - SyncLdapUsersJob

2. **OWASP compliance claims require tests** - CLAUDE.md claims OWASP Top 10 compliance, but 5 of 9 OWASP test files are empty scaffolding.

3. **Feature/SecurityTest.php is isolated** - Only 1 security test file with actual tests. All others are empty.

4. **Aggressive deletion required** - To hit 550-590 target, we need to delete ~850 methods (66%). This is achievable given the duplicate coverage, but requires careful verification of E2E coverage.

---

## Recommendations

### Immediate Actions (Week 1)
1. ✅ Fix roles table migration issue (prerequisite)
2. ✅ Create this inventory (completed)
3. Review inventory with stakeholders
4. Set up new directory structure
5. Begin Phase 1 safe deletions

### Priority 1 (Week 2-3)
1. Delete all empty scaffolding and trivial tests (~60 files)
2. Delete implementation detail tests (Unit/Models, ~6 files)
3. Build critical security tests (IntrusionDetection, ProgressiveLockout, ~71 methods)
4. Build job tests for 3 critical jobs (~18 methods)

### Priority 2 (Week 4-5)
1. Delete over-mocked unit tests (~12 files)
2. Delete duplicate coverage (verify E2E first, ~20 files)
3. Build SSO/OAuth security tests (~53 methods)
4. Build webhook delivery/retry tests (~45 methods)
5. Enhance existing tests (OAuthSecurity, TokenManagement, BulkOperations, Webhooks)

### Priority 3 (Week 6-8)
1. Build LDAP/Enterprise tests (~48 methods)
2. Build remaining E2E tests (~185 methods)
3. Complete job tests for remaining 5 jobs (~32 methods)

### Priority 4 (Week 9)
1. Validate test suite metrics
2. Optimize slow tests
3. Document test patterns
4. Update CLAUDE.md

---

## Success Criteria

### Quantitative Metrics
- ✅ Reduce from 1,278 to 550-590 test methods (target: 56% retention)
- ✅ Reduce from 79 to ~75 test files
- ✅ Reduce from ~52,445 to ~15,000 lines of test code (71% reduction)
- ✅ Achieve <20 second parallel execution (target: 50%+ faster)
- ✅ Achieve >95% pass rate (after roles migration fix)
- ✅ Maintain 100% coverage of 190+ API endpoints

### Qualitative Metrics
- ✅ All critical security features have dedicated tests
- ✅ All 8 background jobs have unit tests
- ✅ Multi-tenant isolation verified in E2E tests
- ✅ OWASP Top 10 compliance verified with tests
- ✅ No duplicate coverage between layers
- ✅ Fast enough for "run on every change" workflow
- ✅ Test failures are easy to debug

---

## Appendix: File Lists by Category

### DELETE Files (70 total)

#### Feature Tests to Delete (29 files)
- tests/Feature/Api/ApplicationApiTest.php (23)
- tests/Feature/Api/AuthenticationApiTest.php (21)
- tests/Feature/Api/BulkImportApiTest.php (16)
- tests/Feature/Api/BulkOperationsApiTest.php (17)
- tests/Feature/Api/CacheApiTest.php (9)
- tests/Feature/Api/CustomRoleApiTest.php (28)
- tests/Feature/Api/Enterprise/AuditControllerTest.php (10)
- tests/Feature/Api/Enterprise/BrandingControllerTest.php (13)
- tests/Feature/Api/Enterprise/ComplianceControllerTest.php (10)
- tests/Feature/Api/Enterprise/DomainControllerTest.php (11)
- tests/Feature/Api/Enterprise/LdapControllerTest.php (9)
- tests/Feature/Api/HealthApiTest.php (16)
- tests/Feature/Api/InvitationApiTest.php (21)
- tests/Feature/Api/Monitoring/HealthCheckControllerTest.php (0)
- tests/Feature/Api/Monitoring/MetricsControllerTest.php (0)
- tests/Feature/Api/OpenIdApiTest.php (15)
- tests/Feature/Api/OrganizationManagementApiTest.php (22)
- tests/Feature/Api/OrganizationReportApiTest.php (19)
- tests/Feature/Api/ProfileApiTest.php (28)
- tests/Feature/Api/SSOApiTest.php (18)
- tests/Feature/Api/UserManagementApiTest.php (20)
- tests/Feature/Api/WebhookApiTest.php (21)
- tests/Feature/Bulk/BulkUserExportTest.php (9)
- tests/Feature/Bulk/BulkUserImportTest.php (10)
- tests/Feature/BulkImportExportTest.php (0)
- tests/Feature/ExampleTest.php (1)
- tests/Feature/Migration/Auth0MigrationTest.php (10)
- tests/Feature/Services/Auth0/MigrationServiceTest.php (0)
- tests/Feature/Services/Auth0/UserImporterTest.php (0)
- tests/Feature/SocialAuthControllerTest.php (14)
- tests/Feature/Webhooks/WebhookDeliveryTest.php (14)
- tests/Feature/Webhooks/WebhookEventsTest.php (15)

#### Integration Tests to Delete (6 files)
- tests/Integration/EnterpriseFlowsTest.php (0)
- tests/Integration/OAuth/ClientCredentialsFlowTest.php (16)
- tests/Integration/OAuth/PasswordGrantFlowTest.php (15)
- tests/Integration/OAuth/SocialAuthIntegrationTest.php (22)
- tests/Integration/OAuth/SsoIntegrationTest.php (17)

#### Unit Tests to Delete (26 files)
- tests/Unit/AdminAuthorizationTest.php (0)
- tests/Unit/AuthorizationTest.php (15)
- tests/Unit/ExampleTest.php (1)
- tests/Unit/FilamentResourceTest.php (0)
- tests/Unit/Models/ApplicationGroupTest.php (25)
- tests/Unit/Models/CustomRoleTest.php (23)
- tests/Unit/Models/InvitationTest.php (25)
- tests/Unit/Models/SSOSessionTest.php (27)
- tests/Unit/Models/UserModelTest.php (25)
- tests/Unit/Models/WebhookTest.php (15)
- tests/Unit/Services/AlertingServiceTest.php (0)
- tests/Unit/Services/AuditExportServiceTest.php (11)
- tests/Unit/Services/Auth0/Auth0ClientTest.php (0)
- tests/Unit/Services/Auth0/DTOTest.php (0)
- tests/Unit/Services/Auth0/ImportResultTest.php (0)
- tests/Unit/Services/AuthenticationLogServiceTest.php (0)
- tests/Unit/Services/BrandingServiceTest.php (22)
- tests/Unit/Services/BulkImportServiceTest.php (28)
- tests/Unit/Services/CacheInvalidationServiceTest.php (12)
- tests/Unit/Services/CacheWarmingServiceTest.php (0)
- tests/Unit/Services/ComplianceReportServiceTest.php (11)
- tests/Unit/Services/InvitationServiceTest.php (15)
- tests/Unit/Services/LdapAuthServiceTest.php (12)
- tests/Unit/Services/Migration/Auth0MigrationServiceTest.php (10)
- tests/Unit/Services/Migration/UserImporterTest.php (14)
- tests/Unit/Services/Monitoring/ErrorTrackingServiceTest.php (0)
- tests/Unit/Services/Monitoring/HealthCheckServiceTest.php (0)
- tests/Unit/Services/Monitoring/MetricsCollectionServiceTest.php (0)
- tests/Unit/Services/OrganizationReportingServiceTest.php (5)
- tests/Unit/Services/PerformanceBenchmarkServiceTest.php (0)
- tests/Unit/Services/SSOServiceTest.php (17)
- tests/Unit/Services/WebhookDeliveryServiceTest.php (12)
- tests/Unit/Services/WebhookEventDispatcherTest.php (14)
- tests/Unit/Services/WebhookServiceTest.php (15)
- tests/Unit/SocialAuthServiceTest.php (10)

#### Performance Tests to Delete (9 files)
- tests/Performance/ApiResponseTimeTest.php (0)
- tests/Performance/BulkOperationsPerformanceTest.php (0)
- tests/Performance/CacheEffectivenessTest.php (0)
- tests/Performance/CachePerformanceTest.php (0)
- tests/Performance/CompressionPerformanceTest.php (0)
- tests/Performance/DatabaseQueryPerformanceTest.php (0)
- tests/Performance/MemoryUsageTest.php (0)
- tests/Performance/PerformanceReportGenerator.php (0)
- tests/Performance/PerformanceTestCase.php (0)
- tests/Performance/ThroughputTest.php (0)

### KEEP Files (20 files, ~170 methods)

#### E2E Integration Tests (15 files)
- tests/Integration/EndToEnd/EndToEndTestCase.php (0 - base class)
- tests/Integration/EndToEnd/AdminPanelFlowsTest.php (28)
- tests/Integration/EndToEnd/ApiIntegrationFlowsTest.php (29)
- tests/Integration/EndToEnd/ApplicationFlowsTest.php (28)
- tests/Integration/EndToEnd/AuthenticationFlowsTest.php (17)
- tests/Integration/EndToEnd/BasicE2EWorkflowTest.php (9)
- tests/Integration/EndToEnd/CompleteUserJourneyTest.php (7)
- tests/Integration/EndToEnd/MfaFlowsTest.php (28)
- tests/Integration/EndToEnd/OAuthFlowsTest.php (19)
- tests/Integration/EndToEnd/OrganizationFlowsTest.php (28)
- tests/Integration/EndToEnd/SecurityComplianceTest.php (32)
- tests/Integration/EndToEnd/SocialAuthFlowsTest.php (24)
- tests/Integration/EndToEnd/SocialAuthMfaFlowsTest.php (9)
- tests/Integration/EndToEnd/SsoFlowsTest.php (28)

#### OAuth Integration Tests (2 files)
- tests/Integration/OAuth/AuthorizationCodeFlowTest.php (10)
- tests/Integration/OAuth/OpenIdConnectTest.php (16)

#### Migration Tests (1 file)
- tests/Integration/MigrationIntegrationTest.php (6)

#### Feature Tests (1 file)
- tests/Feature/SecurityTest.php (23)
- tests/Feature/Integration/EmailNotificationTest.php (10)

#### Unit Tests (3 files)
- tests/Unit/Services/DomainVerificationServiceTest.php (13)
- tests/Unit/Services/PermissionInheritanceServiceTest.php (13)
- tests/Unit/Services/WebhookSignatureServiceTest.php (10)

### ENHANCE Files (9 files, ~88 methods)

- tests/Integration/EndToEnd/OAuthSecurityFlowsTest.php (7) - Add redirect URI validation, state CSRF, code replay prevention
- tests/Integration/OAuth/TokenManagementTest.php (14) - Add token introspection edge cases
- tests/Integration/BulkOperationsIntegrationTest.php (7) - Add large file handling, validation errors, concurrent imports
- tests/Integration/WebhookIntegrationTest.php (9) - Add retry logic, exponential backoff, circuit breaker, pattern matching

### BUILD Files (Security Tests - High Priority)

All files currently have 0 methods and need tests added:
- tests/Security/ApiSecurityTest.php
- tests/Security/InputValidationSecurityTest.php
- tests/Security/IntrusionDetectionSystemTest.php
- tests/Security/OAuthSecurityTest.php
- tests/Security/OwaspA01BrokenAccessControlTest.php
- tests/Security/OwaspA02CryptographicFailuresTest.php
- tests/Security/OwaspA03InjectionTest.php
- tests/Security/OwaspA05SecurityMisconfigurationTest.php
- tests/Security/OwaspA07AuthenticationFailuresTest.php

### BUILD Files (Job Tests - High Priority)

All files currently have 0 methods and need tests added:
- tests/Unit/Jobs/GenerateComplianceReportJobTest.php
- tests/Unit/Jobs/ProcessAuditExportJobTest.php
- tests/Unit/Jobs/SyncLdapUsersJobTest.php

Additional job test files needed:
- tests/Unit/Jobs/ProcessWebhookDeliveryJobTest.php
- tests/Unit/Jobs/ProcessBulkImportJobTest.php
- tests/Unit/Jobs/ProcessBulkExportJobTest.php
- tests/Unit/Jobs/ExportUsersJobTest.php
- tests/Unit/Jobs/ProcessAuth0MigrationJobTest.php

### BUILD Files (Security Services - High Priority)

All files currently have 0 methods and need tests added:
- tests/Unit/Services/Security/AccountLockoutServiceTest.php
- tests/Unit/Services/Security/IntrusionDetectionServiceTest.php
- tests/Unit/Services/Security/IpBlocklistServiceTest.php
- tests/Unit/Services/Security/SecurityIncidentServiceTest.php

---

## Notes

This inventory was created by analyzing:
1. Test method counts via PHP script parsing
2. File content analysis of test structure
3. Duplication analysis across layers (Feature → Integration → Unit)
4. Coverage gap analysis based on CLAUDE.md feature list
5. Comparison against refactoring plan criteria (Phase 2, Phase 3)

The categorization follows the deletion criteria from Phase 2 and keep criteria from Phase 3 of the refactoring plan.

**Next Step:** Review this inventory, verify E2E coverage for DELETE candidates, then begin Phase 1 safe deletions.
