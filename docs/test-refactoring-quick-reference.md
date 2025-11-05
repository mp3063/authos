# Test Refactoring Quick Reference

**Full Inventory:** See `docs/test-refactoring-inventory.md` (1,108 lines)
**Refactoring Plan:** See `.claude/test-refactoring-plan.md`

---

## At a Glance

```
Current:  1,278 test methods across 126 files
Target:     590 test methods across  75 files
Delete:     850 methods (66%) from 70 files
Keep:       170 methods (13%) from 20 files
Enhance:     37 methods (3%) from 4 files
Build:      470 methods (34%) in ~50 new files
```

---

## Top 5 Duplicate Coverage Examples

1. **Webhooks** - 6 layers → 1 enhanced
   - 91 methods → 20 methods (78% reduction)
   - DELETE 6 files, ENHANCE 1 file

2. **Organizations** - 4 layers → 1
   - 97 methods → 28 methods (71% reduction)
   - DELETE 3 Feature/Api files, KEEP 1 E2E file

3. **Bulk Operations** - 5 layers → 1 enhanced
   - 87 methods → 15 methods (83% reduction)
   - DELETE 5 files, ENHANCE 1 file

4. **SSO** - 4 layers → 1
   - 70 methods → 28 methods (60% reduction)
   - DELETE 3 files, KEEP 1 E2E file

5. **Social Auth** - 4 layers → 1
   - 70 methods → 24 methods (66% reduction)
   - DELETE 3 files, KEEP 1 E2E file

**Total Duplicate Savings:** 415 → 115 methods (72% reduction)

---

## Critical Gaps to Fill (HIGH PRIORITY)

### Security Services (0 tests currently)
- AccountLockoutService
- IntrusionDetectionService
- IpBlocklistService
- SecurityIncidentService

### Background Jobs (0 tests for 3 critical jobs)
- GenerateComplianceReportJob
- ProcessAuditExportJob
- SyncLdapUsersJob

### OWASP Security (5 files are empty scaffolding)
- Broken Access Control (A01)
- Injection (A03)
- Security Misconfiguration (A05)
- Authentication Failures (A07)

---

## Week 2 Execution Plan (DELETE Phase)

### Day 1-2: Safe Deletions (~60 files, 142 methods)
```bash
# DELETE empty scaffolding (47 files)
rm -rf tests/Performance/
rm tests/Feature/Api/Monitoring/*.php
rm tests/Unit/Services/Auth0/*.php
rm tests/Unit/Services/Monitoring/*.php
# ... (see full inventory for complete list)

# DELETE example tests (2 files)
rm tests/Feature/ExampleTest.php
rm tests/Unit/ExampleTest.php
```

### Day 3-4: Implementation Detail Deletions (6 files, 140 methods)
```bash
# DELETE Unit/Models tests
rm tests/Unit/Models/ApplicationGroupTest.php
rm tests/Unit/Models/CustomRoleTest.php
rm tests/Unit/Models/InvitationTest.php
rm tests/Unit/Models/SSOSessionTest.php
rm tests/Unit/Models/UserModelTest.php
rm tests/Unit/Models/WebhookTest.php
```

### Day 5: Over-Mocked Unit Tests (12 files, 120 methods)
```bash
# DELETE over-mocked service tests
rm tests/Unit/Services/BrandingServiceTest.php
rm tests/Unit/Services/CacheInvalidationServiceTest.php
rm tests/Unit/Services/InvitationServiceTest.php
rm tests/Unit/Services/LdapAuthServiceTest.php
# ... (see inventory for complete list)
```

### Week End: Duplicate Coverage (20 files, 338 methods)
```bash
# DELETE Feature/Api tests (verify E2E coverage first!)
rm tests/Feature/Api/ApplicationApiTest.php
rm tests/Feature/Api/AuthenticationApiTest.php
rm tests/Feature/Api/SSOApiTest.php
# ... (see inventory for complete list)

# DELETE duplicate Integration tests
rm tests/Integration/OAuth/SocialAuthIntegrationTest.php
rm tests/Integration/OAuth/SsoIntegrationTest.php
```

---

## Files to KEEP (20 files, ~170 methods)

### E2E Integration Tests (15 files) - KEEP ALL
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

### OAuth Integration Tests (2 files)
- tests/Integration/OAuth/AuthorizationCodeFlowTest.php (10)
- tests/Integration/OAuth/OpenIdConnectTest.php (16)

### Critical Security Tests (1 file)
- tests/Feature/SecurityTest.php (23)

### Strategic Unit Tests (4 files)
- tests/Unit/Services/DomainVerificationServiceTest.php (13)
- tests/Unit/Services/PermissionInheritanceServiceTest.php (13)
- tests/Unit/Services/WebhookSignatureServiceTest.php (10)
- tests/Feature/Integration/EmailNotificationTest.php (10)

---

## Files to ENHANCE (4 files)

1. **tests/Integration/EndToEnd/OAuthSecurityFlowsTest.php** (7 methods)
   - Add: Redirect URI validation tests
   - Add: State parameter CSRF protection tests
   - Add: Authorization code replay prevention tests

2. **tests/Integration/OAuth/TokenManagementTest.php** (14 methods)
   - Add: Token introspection edge cases
   - Add: Revoked token handling
   - Add: Expired token edge cases

3. **tests/Integration/BulkOperationsIntegrationTest.php** (7 methods)
   - Add: Large file handling (10k+ rows)
   - Add: Validation error scenarios
   - Add: Concurrent import handling

4. **tests/Integration/WebhookIntegrationTest.php** (9 methods)
   - Add: Retry logic with exponential backoff
   - Add: Circuit breaker (auto-disable after N failures)
   - Add: Pattern matching (wildcards, prefixes)

---

## Week 3+ BUILD Plan

### Week 3: Security Tests (71 methods)
- IntrusionDetectionTest.php (30 methods)
- ProgressiveLockoutTest.php (15 methods)
- OrganizationBoundaryTest.php (10 methods)
- IpBlockingTest.php (8 methods)
- SecurityHeadersTest.php (8 methods)

### Week 4: SSO/OAuth + Webhooks (98 methods)
- Enhanced OIDC flows (20 methods)
- SAML flows (15 methods)
- Token refresh/rotation (10 methods)
- Webhook delivery flow (15 methods)
- Webhook retry flow (12 methods)
- Webhook event dispatch (10 methods)
- Webhook pattern matching (8 methods)

### Week 5: LDAP + Enterprise (48 methods)
- LDAP auth & sync (20 methods)
- Domain verification (10 methods)
- Audit exports (8 methods)
- Compliance reports (10 methods)

### Week 6-8: Remaining E2E Tests (185 methods)
- Organizations & Users (70 methods)
- Applications & Monitoring (65 methods)
- Profile, MFA, Bulk Ops (50 methods)

### Throughout: Job Tests (50 methods)
- 8 job classes × ~6 tests each

---

## Key Metrics

### Reduction Targets
- Test methods: 1,278 → 590 (54% reduction)
- Test files: 126 → 75 (40% reduction)
- Lines of code: 52,445 → 15,000 (71% reduction)
- Execution time: 38s → <20s (50%+ faster)

### Deletion Breakdown
- Duplicate coverage: 415 methods (49% of deletions)
- Implementation details: 200 methods (24% of deletions)
- Over-mocked tests: 100 methods (12% of deletions)
- Empty scaffolding: 48 methods (6% of deletions)
- Trivial tests: 2 methods (<1% of deletions)

### Quality Targets
- Pass rate: 21% → >95%
- Coverage: Maintain 100% of 190+ API endpoints
- Confidence: Higher with fewer, better tests

---

## Risk Mitigation

### High-Risk Deletions (verify before deleting)
1. Feature/Api/ProfileApiTest.php (28 methods)
   - Verify: ApiIntegrationFlowsTest.php covers profile CRUD

2. Feature/Api/ApplicationApiTest.php (23 methods)
   - Verify: ApplicationFlowsTest.php covers all app management

### Safety Protocol
1. Never delete without understanding what it tests
2. Document deletion rationale in commit messages
3. Keep git history (can restore if needed)
4. Verify E2E coverage exists before deleting duplicates

---

## Next Steps

1. Review full inventory: `docs/test-refactoring-inventory.md`
2. Verify E2E coverage for high-risk deletions
3. Begin Phase 1 safe deletions (Week 2, Day 1-2)
4. Build critical security tests (Week 3)
5. Continue with systematic deletion and building per plan

---

**Last Updated:** 2025-01-05
**Status:** Ready for Week 2 execution
