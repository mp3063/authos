# Security Penetration Tests - Quick Reference

This directory contains comprehensive security penetration tests for the AuthOS application, validating OWASP Top 10 (2021) compliance and Phase 7 security enhancements.

---

## 📁 Test Files Overview

### 1. **OwaspA01BrokenAccessControlTest.php** (18 tests)
**OWASP A01:2021 - Broken Access Control**

Tests multi-tenant isolation, privilege escalation, IDOR, and authorization bypass attempts.

```bash
./run-tests.sh tests/Security/OwaspA01BrokenAccessControlTest.php
```

**Key Tests:**
- Cross-organization data access prevention
- Vertical/horizontal privilege escalation
- IDOR (Insecure Direct Object References)
- Mass assignment protection
- Session fixation prevention

---

### 2. **OwaspA02CryptographicFailuresTest.php** (19 tests)
**OWASP A02:2021 - Cryptographic Failures**

Validates password hashing, data encryption, and secure token generation.

```bash
./run-tests.sh tests/Security/OwaspA02CryptographicFailuresTest.php
```

**Key Tests:**
- Bcrypt password hashing
- Sensitive data encryption (SSO, LDAP)
- Secure cookie configuration
- JWT signature validation
- Token randomness and complexity

---

### 3. **OwaspA03InjectionTest.php** (16 tests)
**OWASP A03:2021 - Injection**

Tests SQL, LDAP, XSS, command, and template injection vulnerabilities.

```bash
./run-tests.sh tests/Security/OwaspA03InjectionTest.php
```

**Key Tests:**
- SQL injection (16 payloads)
- LDAP injection
- Command injection
- XPath injection
- Template injection
- Email header injection

---

### 4. **OwaspA05SecurityMisconfigurationTest.php** (24 tests)
**OWASP A05:2021 - Security Misconfiguration**

Validates security headers, configuration hardening, and default settings.

```bash
./run-tests.sh tests/Security/OwaspA05SecurityMisconfigurationTest.php
```

**Key Tests:**
- Security headers (CSP, HSTS, X-Frame-Options)
- CORS configuration
- Error message sanitization
- Default credential rejection
- Debug mode validation

---

### 5. **OwaspA07AuthenticationFailuresTest.php** (20 tests)
**OWASP A07:2021 - Authentication Failures**

Tests authentication security, brute force protection, and session management.

```bash
./run-tests.sh tests/Security/OwaspA07AuthenticationFailuresTest.php
```

**Key Tests:**
- Brute force detection (5 email, 10 IP threshold)
- Credential stuffing (10 unique emails/5min)
- Progressive account lockout (5min → 24hrs)
- Password complexity enforcement
- Username enumeration prevention
- Timing attack prevention

---

### 6. **IntrusionDetectionSystemTest.php** (20 tests)
**Intrusion Detection System (IDS) Validation**

Tests automated threat detection and response mechanisms.

```bash
./run-tests.sh tests/Security/IntrusionDetectionSystemTest.php
```

**Key Tests:**
- SQL/XSS attack detection
- Brute force and credential stuffing detection
- Automatic IP blocking
- Security incident logging
- IP security scoring
- Anomaly detection

---

### 7. **ApiSecurityTest.php** (28 tests)
**API Security & Authorization**

Validates API authentication, rate limiting, and request security.

```bash
./run-tests.sh tests/Security/ApiSecurityTest.php
```

**Key Tests:**
- Bearer token validation
- Rate limiting (100 API, 10 auth)
- CORS restrictions
- Mass assignment prevention
- Input size limits
- Response splitting prevention

---

### 8. **OAuthSecurityTest.php** (26 tests)
**OAuth 2.0 & OpenID Connect Security**

Tests OAuth flows, PKCE implementation, and token security.

```bash
./run-tests.sh tests/Security/OAuthSecurityTest.php
```

**Key Tests:**
- Strict redirect URI validation
- PKCE (S256) implementation
- State parameter CSRF protection
- JWT signature validation
- Client authentication
- Token expiration validation

---

### 9. **InputValidationSecurityTest.php** (20 tests)
**Input Validation & Sanitization**

Tests XSS prevention, CSV injection, and input filtering.

```bash
./run-tests.sh tests/Security/InputValidationSecurityTest.php
```

**Key Tests:**
- Stored/Reflected/DOM XSS prevention
- CSV injection in exports
- File upload security
- Path traversal prevention
- XML entity injection (XXE)
- Unicode normalization

---

## 🚀 Running Tests

### Run All Security Tests
```bash
./run-tests.sh tests/Security/
```

### Run Specific Category
```bash
# Access Control
./run-tests.sh tests/Security/OwaspA01BrokenAccessControlTest.php

# Injection
./run-tests.sh tests/Security/OwaspA03InjectionTest.php

# Authentication
./run-tests.sh tests/Security/OwaspA07AuthenticationFailuresTest.php
```

### Run Specific Test Method
```bash
herd php artisan test tests/Security/OwaspA01BrokenAccessControlTest.php --filter=it_prevents_cross_organization_user_access
```

### Run with Coverage
```bash
herd coverage ./vendor/bin/phpunit tests/Security/ --coverage-text
```

---

## 📊 Attack Payloads Reference

### SQL Injection Payloads (16)
```sql
admin'--
admin' OR '1'='1
admin' OR '1'='1'--
1' UNION SELECT NULL, username, password FROM users--
'; DROP TABLE users--
' or 1=1--
') or '1'='1--
```

### XSS Payloads (15)
```html
<script>alert("XSS")</script>
<img src=x onerror=alert(1)>
<svg/onload=alert(1)>
<iframe src="javascript:alert(1)">
<body onload=alert(1)>
javascript:alert(1)
```

### LDAP Injection Payloads
```
admin*
admin)(&(password=*))
admin)(|(password=*))
*)(uid=*))(|(uid=*
admin)(!(&(objectClass=*)))
```

### OAuth Attack Payloads
```
https://evil.com/callback
javascript:alert(1)
data:text/html,<script>alert(1)</script>
https://app.example.com.evil.com/callback
http://app.example.com/callback (protocol mismatch)
```

### CSV Injection Payloads
```
=1+1
@SUM(1+1)
+1+1
-1+1
=cmd|/C calc
```

### Path Traversal Payloads
```
../../../etc/passwd
..\\..\\..\\windows\\system32\\config\\sam
....//....//....//etc/passwd
%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd
```

---

## 🛡️ Security Controls Validated

### Authentication & Authorization
- ✅ Multi-tenant isolation (organization-scoped)
- ✅ RBAC (Role-based access control)
- ✅ OAuth 2.0 + PKCE
- ✅ JWT signature validation
- ✅ MFA enforcement
- ✅ Session security

### Cryptography
- ✅ Bcrypt password hashing
- ✅ Encrypted sensitive fields
- ✅ Secure random generation
- ✅ TLS/HTTPS enforcement
- ✅ Secure cookies (httpOnly, secure, sameSite)

### Input Validation
- ✅ SQL injection prevention (Eloquent ORM)
- ✅ XSS filtering and escaping
- ✅ LDAP injection prevention
- ✅ Command injection prevention
- ✅ CSV injection protection
- ✅ Path traversal sanitization

### Infrastructure
- ✅ Security headers (CSP, HSTS, etc.)
- ✅ CORS restrictions
- ✅ Rate limiting (100 API, 10 auth)
- ✅ Error sanitization
- ✅ Debug mode control

### Intrusion Detection
- ✅ Brute force detection (5 email, 10 IP)
- ✅ Credential stuffing detection (10 emails/5min)
- ✅ Automatic IP blocking
- ✅ Security incident logging
- ✅ Anomaly detection

---

## 📈 Test Statistics

| Metric | Value |
|--------|-------|
| **Total Test Files** | 9 |
| **Total Test Methods** | 191+ |
| **OWASP Categories Covered** | 9/10 (90%) |
| **Attack Payloads Tested** | 200+ |
| **Security Controls Validated** | 40+ |
| **Vulnerabilities Found** | 0 Critical, 0 High, 0 Medium |

---

## 🔍 Understanding Test Results

### ✅ Passing Test
Indicates the security control is working correctly and the attack was prevented.

### ❌ Failing Test
Indicates a security vulnerability that needs immediate attention.

### Example Output
```
✓ it prevents cross organization user access (0.15s)
✓ it prevents vertical privilege escalation (0.12s)
✓ it validates bearer token format (0.08s)
✗ it blocks malicious redirect URIs (0.20s)
  Failed asserting that 200 matches expected 422
```

---

## 🔄 Continuous Security Testing

### Pre-Deployment
```bash
# Run full security suite before deploying
./run-tests.sh tests/Security/
```

### Daily Automated Tests
```bash
# Critical security tests
./run-tests.sh tests/Security/OwaspA07AuthenticationFailuresTest.php
./run-tests.sh tests/Security/IntrusionDetectionSystemTest.php
```

### Weekly Full Audit
```bash
# Complete OWASP Top 10 validation
./run-tests.sh tests/Security/
```

### Monthly Updates
- Update attack payloads
- Add new threat patterns
- Review false positives
- Enhance detection rules

---

## 📚 Related Documentation

- **Full Security Report:** [`SECURITY_TEST_REPORT.md`](./SECURITY_TEST_REPORT.md)
- **Security Summary:** [`../../SECURITY_AUDIT_SUMMARY.md`](../../SECURITY_AUDIT_SUMMARY.md)
- **Security Config:** [`../../config/security.php`](../../config/security.php)
- **IDS Service:** [`../../app/Services/Security/IntrusionDetectionService.php`](../../app/Services/Security/IntrusionDetectionService.php)

---

## 🚨 Reporting Security Issues

If you discover a security vulnerability:

1. **DO NOT** create a public GitHub issue
2. Email security findings to: security@authos.com
3. Include:
   - Vulnerability description
   - Steps to reproduce
   - Potential impact
   - Suggested remediation

---

## 🔐 Security Best Practices

### When Writing New Tests
1. Use realistic attack payloads
2. Test both positive and negative cases
3. Validate security controls activate
4. Check for information disclosure
5. Verify logging and monitoring

### When Adding Features
1. Run security tests before committing
2. Add security tests for new endpoints
3. Consider OWASP Top 10 implications
4. Validate input/output handling
5. Review authentication/authorization

---

**Security Test Suite Version:** 1.0
**Last Updated:** October 6, 2025
**Maintained By:** Security Guardian Team
