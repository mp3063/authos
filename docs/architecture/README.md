# Architecture Documentation

> **Note**: AuthOS is currently in development with an 85% test pass rate. 8 test categories (Security, OAuth, SSO, Webhooks, Cache, Bulk Operations, Monitoring, Model Lifecycle) are at 100%.

This directory contains architectural documentation for AuthOS.

## Overview

AuthOS follows a modular, multi-tenant architecture built on Laravel 12 with Filament 4 for administration.

## Key Architecture Decisions

### Multi-Tenant Design
- Organization-based isolation
- Scoped data access through middleware
- Per-organization settings and branding

### Authentication Flow
- OAuth 2.0 + PKCE authorization server
- OpenID Connect identity layer
- SAML 2.0 for enterprise SSO
- Multi-factor authentication (TOTP)

### Event-Driven Security
- Real-time security event monitoring
- Automatic threat detection and response
- Progressive account lockout
- IP-based blocking

## Documentation Files

| File | Description |
|------|-------------|
| [event-driven-security.md](./event-driven-security.md) | Event-driven security architecture overview |
| [event-driven-security-implementation.md](./event-driven-security-implementation.md) | Implementation details for security events |

## Technology Stack

- **Backend**: Laravel 12, PHP 8.4
- **Admin Panel**: Filament 4
- **OAuth Server**: Laravel Passport 13
- **Database**: PostgreSQL
- **Cache**: Redis / Database
- **Queue**: Database driver

## Security Architecture

### OWASP Top 10 (2021) Compliance
- A01: Broken Access Control - Multi-tenant isolation
- A02: Cryptographic Failures - AES-256 encryption, secure tokens
- A03: Injection - Parameterized queries, input validation
- A04: Insecure Design - Defense in depth
- A05: Security Misconfiguration - Security headers (CSP, HSTS)
- A06: Vulnerable Components - Regular dependency updates
- A07: Authentication Failures - MFA, progressive lockout
- A08: Data Integrity Failures - HMAC signatures, audit logging
- A09: Logging Failures - Comprehensive audit trail
- A10: SSRF - URL validation, allowlisting

## API Architecture

### Endpoint Categories (206 total)
- Health Check (5)
- Authentication (14)
- OAuth & OIDC (3)
- User Management (17)
- Bulk Operations (10)
- Application Management (13)
- Profile Management (10)
- MFA (10)
- Organization Management (43)
- Invitations (3)
- SSO (19)
- Monitoring (15)
- Cache Management (3)
- Configuration (2)
- Enterprise (22)
- Webhooks (18)
- Version (1)

## Related Documentation

- [Security Documentation](../security/)
- [API Documentation](../api/)
- [Operations Documentation](../operations/)
