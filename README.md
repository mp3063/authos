# AuthOS

<p align="center">
  <strong>Enterprise Authentication Service</strong><br>
  An Auth0/Okta alternative built with Laravel 13 and Filament 5
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Status-In%20Development-yellow" alt="In Development">
  <img src="https://img.shields.io/badge/PHP-8.4-blue" alt="PHP 8.4">
  <img src="https://img.shields.io/badge/Laravel-13-red" alt="Laravel 13">
  <img src="https://img.shields.io/badge/Filament-5-orange" alt="Filament 5">
  <img src="https://img.shields.io/badge/Tests-1680+-green" alt="1680+ Tests">
  <img src="https://img.shields.io/badge/Suite-passing-brightgreen" alt="Test suite passing">
  <img src="https://img.shields.io/badge/License-MIT-blue" alt="MIT License">
</p>

---

> **:warning: NOT PRODUCTION READY**: This application is currently **in active development** and should **not be used in production environments**. Core features are functional and the full test suite (1,680+ tests) passes. See the [Testing](#testing) section for details.

---

## Overview

AuthOS is an authentication and authorization service that provides:

- **OAuth 2.0 + PKCE** - Full RFC 6749 compliant authorization server
- **OpenID Connect** - Identity layer with discovery and JWKS endpoints
- **SAML 2.0** - Enterprise SSO with mandatory XML signature validation (IdP- and SP-initiated, single logout)
- **Multi-Factor Authentication** - TOTP with single-use recovery codes
- **Social Login** - Google, GitHub, Facebook, Twitter, LinkedIn
- **LDAP/Active Directory** - Enterprise directory integration
- **Multi-Tenant** - Organization-based isolation with custom branding
- **Webhooks** - 44 event types with retry logic and signatures

## Features

### Authentication
- Password-based authentication with progressive lockout
- Multi-factor authentication (TOTP)
- Social authentication (5 providers)
- Single Sign-On (OIDC, SAML 2.0)
- LDAP/Active Directory integration
- Session management with device tracking

### Authorization
- OAuth 2.0 authorization server (authorization code, client credentials, password, device code, refresh token)
- PKCE support (S256 + plain)
- Refresh token rotation and token revocation
- Scope-based permissions
- Role-based access control (RBAC)

### Enterprise Features
- Multi-tenant organizations
- Custom branding (logo, colors, CSS)
- Custom domains with DNS verification
- Webhook integrations (44 event types)
- Audit log exports (stored privately, downloadable only through the authorized API)
- Compliance reporting (SOC 2, ISO 27001, GDPR), including scheduled reports
- Bulk user import/export (CSV, Excel, JSON)
- Migration tools (Auth0, Okta)

### Security
- OWASP Top 10 (2021) compliant
- Intrusion detection (brute force, credential stuffing, SQL injection, XSS)
- Progressive account lockout
- Automatic IP blocking
- Enhanced security headers (CSP, HSTS, Permissions-Policy)
- Comprehensive audit trail

## Quick Start

### Requirements

- PHP 8.4+
- Composer 2.x
- PostgreSQL (recommended) or MySQL
- Node.js & npm
- [Laravel Herd](https://herd.laravel.com/) (recommended)

### Installation

```bash
# Clone the repository
git clone https://github.com/yourusername/authos.git
cd authos

# Install dependencies
composer install
npm install

# Configure environment
cp .env.example .env
php artisan key:generate

# Set up database
php artisan migrate --seed
php artisan passport:keys
php artisan passport:install

# Build frontend assets
npm run build
```

### Using Laravel Herd (Recommended)

```bash
# Link the project
herd link authos

# Start services
herd start

# Access the application
open https://authos.test
```

### Default Credentials

- **Admin Panel**: https://authos.test/admin
  - Email: `admin@authservice.com`
  - Password: `password`

- **API Base URL**: https://authos.test/api/v1

## Technology Stack

| Component | Technology |
|-----------|------------|
| Backend | PHP 8.4, Laravel 13 |
| Admin Panel | Filament 5, Livewire 4 |
| OAuth Server | Laravel Passport 13 |
| Social Auth | Laravel Socialite 5 |
| RBAC | Spatie Laravel Permission 8 (organization teams) |
| SAML Signatures | robrichards/xmlseclibs 3 |
| Database | PostgreSQL |
| Cache | Redis / Database |
| Testing | PHPUnit 13 + ParaTest |
| Frontend | Tailwind CSS 4, Vite 8 |

## API Documentation

### OAuth 2.0 Endpoints

| Endpoint | Description |
|----------|-------------|
| `GET /oauth/authorize` | Authorization endpoint |
| `POST /oauth/token` | Token endpoint |
| `POST /oauth/token/refresh` | Refresh tokens |
| `POST /oauth/device/code` | Device authorization (device code grant) |
| `POST /api/v1/auth/revoke` | Revoke tokens |

### OpenID Connect Endpoints

| Endpoint | Description |
|----------|-------------|
| `GET /api/.well-known/openid-configuration` | OIDC Discovery |
| `GET /api/v1/oauth/jwks` | JSON Web Key Set |
| `GET /api/v1/oauth/userinfo` | UserInfo |

### REST API

AuthOS provides 220+ API endpoints under `/api/v1` across these categories:

- **Authentication** - Login, register, MFA, social auth
- **Users** - CRUD, sessions, roles, applications
- **Organizations** - Multi-tenant management
- **Applications** - OAuth client management
- **Profile** - User settings and preferences
- **Webhooks** - Event subscriptions
- **SSO** - OIDC/SAML flows, sessions, SSO configurations, SAML certificates
- **Enterprise** - LDAP, branding, domains, audit, compliance

See [API Documentation](docs/api/) for complete details.

## Admin Panel

The Filament-powered admin panel provides:

### Resources (23)
- Users, Organizations, Organization Branding
- Applications, Application Groups
- Roles, Custom Roles, Permissions
- SSO Configurations, SSO Sessions
- Authentication Logs, Failed Login Attempts
- Security Incidents, Account Lockouts, IP Blocklist
- Webhooks, Webhook Events, Webhook Deliveries
- Audit Exports, Compliance Reports, Scheduled Compliance Reports
- Bulk Import Jobs, Migration Jobs

### Dashboard Widgets (13)
- System Health, Real-Time Metrics
- Auth Stats Overview, Login Activity Chart, User Activity
- OAuth Flow Monitor, Application Access Matrix
- Security Monitoring, Error Trends
- Webhook Activity Chart, Recent Authentication Logs
- Pending Invitations, Organization Overview

## Testing

AuthOS has **1,680+ tests** in ~140 test files (unit, feature and integration). The full suite passes; a handful of tests are skipped or marked incomplete. Tests run against in-memory SQLite and in parallel via ParaTest.

```bash
# Run all tests (parallel, with timeout protection)
./run-tests.sh

# Run a directory or a single file
herd php artisan test tests/Integration/SSO/
herd php artisan test tests/Integration/Security/IntrusionDetectionTest.php

# Run with coverage
herd composer test:coverage
```

### Integration Test Categories

| Directory | Covers |
|-----------|--------|
| `Security/` | Intrusion detection, progressive lockout, IP blocking, security headers, tenant boundaries |
| `SSO/` | OIDC and SAML flows, signature validation, single logout, SAML certificates, SSO configuration management |
| `OAuth/` | Authorization code + PKCE, client credentials, password grant, token refresh/management, OIDC |
| `Users/`, `Organizations/`, `Applications/` | CRUD, roles, invitations, user–application access, analytics and exports |
| `Profile/` | Profile, MFA (TOTP, recovery codes), social accounts |
| `Enterprise/` | LDAP, branding, domain verification, audit export, compliance reports |
| `Webhooks/`, `Jobs/`, `BulkOperations/` | Webhook delivery/retry, background jobs, bulk import/export |
| `Cache/`, `Monitoring/`, `Models/`, `Events/` | Caching, health/metrics, model lifecycle, event listener registration |
| `EndToEnd/` | Complete user journeys across auth, SSO, MFA, OAuth and the admin panel |

## Configuration

### Environment Variables

```bash
# Application
APP_NAME=AuthOS
APP_URL=https://authos.test

# Database
DB_CONNECTION=pgsql
DB_HOST=127.0.0.1
DB_DATABASE=authos
DB_USERNAME=postgres
DB_PASSWORD=secret

# OAuth (auto-generated by passport:install)
PASSPORT_PERSONAL_ACCESS_CLIENT_ID=
PASSPORT_PERSONAL_ACCESS_CLIENT_SECRET=

# Social Providers (optional)
GOOGLE_CLIENT_ID=
GOOGLE_CLIENT_SECRET=
GITHUB_CLIENT_ID=
GITHUB_CLIENT_SECRET=
# ... other providers

# Security
MFA_ISSUER="${APP_NAME}"
RATE_LIMIT_API=100
RATE_LIMIT_AUTH=10
```

## Documentation

Detailed documentation is available in the [docs/](docs/) directory:

- [API Reference](docs/api/) - API documentation
- [Architecture](docs/architecture/) - System design and patterns
- [Diagrams](docs/diagrams/) - Flow and architecture diagrams
- [Guides](docs/guides/) - How-to guides and tutorials
- [Operations](docs/operations/) - Deployment and operations

## Development

### Code Quality

```bash
# Run all quality checks
herd composer quality

# Individual checks
herd composer cs:fix          # Code style (Pint)
herd composer phpmd           # Mess detector (phpmd.xml ruleset)
herd composer security:check  # Dependency security audit
```

Static analysis (`composer analyse`) currently needs a `phpstan.neon` configuration before it can run.

### Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines on:

- Code standards
- Testing requirements
- Pull request process
- Commit message format

## Security

If you discover a security vulnerability, please report it privately to the maintainers rather than opening a public issue.

Security-relevant behavior worth knowing:

- Organization isolation is enforced by the `org.boundary` middleware and org-scoped lookups; cross-organization IDs generally return 404 (Super Admin is unscoped)
- SAML responses and logout requests must be signed by the configured IdP certificate; unsigned or unconfigured IdPs are rejected
- Disabling MFA requires the password plus a TOTP or recovery code
- Exports are written to the private disk and served only through authorized download endpoints

## License

AuthOS is open-source software licensed under the [MIT License](LICENSE).

---

<p align="center">
  Built with Laravel and Filament
</p>
