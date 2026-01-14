# AuthOS

<p align="center">
  <strong>Enterprise Authentication Service</strong><br>
  A production-ready Auth0/Okta alternative built with Laravel 12 and Filament 4
</p>

<p align="center">
  <img src="https://img.shields.io/badge/PHP-8.4-blue" alt="PHP 8.4">
  <img src="https://img.shields.io/badge/Laravel-12-red" alt="Laravel 12">
  <img src="https://img.shields.io/badge/Filament-4.0-orange" alt="Filament 4">
  <img src="https://img.shields.io/badge/Tests-475+-green" alt="475+ Tests">
  <img src="https://img.shields.io/badge/License-MIT-blue" alt="MIT License">
</p>

---

## Overview

AuthOS is an enterprise-grade authentication and authorization service that provides:

- **OAuth 2.0 + PKCE** - Full RFC 6749 compliant authorization server
- **OpenID Connect** - Identity layer with discovery and JWKS endpoints
- **SAML 2.0** - Enterprise SSO integration
- **Multi-Factor Authentication** - TOTP with recovery codes
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
- OAuth 2.0 authorization server (all grant types)
- PKCE support (S256 + plain)
- Token introspection (RFC 7662)
- Refresh token rotation
- Scope-based permissions
- Role-based access control (RBAC)

### Enterprise Features
- Multi-tenant organizations
- Custom branding (logo, colors, CSS)
- Custom domains with DNS verification
- Webhook integrations (44 event types)
- Audit logging and compliance reporting
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
| Backend | PHP 8.4, Laravel 12 |
| Admin Panel | Filament 4 |
| OAuth Server | Laravel Passport 13 |
| Social Auth | Laravel Socialite |
| RBAC | Spatie Laravel Permission |
| Database | PostgreSQL |
| Cache | Redis / Database |
| Testing | PHPUnit 11 |
| Frontend | Tailwind CSS 4 |

## API Documentation

### OAuth 2.0 Endpoints

| Endpoint | Description |
|----------|-------------|
| `GET /oauth/authorize` | Authorization endpoint |
| `POST /oauth/token` | Token endpoint |
| `POST /oauth/token/refresh` | Refresh tokens |
| `POST /oauth/revoke` | Revoke tokens |
| `POST /oauth/introspect` | Token introspection |

### Well-Known Endpoints

| Endpoint | Description |
|----------|-------------|
| `GET /.well-known/openid-configuration` | OIDC Discovery |
| `GET /.well-known/jwks.json` | JSON Web Key Set |

### REST API

AuthOS provides 154+ API endpoints across these categories:

- **Authentication** - Login, register, MFA, social auth
- **Users** - CRUD, sessions, roles, applications
- **Organizations** - Multi-tenant management
- **Applications** - OAuth client management
- **Profile** - User settings and preferences
- **Webhooks** - Event subscriptions
- **Enterprise** - LDAP, branding, domains, audit

See [API Documentation](docs/api/) for complete details.

## Admin Panel

The Filament-powered admin panel provides:

### Resources (12)
- Users, Organizations, Applications
- Roles, Permissions
- Authentication Logs
- Social Accounts, Invitations
- LDAP Configurations
- Custom Domains
- Webhooks, Webhook Deliveries

### Dashboard Widgets (13)
- System Health Monitor
- Real-Time Metrics
- OAuth Flow Monitor
- Security Monitoring
- Login Activity Chart
- Error Trends Analysis
- And more...

## Testing

AuthOS includes a comprehensive test suite with 475+ test methods:

```bash
# Run all tests
./run-tests.sh

# Run specific test categories
php artisan test tests/Integration/Security/    # Security (100% passing)
php artisan test tests/Integration/OAuth/       # OAuth (100% passing)
php artisan test tests/Integration/SSO/         # SSO (100% passing)
php artisan test tests/Integration/Webhooks/    # Webhooks (100% passing)

# Run with coverage
composer test:coverage
```

### Test Categories

| Category | Files | Tests | Status |
|----------|-------|-------|--------|
| Security | 5 | 99 | 100% |
| SSO | 5 | 45 | 100% |
| OAuth | 6 | 10 | 100% |
| Webhooks | 4 | 62 | 100% |
| Cache | 3 | 28 | 100% |
| Bulk Operations | 2 | 39 | 100% |
| Monitoring | 5 | 38 | 100% |
| Model Lifecycle | 3 | 40 | 100% |

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

- [API Reference](docs/api/) - Complete API documentation
- [Architecture](docs/architecture/) - System design and patterns
- [Security](docs/security/) - Security implementation details
- [Guides](docs/guides/) - How-to guides and tutorials
- [Operations](docs/operations/) - Deployment and operations
- [Testing](docs/testing/) - Test patterns and guidelines

## Development

### Code Quality

```bash
# Run all quality checks
composer quality

# Individual checks
composer cs:fix      # Code style (Pint)
composer analyse     # Static analysis (PHPStan)
composer security    # Security audit
```

### Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines on:

- Code standards
- Testing requirements
- Pull request process
- Commit message format

## Security

If you discover a security vulnerability, please review our security policy and report responsibly. See the [Security Documentation](docs/security/) for details on:

- OWASP compliance
- Security headers
- Intrusion detection
- Account protection

## License

AuthOS is open-source software licensed under the [MIT License](LICENSE).

---

<p align="center">
  Built with Laravel and Filament
</p>
