# CLAUDE.md - Laravel 12 Auth Service Project Documentation

## Project Overview
This is a comprehensive Laravel 12 authentication service built as an alternative to Auth0. The project leverages Filament 4 for admin panel management and implements OAuth 2.0, OpenID Connect, multi-factor authentication, and single sign-on capabilities.

## Technology Stack
- **Laravel 12** - Core framework with latest features
- **Filament 4** - Admin panel with built-in MFA support
- **Laravel Passport** - OAuth 2.0 server implementation  
- **Laravel Fortify** - Authentication backend services
- **Laravel Socialite** - Social authentication providers
- **Spatie Laravel Permission** - Role and permission management
- **Spatie Laravel Activity Log** - Audit trail functionality
- **PostgreSQL** - Primary database
- **Redis** - Caching, sessions, and queue backend

## Development Commands

### Environment Setup
```bash
# Start development environment
composer dev

# Individual services
php artisan serve          # Laravel server on http://127.0.0.1:8000
php artisan queue:listen   # Queue worker
php artisan pail          # Real-time logs
npm run dev               # Vite development server
```

### Database Operations
```bash
# Run migrations
php artisan migrate

# Refresh with seeders (includes sample data)
php artisan migrate:refresh --seed

# Generate new OAuth keys
php artisan passport:keys
```

### Testing
```bash
# Run test suite
composer test
# OR
php artisan test
```

## Project Structure

### Key Directories
- `app/Models/` - Core models (User, Organization, Application)
- `app/Filament/Resources/` - Admin panel resources
- `app/Http/Middleware/` - Custom middleware (SecurityHeaders)
- `database/migrations/` - Database schema definitions
- `database/seeders/` - Sample data seeders

### Core Models

#### User Model (`app/Models/User.php`)
- Enhanced with MFA support (mfa_enabled, mfa_secret, backup_codes)
- Laravel Passport traits for OAuth
- Spatie roles and permissions
- Organization relationships

#### Organization Model (`app/Models/Organization.php`)
- Multi-tenancy support
- Security policy configuration
- User and application relationships

#### Application Model (`app/Models/Application.php`)
- OAuth client management
- Auto-generated client credentials
- Redirect URI validation
- Organization scoped

## Database Schema

### Key Tables
- `organizations` - Multi-tenant organization management
- `applications` - OAuth client applications
- `users` - Enhanced with MFA fields
- `user_applications` - User access to applications
- `authentication_logs` - Audit trail for all auth events
- `oauth_*` tables - Laravel Passport OAuth implementation
- `roles` & `permissions` tables - Spatie RBAC system

## Environment Configuration

### Required Environment Variables
```bash
# Database
DB_CONNECTION=pgsql
DB_DATABASE=authos

# Redis (Sessions, Cache, Queues)
REDIS_HOST=127.0.0.1
REDIS_PASSWORD=null
REDIS_PORT=6379

# OAuth Configuration
PASSPORT_PERSONAL_ACCESS_CLIENT_ID=
PASSPORT_PERSONAL_ACCESS_CLIENT_SECRET=
PASSPORT_PASSWORD_GRANT_CLIENT_ID=
PASSPORT_PASSWORD_GRANT_CLIENT_SECRET=

# MFA Settings
MFA_ISSUER="AuthOS"
MFA_DIGITS=6
MFA_ALGORITHM=sha1
MFA_PERIOD=30
MFA_BACKUP_CODES_COUNT=8

# Rate Limiting
RATE_LIMIT_API=100
RATE_LIMIT_AUTH=10
RATE_LIMIT_OAUTH=20

# CORS Settings
CORS_ALLOWED_ORIGINS="http://localhost:3000,http://127.0.0.1:3000"
CORS_ALLOWED_METHODS="GET,POST,PUT,DELETE,OPTIONS"
CORS_ALLOWED_HEADERS="Content-Type,Authorization,X-Requested-With"
CORS_EXPOSED_HEADERS="X-Pagination-Count,X-Pagination-Page"
CORS_MAX_AGE=3600
CORS_SUPPORTS_CREDENTIALS=true
```

## Security Features

### Implemented Security Measures
- Comprehensive security headers middleware (`SecurityHeaders.php`)
- CORS configuration for API endpoints
- Rate limiting on authentication endpoints
- CSRF protection on all forms
- PostgreSQL with parameterized queries
- Redis session management
- OAuth 2.0 with PKCE support planned

### Security Headers Applied
- `X-Content-Type-Options: nosniff`
- `X-Frame-Options: DENY`
- `X-XSS-Protection: 1; mode=block`
- `Strict-Transport-Security` with HSTS preload
- `Referrer-Policy: strict-origin-when-cross-origin`
- `Permissions-Policy` for enhanced privacy

## Sample Data (Seeders)

### Organizations
1. **TechCorp Solutions** - Standard security (MFA optional)
2. **SecureBank Holdings** - High security (MFA required)

### Applications  
1. **TechCorp Dashboard** - Main application
2. **SecureBank Portal** - Banking application  
3. **Analytics Platform** - Cross-organization analytics

### Roles & Permissions
- **Super Admin** (23 permissions) - Full system access
- **Organization Admin** (16 permissions) - Organization management
- **Application Admin** (10 permissions) - App-specific management  
- **User** (3 permissions) - Basic user operations

## Development Progress

### ✅ Phase 1: Foundation Setup (COMPLETE)
All foundation tasks completed including:
- Environment configuration with Redis and security settings
- Database architecture with 5 new migrations
- Authentication packages installation and configuration
- Security middleware and CORS setup
- Comprehensive seeders with sample data
- OAuth key generation and Passport setup

### 🚧 Phase 2: Admin Panel Development (IN PROGRESS)
Current todo list:
- Configure main admin panel with MFA
- Set up authentication guards
- Configure navigation structure
- Set up database notifications
- Configure theme and branding
- Create Filament resources for all models

### 📋 Upcoming Phases
- Phase 3: OAuth 2.0 & OpenID Connect
- Phase 4: Multi-Factor Authentication
- Phase 5: API Development
- Phase 6: Advanced Features (SSO, Social Auth)
- Phase 7: Webhook & Integration System
- Phase 8: Performance & Security
- Phase 9: Testing & Quality Assurance
- Phase 10: Documentation & Deployment

## Admin Panel Access

### Filament Admin Panel
- **URL**: `/admin`
- **Current Configuration**: Basic setup with login
- **Authentication**: Standard Laravel authentication
- **Planned Features**: MFA integration, role-based access

### Default Admin User
Created via seeder:
- **Email**: admin@techcorp.com
- **Role**: Super Admin
- **Organization**: TechCorp Solutions

## API Endpoints (Planned)

### Authentication Endpoints
- `POST /api/auth/login` - User authentication
- `POST /api/auth/logout` - User logout  
- `POST /api/auth/register` - User registration
- `POST /api/auth/refresh` - Token refresh

### OAuth 2.0 Endpoints  
- `GET /oauth/authorize` - Authorization endpoint
- `POST /oauth/token` - Token endpoint
- `GET /oauth/user` - User info endpoint

### Management Endpoints
- `/api/organizations` - Organization management
- `/api/applications` - Application management
- `/api/users` - User management
- `/api/auth-logs` - Authentication logs

## Troubleshooting

### Common Issues
1. **Redis Connection Error**: Ensure Redis is running locally
2. **Database Migration Issues**: Check PostgreSQL connection and permissions
3. **OAuth Keys Missing**: Run `php artisan passport:keys`
4. **Seeder Failures**: Check database constraints and foreign key relationships

### Useful Commands
```bash
# Clear all caches
php artisan optimize:clear

# Generate application key
php artisan key:generate

# View current routes
php artisan route:list

# Check queue status
php artisan queue:work --once
```

## Notes for Future Development

### Important Architectural Decisions
1. **Multi-tenancy**: Organization-based isolation implemented
2. **MFA Strategy**: User-level MFA with organization policies
3. **OAuth Flow**: Standard authorization code flow with PKCE
4. **Database**: PostgreSQL chosen for JSONB support and performance
5. **Caching**: Redis for sessions, cache, and queue backend

### Code Conventions
- Follow Laravel coding standards
- Use Filament conventions for admin resources
- Implement proper validation at model and request levels
- Maintain comprehensive audit logging
- Follow security best practices throughout

### Testing Strategy
- Unit tests for all service classes
- Feature tests for API endpoints  
- Integration tests for OAuth flows
- E2E tests for admin panel workflows

This documentation provides a comprehensive overview for any Claude instance working on this Laravel 12 authentication service project.