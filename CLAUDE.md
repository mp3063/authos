# CLAUDE.md - Laravel 12 Auth Service Project Documentation

## Project Overview
This is a comprehensive Laravel 12 authentication service built as an alternative to Auth0. The project leverages Filament 4 for admin panel management and implements OAuth 2.0, OpenID Connect, multi-factor authentication, and single sign-on capabilities.

**Current Status**: Phase 2 Complete - Full admin panel implementation with complete CRUD resources for all models.

## Technology Stack
- **Laravel 12** - Core framework with latest features
- **Filament 4** - Admin panel with built-in MFA support (✅ Implemented)
- **Laravel Passport** - OAuth 2.0 server implementation  
- **Laravel Fortify** - Authentication backend services
- **Laravel Socialite** - Social authentication providers
- **Spatie Laravel Permission** - Role and permission management (✅ Implemented)
- **Spatie Laravel Activity Log** - Audit trail functionality (✅ Implemented)
- **PostgreSQL** - Primary database (✅ Configured)
- **Redis** - Caching, sessions, and queue backend (✅ Configured)

## Development Commands

### Environment Setup
```bash
# Start development environment (using HERD for local development)
# HERD users: Admin panel accessible at http://authos.test/admin

# Individual services for non-HERD setups
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

### Testing & Quality Assurance
```bash
# Run test suite
composer test
# OR
php artisan test

# Run linting and type checking (recommended after changes)
npm run lint              # Frontend linting
npm run typecheck        # TypeScript checking (if applicable)
```

## Project Structure

### Key Directories
- `app/Models/` - Core models (User, Organization, Application, AuthenticationLog)
- `app/Filament/Resources/` - Complete admin panel resources (✅ All implemented)
- `app/Filament/Widgets/` - Dashboard analytics widgets (✅ Implemented)
- `app/Http/Middleware/` - Custom middleware (SecurityHeaders)
- `app/Enums/` - Navigation and system enumerations
- `database/migrations/` - Database schema definitions (15 migrations)
- `database/seeders/` - Sample data seeders
- `public/` - Compiled Filament assets (CSS, JS, fonts)

### Core Models

#### User Model (`app/Models/User.php`)
- Enhanced with MFA support (mfa_methods, two_factor_secret, recovery_codes)
- Laravel Passport traits for OAuth
- Spatie roles and permissions integration
- Organization relationships
- Helper method: `hasMfaEnabled()` for MFA status checking

#### Organization Model (`app/Models/Organization.php`)
- Multi-tenancy support with slug-based identification
- Security policy configuration (JSONB field)
- User and application relationships
- Settings include: require_mfa, password_policy, session_timeout, etc.

#### Application Model (`app/Models/Application.php`)
- OAuth client management with auto-generated credentials
- Redirect URI validation
- Organization scoped applications
- User access tracking through pivot table

#### AuthenticationLog Model (`app/Models/AuthenticationLog.php`)
- Comprehensive audit trail for authentication events
- IP address and user agent tracking
- Event categorization and security monitoring

## Database Schema

### Key Tables (15 Total Migrations)
- `organizations` - Multi-tenant organization management
- `applications` - OAuth client applications
- `users` - Enhanced with MFA fields (mfa_methods, two_factor_*, etc.)
- `user_applications` - User access to applications with login tracking
- `authentication_logs` - Audit trail for all auth events
- `oauth_*` tables (5 tables) - Laravel Passport OAuth implementation
- `roles` & `permissions` tables - Spatie RBAC system
- `activity_log` tables (3 tables) - Spatie activity logging
- `notifications` - Database notifications for admin panel

## Admin Panel Implementation

### Filament 4 Admin Panel (✅ COMPLETE)
- **URL**: `/admin`
- **Configuration**: Fully configured with navigation groups, theming, and notifications
- **Authentication**: Standard Laravel authentication with role-based access
- **Features**: 
  - Database notifications with 30s polling
  - Custom dashboard with analytics widgets
  - Navigation organized into logical groups
  - Maximum content width optimized for admin tasks

### Admin Resources (All Implemented ✅)

#### User Management
- **UserResource**: Complete CRUD with MFA controls, bulk operations
- **Features**: User tabs (All/Active/MFA Enabled), role assignments, MFA reset
- **Pages**: List, Create, Edit, View (with MFA reset action)
- **Relations**: User-application relationships

#### Organization Management  
- **OrganizationResource**: Multi-tenant organization management
- **Features**: Security policy configuration, bulk status toggles
- **Auto-slug**: Automatic slug generation from organization name
- **Relations**: Organization applications

#### Application Management
- **ApplicationResource**: OAuth client application management
- **Features**: Client credentials, redirect URI management, user access
- **Relations**: Application users with login tracking

#### Access Control (RBAC)
- **RoleResource**: Complete role management with permission assignment
- **PermissionResource**: Permission management with role assignment
- **Features**: Role duplication, bulk permission assignments, categorization
- **Relations**: Role-user and role-permission managers

#### Authentication Monitoring
- **AuthenticationLogResource**: Comprehensive audit trail
- **Features**: Event filtering, IP tracking, security monitoring
- **Analytics**: Integration with dashboard widgets

### Dashboard Widgets (✅ Implemented)
- **AuthStatsOverview**: Authentication statistics with trend indicators
- **LoginActivityChart**: Visual login activity trends
- **RecentAuthenticationLogs**: Real-time security event monitoring

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

## Security Features (✅ Implemented)

### Security Measures
- **SecurityHeaders Middleware**: Comprehensive HTTP security headers
- **CORS Configuration**: Proper API endpoint protection
- **Rate Limiting**: Authentication and API endpoint protection
- **CSRF Protection**: All forms protected
- **PostgreSQL**: Parameterized queries and JSONB support
- **Redis Session Management**: Secure session handling
- **OAuth 2.0**: Laravel Passport implementation

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

### Default Admin User
Created via seeder:
- **Email**: admin@techcorp.com
- **Password**: Set in seeder
- **Role**: Super Admin
- **Organization**: TechCorp Solutions

## Development Progress

### ✅ Phase 1: Foundation Setup (COMPLETE)
- Environment configuration with Redis and security settings
- Database architecture with 15 migrations
- Authentication packages installation and configuration
- Security middleware and CORS setup
- Comprehensive seeders with sample data
- OAuth key generation and Passport setup

### ✅ Phase 2: Admin Panel Development (COMPLETE)
**All tasks completed:**
- ✅ Main admin panel configuration with database notifications
- ✅ Navigation structure with organized groups
- ✅ Theme and branding setup
- ✅ Complete CRUD resources for all models:
  - ✅ UserResource with MFA controls
  - ✅ OrganizationResource with security policies
  - ✅ ApplicationResource with OAuth management
  - ✅ RoleResource and PermissionResource for RBAC
  - ✅ AuthenticationLogResource for monitoring
- ✅ Dashboard widgets with analytics
- ✅ All Filament 4.x compatibility issues resolved

### 📋 Upcoming Phases
- **Phase 3**: OAuth 2.0 & OpenID Connect API Implementation
- **Phase 4**: Multi-Factor Authentication Frontend Integration
- **Phase 5**: Public API Development with Rate Limiting
- **Phase 6**: Advanced Features (SSO, Social Auth, WebAuthn)
- **Phase 7**: Webhook & Integration System
- **Phase 8**: Performance & Security Hardening
- **Phase 9**: Testing & Quality Assurance
- **Phase 10**: Documentation & Deployment

## Git History & Project Organization

### Commit Structure (11 Logical Commits)
The project is organized into logical commits for better management:
1. **Project Foundation & Configuration** (7 files)
2. **Database Schema & Models** (23 files)
3. **Security & OAuth Configuration** (4 files)
4. **Filament Admin Panel Setup** (3 files)
5. **User Management Resources** (6 files)
6. **Organization Management Resources** (6 files)
7. **Application Management Resources** (6 files)
8. **Access Control Resources** (12 files)
9. **Authentication Logging & Monitoring** (3 files)
10. **Dashboard Widgets & Analytics** (3 files)
11. **Filament Assets** (46 compiled files)

**Total**: 119 files representing complete authentication service implementation.

## API Endpoints (Planned - Phase 3)

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

## Filament 4.x Specific Notes

### Known Compatibility Requirements
- Use `recordActions()` instead of deprecated `actions()`
- Use `toolbarActions()` instead of deprecated `bulkActions()`
- Import Actions from `Filament\Actions\` namespace
- Use string values for MaxWidth (e.g., '7xl') instead of enums
- Import Tab components from correct namespace: `Filament\Schemas\Components\Tabs\Tab`
- Avoid deprecated methods like `formatStateUsing()` in favor of column-specific methods

### Asset Management
- Filament assets are auto-compiled to `public/` directory
- Includes Inter font family and all necessary CSS/JS components
- No manual asset compilation required

## Troubleshooting

### Common Issues & Solutions
1. **Redis Connection Error**: Ensure Redis is running locally
2. **Database Migration Issues**: Check PostgreSQL connection and permissions
3. **OAuth Keys Missing**: Run `php artisan passport:keys`
4. **Seeder Failures**: Check database constraints and foreign key relationships
5. **Filament Route Errors**: Ensure all actions have proper routes defined
6. **PostgreSQL JSON Errors**: Use `jsonb()` instead of `json()` for better performance

### Development Commands
```bash
# Clear all caches
php artisan optimize:clear

# Generate application key
php artisan key:generate

# View current routes
php artisan route:list

# Check queue status
php artisan queue:work --once

# Reset to clean state
php artisan migrate:fresh --seed
php artisan passport:keys --force
```

## Important Architectural Decisions

### Technical Architecture
1. **Multi-tenancy**: Organization-based isolation with slug identification
2. **MFA Strategy**: User-level MFA with organization policy overrides
3. **OAuth Flow**: Laravel Passport with standard authorization code flow
4. **Database**: PostgreSQL with JSONB for flexible configuration storage
5. **Caching**: Redis for sessions, cache, and queue backend
6. **Admin Interface**: Filament 4.x with database notifications and real-time updates

### Code Conventions & Standards
- Follow Laravel coding standards and PSR-12
- Use Filament 4.x conventions for admin resources
- Implement proper validation at model and request levels
- Maintain comprehensive audit logging for all actions
- Follow security best practices throughout codebase
- No unnecessary code comments unless explicitly requested

### Security Best Practices Implemented
- Comprehensive HTTP security headers
- CORS configuration for API access
- Rate limiting on authentication endpoints
- MFA support with organization-level policies
- Audit logging for all authentication events
- Role-based access control (RBAC) system

This documentation provides a comprehensive overview for any Claude instance working on this Laravel 12 authentication service project. The project is now ready for Phase 3 development focusing on OAuth 2.0 API implementation.