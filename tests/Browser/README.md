# AuthOS E2E Testing Framework

Comprehensive end-to-end testing suite for AuthOS using Laravel Dusk.

## Overview

This E2E testing framework provides automated browser testing for all critical user flows in the AuthOS application, including authentication, OAuth flows, admin panel operations, and security scenarios.

## Test Structure

```
tests/Browser/
├── Auth/                      # Authentication tests
│   ├── LoginTest.php         # Login flows (8 tests)
│   ├── RegistrationTest.php  # Registration flows (6 tests)
│   ├── MFATest.php           # Multi-factor authentication (4 tests)
│   └── PasswordResetTest.php # Password reset flows (4 tests)
├── OAuth/                     # OAuth 2.0 tests
│   └── AuthorizationFlowTest.php # Authorization code flow (5 tests)
├── Admin/                     # Filament admin tests
│   ├── FilamentLoginTest.php # Admin login (4 tests)
│   ├── UserManagementTest.php # User CRUD operations (5 tests)
│   ├── OrganizationManagementTest.php # Organization management (4 tests)
│   ├── ApplicationManagementTest.php # OAuth app management (6 tests)
│   ├── DashboardTest.php     # Dashboard & widgets (5 tests)
│   └── AuditLogTest.php      # Audit log viewing (3 tests)
├── Security/                  # Security tests
│   ├── BruteForceProtectionTest.php # Account lockout (4 tests)
│   ├── XSSProtectionTest.php # XSS prevention (4 tests)
│   └── CSRFProtectionTest.php # CSRF protection (3 tests)
├── MultiTenant/               # Multi-tenancy tests
│   └── OrganizationIsolationTest.php # Data isolation (4 tests)
├── Pages/                     # Page Objects
│   ├── LoginPage.php
│   ├── RegisterPage.php
│   ├── MFASetupPage.php
│   ├── DashboardPage.php
│   ├── ProfilePage.php
│   ├── PasswordResetPage.php
│   ├── FilamentLoginPage.php
│   ├── FilamentDashboardPage.php
│   └── OAuthAuthorizePage.php
├── Components/                # Reusable components
│   ├── FilamentResourceTable.php
│   ├── FilamentModal.php
│   └── FilamentNotification.php
└── Helpers/                   # Test helpers
    └── BrowserTestHelpers.php
```

## Total Test Coverage

- **59 E2E test methods** across 15 test classes
- **9 Page Objects** for reusable page interactions
- **3 Component Objects** for Filament UI components
- **1 Test Helper Trait** with 20+ utility methods

## Quick Start

### Prerequisites

1. PHP 8.4+
2. ChromeDriver (auto-installed)
3. PostgreSQL database
4. Laravel Herd (or local PHP server)

### Installation

```bash
# Install dependencies
composer install

# Install Dusk
composer require --dev laravel/dusk
php artisan dusk:install

# Create test database
createdb authos_dusk
```

### Running Tests

```bash
# Run all E2E tests
./run-dusk.sh

# Run specific test file
./run-dusk.sh tests/Browser/Auth/LoginTest.php

# Run specific test directory
./run-dusk.sh tests/Browser/Admin

# Run with PHPUnit directly
php artisan dusk --configuration=phpunit.dusk.xml
```

## Test Categories

### 1. Authentication Tests (22 tests)

**Login Tests** (`tests/Browser/Auth/LoginTest.php`)
- ✓ View login form
- ✓ Login with valid credentials
- ✓ Login fails with invalid credentials
- ✓ Login fails with invalid password
- ✓ Remember me functionality
- ✓ Navigate to forgot password
- ✓ Navigate to registration
- ✓ Account lockout after failed attempts

**Registration Tests** (`tests/Browser/Auth/RegistrationTest.php`)
- ✓ View registration form
- ✓ Register with valid data
- ✓ Registration fails with invalid email
- ✓ Registration fails with short password
- ✓ Registration fails with existing email
- ✓ Navigate to login from registration

**MFA Tests** (`tests/Browser/Auth/MFATest.php`)
- ✓ Enable MFA
- ✓ MFA setup requires valid code
- ✓ Disable MFA
- ✓ Login with MFA requires code

**Password Reset Tests** (`tests/Browser/Auth/PasswordResetTest.php`)
- ✓ View password reset request form
- ✓ Request password reset with valid email
- ✓ Password reset fails with invalid email
- ✓ Navigate back to login

### 2. OAuth Tests (5 tests)

**Authorization Flow Tests** (`tests/Browser/OAuth/AuthorizationFlowTest.php`)
- ✓ Complete OAuth authorization code flow
- ✓ OAuth authorization with PKCE
- ✓ User can deny authorization
- ✓ Authorization requires authentication
- ✓ Authorization with invalid client

### 3. Admin Panel Tests (27 tests)

**Filament Login Tests** (`tests/Browser/Admin/FilamentLoginTest.php`)
- ✓ View Filament login form
- ✓ Admin login with valid credentials
- ✓ Login fails with invalid credentials
- ✓ Non-admin user cannot access Filament

**User Management Tests** (`tests/Browser/Admin/UserManagementTest.php`)
- ✓ View users list
- ✓ Create new user
- ✓ Search users
- ✓ Edit user
- ✓ Delete user

**Organization Management Tests** (`tests/Browser/Admin/OrganizationManagementTest.php`)
- ✓ View organizations list
- ✓ Create new organization
- ✓ Search organizations
- ✓ Edit organization

**Application Management Tests** (`tests/Browser/Admin/ApplicationManagementTest.php`)
- ✓ View applications list
- ✓ Create new OAuth application
- ✓ View application credentials
- ✓ Regenerate application credentials
- ✓ Edit application
- ✓ Delete application

**Dashboard Tests** (`tests/Browser/Admin/DashboardTest.php`)
- ✓ View dashboard
- ✓ Dashboard displays widgets
- ✓ Navigation menu is functional
- ✓ Widget auto-refresh functionality
- ✓ Dashboard responsive design

**Audit Log Tests** (`tests/Browser/Admin/AuditLogTest.php`)
- ✓ View authentication logs
- ✓ Filter authentication logs
- ✓ Export audit logs

### 4. Security Tests (11 tests)

**Brute Force Protection Tests** (`tests/Browser/Security/BruteForceProtectionTest.php`)
- ✓ Account lockout after multiple failed attempts
- ✓ Failed login attempts are tracked
- ✓ Rate limiting on login endpoint
- ✓ IP blocking after suspicious activity

**XSS Protection Tests** (`tests/Browser/Security/XSSProtectionTest.php`)
- ✓ XSS attack in profile name is prevented
- ✓ XSS in search field is prevented
- ✓ CSP headers are present
- ✓ Inline JavaScript is blocked by CSP

**CSRF Protection Tests** (`tests/Browser/Security/CSRFProtectionTest.php`)
- ✓ CSRF token is present in forms
- ✓ Form submission without CSRF token fails
- ✓ CSRF token is refreshed on each request

### 5. Multi-Tenant Tests (4 tests)

**Organization Isolation Tests** (`tests/Browser/MultiTenant/OrganizationIsolationTest.php`)
- ✓ Users can only see their organization's data
- ✓ Super admin can see all organizations
- ✓ Organization switching
- ✓ Cross-organization data access is prevented

## Page Objects

Page Objects provide a clean API for interacting with pages:

```php
// Example: Using LoginPage
$browser->visit(new LoginPage)
    ->login('user@example.com', 'password')
    ->waitForLocation('/dashboard');

// Example: Using FilamentResourceTable
$browser->within(new FilamentResourceTable, function (Browser $table) {
    $table->search('John Doe');
    $table->clickRowAction('Edit', 1);
});
```

### Available Page Objects

- `LoginPage` - User login page
- `RegisterPage` - User registration page
- `MFASetupPage` - MFA configuration page
- `DashboardPage` - User dashboard
- `ProfilePage` - User profile page
- `PasswordResetPage` - Password reset request
- `FilamentLoginPage` - Admin login page
- `FilamentDashboardPage` - Admin dashboard
- `OAuthAuthorizePage` - OAuth consent screen

## Component Objects

Component Objects encapsulate reusable UI components:

```php
// Example: Using FilamentModal
$browser->within(new FilamentModal, function (Browser $modal) {
    $modal->fillField('name', 'Test User');
    $modal->fillField('email', 'test@example.com');
    $modal->submit();
});
```

### Available Components

- `FilamentResourceTable` - Data tables with search, pagination, actions
- `FilamentModal` - Modal dialogs
- `FilamentNotification` - Toast notifications

## Test Helpers

The `BrowserTestHelpers` trait provides utility methods:

```php
use Tests\Browser\Helpers\BrowserTestHelpers;

class MyTest extends DuskTestCase
{
    use BrowserTestHelpers;

    public function test_example()
    {
        $user = $this->createTestUser();
        $admin = $this->createAdminUser();

        $this->browse(function (Browser $browser) use ($user) {
            $this->loginAs($browser, $user);
            $this->waitForLivewire($browser);
            $this->assertFilamentNotification($browser, 'Success!');
        });
    }
}
```

### Available Helpers

- `createTestUser()` - Create test user
- `createAdminUser()` - Create admin user
- `loginAs()` - Login as user
- `loginToFilamentAs()` - Login to Filament admin
- `waitForLivewire()` - Wait for Livewire to finish
- `waitForAjax()` - Wait for AJAX requests
- `fillFilamentField()` - Fill Filament form field
- `assertFilamentNotification()` - Assert notification
- `resizeMobile()` - Resize to mobile view
- `resizeTablet()` - Resize to tablet view
- `resizeDesktop()` - Resize to desktop view

## Configuration

### Environment Variables

Create `.env.dusk.local` for Dusk-specific configuration:

```bash
APP_URL=http://localhost:8000
DB_DATABASE=authos_dusk
DUSK_DRIVER_URL=http://localhost:9515
```

### Browser Options

Configure in `tests/DuskTestCase.php`:

```php
protected function driver(): RemoteWebDriver
{
    $options = (new ChromeOptions)->addArguments([
        '--disable-gpu',
        '--headless=new',  // Run in headless mode
        '--window-size=1920,1080',
    ]);

    return RemoteWebDriver::create(
        'http://localhost:9515',
        DesiredCapabilities::chrome()->setCapability(
            ChromeOptions::CAPABILITY, $options
        )
    );
}
```

## CI/CD Integration

### GitHub Actions

Tests automatically run on push/PR via `.github/workflows/e2e-tests.yml`:

```yaml
- name: Run Dusk tests
  run: php artisan dusk --configuration=phpunit.dusk.xml
```

Screenshots and logs are uploaded as artifacts on failure.

## Debugging

### Screenshots

Failed tests automatically capture screenshots:

```
tests/Browser/screenshots/
├── failure-login-test.png
├── failure-oauth-test.png
└── ...
```

### Console Logs

Browser console logs are captured:

```
tests/Browser/console/
├── login-test.log
├── oauth-test.log
└── ...
```

### Manual Screenshots

Take screenshots manually in tests:

```php
$browser->screenshot('my-screenshot');
```

### Pause Execution

Pause test execution to inspect:

```php
$browser->pause(5000); // Pause for 5 seconds
```

## Best Practices

1. **Use Page Objects** - Encapsulate page logic in Page Objects
2. **Use wait methods** - Always wait for elements before interacting
3. **Use descriptive selectors** - Prefer data attributes over classes
4. **Isolate tests** - Each test should be independent
5. **Clean up data** - Use DatabaseMigrations trait
6. **Take screenshots** - On failures for debugging
7. **Use helpers** - Leverage BrowserTestHelpers for common tasks
8. **Test happy paths first** - Then add edge cases
9. **Keep tests fast** - Minimize unnecessary waits
10. **Run tests frequently** - Catch regressions early

## Troubleshooting

### ChromeDriver Issues

```bash
# Update ChromeDriver
php artisan dusk:chrome-driver --detect

# Manually start ChromeDriver
./vendor/laravel/dusk/bin/chromedriver-mac &
```

### Database Issues

```bash
# Reset test database
php artisan migrate:fresh --seed --database=pgsql --env=testing
```

### Port Conflicts

```bash
# Change default ports in .env.dusk.local
APP_URL=http://localhost:8001
DUSK_DRIVER_URL=http://localhost:9516
```

### Headless Mode Issues

Disable headless mode in `DuskTestCase.php` for debugging:

```php
$options = (new ChromeOptions)->addArguments([
    '--disable-gpu',
    // '--headless=new',  // Comment out
]);
```

## Performance

- **Average test execution**: 2-5 seconds per test
- **Full suite runtime**: ~5-10 minutes (59 tests)
- **Parallel execution**: Not yet configured (can reduce to ~2-3 minutes)

## Future Enhancements

- [ ] Add SSO flow tests (OIDC/SAML)
- [ ] Add social authentication tests (Google, GitHub, etc.)
- [ ] Add LDAP/AD integration tests
- [ ] Add webhook delivery tests
- [ ] Add bulk operation tests
- [ ] Add mobile-specific tests
- [ ] Add accessibility tests
- [ ] Add performance tests
- [ ] Add visual regression tests
- [ ] Configure parallel test execution

## Resources

- [Laravel Dusk Documentation](https://laravel.com/docs/11.x/dusk)
- [Filament Testing](https://filamentphp.com/docs/3.x/panels/testing)
- [Selenium WebDriver](https://www.selenium.dev/documentation/webdriver/)
- [PHPUnit Documentation](https://phpunit.de/documentation.html)

## Support

For issues or questions:
1. Check screenshots in `tests/Browser/screenshots/`
2. Check console logs in `tests/Browser/console/`
3. Review Laravel logs in `storage/logs/`
4. Run tests with `--verbose` flag for more output
