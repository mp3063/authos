# AuthOS E2E Testing - Quick Start Guide

## Installation (One-Time Setup)

```bash
# 1. Install Dusk (already done)
composer require --dev laravel/dusk

# 2. Create test database
createdb authos_dusk

# 3. Install ChromeDriver
php artisan dusk:chrome-driver --detect
```

## Running Tests

### Run All Tests
```bash
./run-dusk.sh
```

### Run Specific Test File
```bash
./run-dusk.sh tests/Browser/Auth/LoginTest.php
```

### Run Specific Test Directory
```bash
./run-dusk.sh tests/Browser/Admin
```

### Run With PHPUnit Directly
```bash
herd php artisan dusk --configuration=phpunit.dusk.xml
```

## Common Commands

### Database Reset
```bash
herd php artisan migrate:fresh --seed --database=pgsql
```

### Update ChromeDriver
```bash
herd php artisan dusk:chrome-driver --detect
```

### Clear Caches
```bash
herd php artisan config:clear
herd php artisan cache:clear
herd php artisan view:clear
```

## Test Categories

### Authentication Tests (22 tests)
```bash
./run-dusk.sh tests/Browser/Auth
```

### OAuth Tests (5 tests)
```bash
./run-dusk.sh tests/Browser/OAuth
```

### Admin Panel Tests (27 tests)
```bash
./run-dusk.sh tests/Browser/Admin
```

### Security Tests (11 tests)
```bash
./run-dusk.sh tests/Browser/Security
```

### Multi-Tenant Tests (4 tests)
```bash
./run-dusk.sh tests/Browser/MultiTenant
```

## Debugging

### View Screenshots (on failure)
```bash
open tests/Browser/screenshots/
```

### View Console Logs (on failure)
```bash
ls tests/Browser/console/
```

### Run in Headed Mode (see browser)
Edit `tests/DuskTestCase.php` and comment out `--headless=new`

## Writing New Tests

### Basic Structure
```php
<?php

namespace Tests\Browser\MyCategory;

use Tests\DuskTestCase;
use Tests\Browser\Helpers\BrowserTestHelpers;
use Illuminate\Foundation\Testing\DatabaseMigrations;
use Laravel\Dusk\Browser;

class MyTest extends DuskTestCase
{
    use DatabaseMigrations, BrowserTestHelpers;

    public function test_my_scenario(): void
    {
        $this->browse(function (Browser $browser) {
            $browser->visit('/')
                ->assertSee('Welcome');
        });
    }
}
```

### Using Page Objects
```php
use Tests\Browser\Pages\LoginPage;

$this->browse(function (Browser $browser) {
    $browser->visit(new LoginPage)
        ->login('user@example.com', 'password')
        ->assertPathIs('/dashboard');
});
```

### Using Helpers
```php
public function test_example(): void
{
    $user = $this->createTestUser();

    $this->browse(function (Browser $browser) use ($user) {
        $this->loginAs($browser, $user);
        $this->waitForLivewire($browser);
        $this->assertFilamentNotification($browser, 'Success!');
    });
}
```

## Troubleshooting

### Tests Hanging
- Stop ChromeDriver: `pkill chromedriver`
- Restart: `./vendor/laravel/dusk/bin/chromedriver-mac &`

### Database Errors
- Check database exists: `psql -l | grep authos_dusk`
- Create if missing: `createdb authos_dusk`
- Reset database: `herd php artisan migrate:fresh --seed`

### Port Conflicts
- Change APP_URL in `.env.dusk.local`
- Change DUSK_DRIVER_URL if 9515 is taken

### "Element not found"
- Add `->pause(500)` before assertion
- Use `->waitFor('@element')` instead of `->assertVisible()`

## Tips

- Use `$browser->pause(5000)` to inspect during test
- Use `$browser->screenshot('debug')` to capture state
- Use `--filter=testMethodName` to run specific test
- Check `storage/logs/laravel.log` for application errors
- Use data attributes for selectors (e.g., `[data-testid="..."]`)

## Resources

- Full Documentation: `tests/Browser/README.md`
- Implementation Report: `E2E_TESTING_REPORT.md`
- Laravel Dusk Docs: https://laravel.com/docs/11.x/dusk
