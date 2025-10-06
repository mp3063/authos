<?php

namespace Tests\Browser\Helpers;

use App\Models\User;
use Illuminate\Support\Facades\Hash;
use Laravel\Dusk\Browser;

trait BrowserTestHelpers
{
    /**
     * Create a test user.
     */
    protected function createTestUser(array $attributes = []): User
    {
        return User::factory()->create(array_merge([
            'email' => 'test-'.uniqid().'@example.com',
            'password' => Hash::make('password123'),
            'email_verified_at' => now(),
        ], $attributes));
    }

    /**
     * Create an admin user.
     */
    protected function createAdminUser(): User
    {
        $user = $this->createTestUser([
            'email' => 'admin-'.uniqid().'@example.com',
        ]);

        $user->assignRole('Super Admin');

        return $user;
    }

    /**
     * Login as a user.
     */
    protected function loginAs(Browser $browser, User $user, string $password = 'password123'): void
    {
        $browser->visit('/login')
            ->type('input[name="email"]', $user->email)
            ->type('input[name="password"]', $password)
            ->click('button[type="submit"]')
            ->pause(500);
    }

    /**
     * Login to Filament admin as a user.
     */
    protected function loginToFilamentAs(Browser $browser, User $user, string $password = 'password123'): void
    {
        $browser->visit('/admin/login')
            ->type('input[name="email"]', $user->email)
            ->type('input[name="password"]', $password)
            ->click('button[type="submit"]')
            ->pause(1000);
    }

    /**
     * Take a screenshot on failure.
     */
    protected function takeScreenshotOnFailure(Browser $browser, string $name): void
    {
        if ($this->hasFailed()) {
            $browser->screenshot("failure-{$name}");
        }
    }

    /**
     * Wait for Livewire to finish.
     */
    protected function waitForLivewire(Browser $browser): void
    {
        $browser->waitUntilMissing('[wire\\:loading]', 5);
    }

    /**
     * Wait for AJAX to finish.
     */
    protected function waitForAjax(Browser $browser): void
    {
        $browser->pause(300);
    }

    /**
     * Fill Filament form field.
     */
    protected function fillFilamentField(Browser $browser, string $name, string $value): void
    {
        $browser->type("input[wire\\:model=\"data.{$name}\"]", $value)
            ->pause(100);
    }

    /**
     * Click Filament button.
     */
    protected function clickFilamentButton(Browser $browser, string $label): void
    {
        $browser->click("button:contains(\"{$label}\")")
            ->pause(300);
    }

    /**
     * Assert Filament notification.
     */
    protected function assertFilamentNotification(Browser $browser, string $message, string $type = 'success'): void
    {
        $browser->waitFor('.fi-no-notification', 3)
            ->assertSeeIn('.fi-no-notification', $message);
    }

    /**
     * Dismiss Filament notification.
     */
    protected function dismissFilamentNotification(Browser $browser): void
    {
        $browser->click('.fi-no-close-btn')
            ->pause(200);
    }

    /**
     * Generate TOTP code for MFA.
     */
    protected function generateTOTPCode(string $secret): string
    {
        // Simplified TOTP generation - in real tests you'd use a proper library
        // For demonstration purposes
        return sprintf('%06d', rand(100000, 999999));
    }

    /**
     * Wait for redirect.
     */
    protected function waitForRedirect(Browser $browser, string $path, int $seconds = 5): void
    {
        $browser->waitForLocation($path, $seconds);
    }

    /**
     * Resize browser for mobile testing.
     */
    protected function resizeMobile(Browser $browser): void
    {
        $browser->resize(375, 667); // iPhone size
    }

    /**
     * Resize browser for tablet testing.
     */
    protected function resizeTablet(Browser $browser): void
    {
        $browser->resize(768, 1024); // iPad size
    }

    /**
     * Resize browser for desktop testing.
     */
    protected function resizeDesktop(Browser $browser): void
    {
        $browser->resize(1920, 1080); // Full HD
    }

    /**
     * Scroll to element.
     */
    protected function scrollTo(Browser $browser, string $selector): void
    {
        $browser->script("document.querySelector('{$selector}').scrollIntoView();");
        $browser->pause(200);
    }

    /**
     * Check if element exists.
     */
    protected function elementExists(Browser $browser, string $selector): bool
    {
        return count($browser->elements($selector)) > 0;
    }
}
