<?php

namespace Tests\Browser\Pages;

use Laravel\Dusk\Browser;
use Laravel\Dusk\Page;

class ProfilePage extends Page
{
    /**
     * Get the URL for the page.
     */
    public function url(): string
    {
        return '/profile';
    }

    /**
     * Assert that the browser is on the page.
     */
    public function assert(Browser $browser): void
    {
        $browser->assertPathBeginsWith('/profile');
    }

    /**
     * Get the element shortcuts for the page.
     */
    public function elements(): array
    {
        return [
            '@name' => 'input[name="name"]',
            '@email' => 'input[name="email"]',
            '@currentPassword' => 'input[name="current_password"]',
            '@newPassword' => 'input[name="password"]',
            '@confirmPassword' => 'input[name="password_confirmation"]',
            '@saveButton' => 'button[type="submit"]:contains("Save"), button:contains("Update")',
            '@mfaSection' => '#mfa-section, [data-mfa-section]',
            '@enableMFA' => 'button:contains("Enable"), a:contains("Enable MFA")',
            '@disableMFA' => 'button:contains("Disable"), a:contains("Disable MFA")',
            '@successMessage' => '.alert-success, [role="alert"]',
            '@errorMessage' => '.alert-danger, [role="alert"]',
        ];
    }

    /**
     * Update profile information.
     */
    public function updateProfile(Browser $browser, string $name, string $email): void
    {
        $browser->type('@name', $name)
            ->type('@email', $email)
            ->click('@saveButton')
            ->pause(500);
    }

    /**
     * Change password.
     */
    public function changePassword(
        Browser $browser,
        string $currentPassword,
        string $newPassword
    ): void {
        $browser->type('@currentPassword', $currentPassword)
            ->type('@newPassword', $newPassword)
            ->type('@confirmPassword', $newPassword)
            ->click('@saveButton')
            ->pause(500);
    }
}
