<?php

namespace Tests\Browser\Pages;

use Laravel\Dusk\Browser;
use Laravel\Dusk\Page;

class FilamentLoginPage extends Page
{
    /**
     * Get the URL for the page.
     */
    public function url(): string
    {
        return '/admin/login';
    }

    /**
     * Assert that the browser is on the page.
     */
    public function assert(Browser $browser): void
    {
        $browser->assertPathIs($this->url());
    }

    /**
     * Get the element shortcuts for the page.
     */
    public function elements(): array
    {
        return [
            '@email' => 'input[name="email"], input[type="email"]',
            '@password' => 'input[name="password"], input[type="password"]',
            '@remember' => 'input[name="remember"]',
            '@submit' => 'button[type="submit"]',
            '@errorMessage' => '.fi-fo-field-wrp-error-message, [role="alert"]',
        ];
    }

    /**
     * Perform Filament admin login.
     */
    public function login(Browser $browser, string $email, string $password, bool $remember = false): void
    {
        $browser->type('@email', $email)
            ->type('@password', $password);

        if ($remember) {
            $browser->check('@remember');
        }

        $browser->click('@submit')
            ->pause(1000); // Filament needs more time to load
    }

    /**
     * Login as admin.
     */
    public function loginAsAdmin(Browser $browser): void
    {
        $this->login($browser, 'admin@authservice.com', 'password123');
    }
}
