<?php

namespace Tests\Browser\Pages;

use Laravel\Dusk\Browser;
use Laravel\Dusk\Page;

class LoginPage extends Page
{
    /**
     * Get the URL for the page.
     */
    public function url(): string
    {
        return '/login';
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
            '@email' => 'input[name="email"]',
            '@password' => 'input[name="password"]',
            '@remember' => 'input[name="remember"]',
            '@submit' => 'button[type="submit"]',
            '@forgotPassword' => 'a[href*="forgot-password"]',
            '@register' => 'a[href*="register"]',
            '@errorMessage' => '.alert-danger, [role="alert"]',
        ];
    }

    /**
     * Perform login with credentials.
     */
    public function login(Browser $browser, string $email, string $password, bool $remember = false): void
    {
        $browser->type('@email', $email)
            ->type('@password', $password);

        if ($remember) {
            $browser->check('@remember');
        }

        $browser->click('@submit')
            ->pause(500);
    }

    /**
     * Login with valid credentials.
     */
    public function loginAsUser(Browser $browser, ?string $email = null, ?string $password = null): void
    {
        $this->login(
            $browser,
            $email ?? 'admin@authservice.com',
            $password ?? 'password123'
        );
    }
}
