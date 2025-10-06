<?php

namespace Tests\Browser\Pages;

use Laravel\Dusk\Browser;
use Laravel\Dusk\Page;

class RegisterPage extends Page
{
    /**
     * Get the URL for the page.
     */
    public function url(): string
    {
        return '/register';
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
            '@name' => 'input[name="name"]',
            '@email' => 'input[name="email"]',
            '@password' => 'input[name="password"]',
            '@passwordConfirmation' => 'input[name="password_confirmation"]',
            '@submit' => 'button[type="submit"]',
            '@login' => 'a[href*="login"]',
            '@errorMessage' => '.alert-danger, [role="alert"]',
            '@successMessage' => '.alert-success',
        ];
    }

    /**
     * Register a new user.
     */
    public function register(
        Browser $browser,
        string $name,
        string $email,
        string $password
    ): void {
        $browser->type('@name', $name)
            ->type('@email', $email)
            ->type('@password', $password)
            ->type('@passwordConfirmation', $password)
            ->click('@submit')
            ->pause(500);
    }
}
