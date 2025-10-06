<?php

namespace Tests\Browser\Pages;

use Laravel\Dusk\Browser;
use Laravel\Dusk\Page;

class MFASetupPage extends Page
{
    /**
     * Get the URL for the page.
     */
    public function url(): string
    {
        return '/mfa/setup';
    }

    /**
     * Assert that the browser is on the page.
     */
    public function assert(Browser $browser): void
    {
        $browser->assertPathBeginsWith('/mfa');
    }

    /**
     * Get the element shortcuts for the page.
     */
    public function elements(): array
    {
        return [
            '@qrCode' => '#qr-code, [data-qr-code], img[alt*="QR"]',
            '@secretKey' => '#secret-key, [data-secret-key]',
            '@verificationCode' => 'input[name="code"], input[name="verification_code"]',
            '@enableButton' => 'button[type="submit"], button:contains("Enable")',
            '@cancelButton' => 'a:contains("Cancel"), button:contains("Cancel")',
            '@errorMessage' => '.alert-danger, [role="alert"]',
            '@successMessage' => '.alert-success',
        ];
    }

    /**
     * Verify MFA code.
     */
    public function verifyCode(Browser $browser, string $code): void
    {
        $browser->type('@verificationCode', $code)
            ->click('@enableButton')
            ->pause(500);
    }

    /**
     * Get the secret key from the page.
     */
    public function getSecretKey(Browser $browser): string
    {
        return $browser->text('@secretKey');
    }
}
