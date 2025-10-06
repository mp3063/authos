<?php

namespace Tests\Browser\OAuth;

use App\Models\User;
use Illuminate\Foundation\Testing\DatabaseMigrations;
use Laravel\Dusk\Browser;
use Laravel\Passport\Client;
use Tests\Browser\Helpers\BrowserTestHelpers;
use Tests\Browser\Pages\LoginPage;
use Tests\Browser\Pages\OAuthAuthorizePage;
use Tests\DuskTestCase;

class AuthorizationFlowTest extends DuskTestCase
{
    use BrowserTestHelpers, DatabaseMigrations;

    private Client $client;

    protected function setUp(): void
    {
        parent::setUp();

        $this->artisan('passport:keys');
        $this->artisan('passport:client', [
            '--personal' => true,
            '--name' => 'Test Personal Access Client',
        ]);
    }

    /**
     * Test complete OAuth authorization code flow.
     */
    public function test_complete_oauth_authorization_code_flow(): void
    {
        $user = $this->createTestUser();
        $client = Client::factory()->create([
            'user_id' => $user->id,
            'name' => 'Test Application',
            'redirect' => 'http://localhost:3000/callback',
            'personal_access_client' => false,
            'password_client' => false,
            'revoked' => false,
        ]);

        $this->browse(function (Browser $browser) use ($user, $client) {
            // Visit authorization endpoint
            $authUrl = '/oauth/authorize?'.http_build_query([
                'client_id' => $client->id,
                'redirect_uri' => $client->redirect,
                'response_type' => 'code',
                'scope' => 'read-user',
            ]);

            $browser->visit($authUrl);

            // Should redirect to login if not authenticated
            $browser->on(new LoginPage)
                ->login($user->email, 'password123')
                ->waitForLocation('/oauth/authorize', 10);

            // Should show authorization page
            $browser->on(new OAuthAuthorizePage)
                ->assertSee('Test Application')
                ->assertVisible('@authorizeButton')
                ->assertVisible('@denyButton')
                ->authorize()
                ->pause(1000);

            // Should redirect to callback URL with code
            $currentUrl = $browser->driver->getCurrentURL();
            $this->assertStringContainsString('code=', $currentUrl);
            $this->assertStringContainsString($client->redirect, $currentUrl);
        });
    }

    /**
     * Test OAuth authorization with PKCE.
     */
    public function test_oauth_authorization_with_pkce(): void
    {
        $user = $this->createTestUser();
        $client = Client::factory()->create([
            'user_id' => $user->id,
            'name' => 'PKCE Application',
            'redirect' => 'http://localhost:3000/callback',
        ]);

        $codeVerifier = bin2hex(random_bytes(32));
        $codeChallenge = rtrim(strtr(base64_encode(hash('sha256', $codeVerifier, true)), '+/', '-_'), '=');

        $this->browse(function (Browser $browser) use ($user, $client, $codeChallenge) {
            $authUrl = '/oauth/authorize?'.http_build_query([
                'client_id' => $client->id,
                'redirect_uri' => $client->redirect,
                'response_type' => 'code',
                'scope' => 'read-user',
                'code_challenge' => $codeChallenge,
                'code_challenge_method' => 'S256',
            ]);

            $this->loginAs($browser, $user);

            $browser->visit($authUrl)
                ->on(new OAuthAuthorizePage)
                ->authorize()
                ->pause(1000);

            $currentUrl = $browser->driver->getCurrentURL();
            $this->assertStringContainsString('code=', $currentUrl);
        });
    }

    /**
     * Test user can deny authorization.
     */
    public function test_user_can_deny_authorization(): void
    {
        $user = $this->createTestUser();
        $client = Client::factory()->create([
            'user_id' => $user->id,
            'name' => 'Test Application',
            'redirect' => 'http://localhost:3000/callback',
        ]);

        $this->browse(function (Browser $browser) use ($user, $client) {
            $authUrl = '/oauth/authorize?'.http_build_query([
                'client_id' => $client->id,
                'redirect_uri' => $client->redirect,
                'response_type' => 'code',
                'scope' => 'read-user',
            ]);

            $this->loginAs($browser, $user);

            $browser->visit($authUrl)
                ->on(new OAuthAuthorizePage)
                ->deny()
                ->pause(1000);

            $currentUrl = $browser->driver->getCurrentURL();
            $this->assertStringContainsString('error=access_denied', $currentUrl);
        });
    }

    /**
     * Test authorization requires authentication.
     */
    public function test_authorization_requires_authentication(): void
    {
        $client = Client::factory()->create([
            'name' => 'Test Application',
            'redirect' => 'http://localhost:3000/callback',
        ]);

        $this->browse(function (Browser $browser) use ($client) {
            $authUrl = '/oauth/authorize?'.http_build_query([
                'client_id' => $client->id,
                'redirect_uri' => $client->redirect,
                'response_type' => 'code',
            ]);

            $browser->visit($authUrl)
                ->waitForLocation('/login', 5)
                ->assertPathIs('/login');
        });
    }

    /**
     * Test authorization with invalid client.
     */
    public function test_authorization_with_invalid_client(): void
    {
        $user = $this->createTestUser();

        $this->browse(function (Browser $browser) use ($user) {
            $this->loginAs($browser, $user);

            $authUrl = '/oauth/authorize?'.http_build_query([
                'client_id' => 'invalid-client-id',
                'redirect_uri' => 'http://localhost:3000/callback',
                'response_type' => 'code',
            ]);

            $browser->visit($authUrl)
                ->pause(500)
                ->assertSee('error');
        });
    }
}
