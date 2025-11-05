<?php

namespace Tests\Integration;

use App\Models\Application;
use App\Models\Organization;
use App\Models\User;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\Notification;
use Laravel\Passport\Passport;
use Tests\TestCase;

/**
 * Base test case for all Integration (E2E) tests
 *
 * Integration tests verify complete user flows by making real HTTP requests
 * to the API and verifying both the HTTP response and side effects (database,
 * events, notifications, etc.).
 *
 * Key differences from Unit tests:
 * - Tests complete flows (multiple HTTP requests in sequence)
 * - Tests real database interactions (not mocked)
 * - Verifies side effects (audit logs, notifications, webhooks)
 * - Uses real Passport OAuth tokens (not mocked)
 *
 * Usage:
 *
 *     class OAuthFlowTest extends IntegrationTestCase
 *     {
 *         public function test_complete_authorization_code_flow()
 *         {
 *             // ARRANGE: Set up test data
 *             $user = $this->createUser();
 *             $app = $this->createApplication();
 *
 *             // ACT: Request authorization
 *             $response = $this->actingAs($user)->get('/oauth/authorize', [...]);
 *
 *             // ASSERT: Verify response
 *             $response->assertRedirect();
 *
 *             // ACT: Exchange code for token
 *             $tokenResponse = $this->post('/oauth/token', [...]);
 *
 *             // ASSERT: Verify token response
 *             $tokenResponse->assertOk();
 *
 *             // ASSERT: Verify side effects
 *             $this->assertDatabaseHas('authentication_logs', [...]);
 *         }
 *     }
 *
 * @see Tests\TestCase Base test case with core helper methods
 */
abstract class IntegrationTestCase extends TestCase
{
    use RefreshDatabase;

    /**
     * Set up integration test environment
     */
    protected function setUp(): void
    {
        parent::setUp();

        // Fake notifications by default to prevent actual email sending
        // Individual tests can override this if they need to test notification content
        Notification::fake();
    }

    /**
     * Create an OAuth Application for testing
     *
     * @param  array  $attributes  Override default attributes
     * @param  Organization|null  $organization  Organization to associate with
     * @return Application
     */
    protected function createOAuthApplication(array $attributes = [], ?Organization $organization = null): Application
    {
        if (! $organization && ! isset($attributes['organization_id'])) {
            $organization = $this->createOrganization();
            $attributes['organization_id'] = $organization->id;
        }

        return Application::factory()->create($attributes);
    }

    /**
     * Create an authenticated API request with OAuth token
     *
     * @param  User  $user  User to authenticate as
     * @param  array  $scopes  OAuth scopes (default: ['*'])
     * @return $this
     */
    protected function actingAsApiUserWithToken(User $user, array $scopes = ['*']): static
    {
        Passport::actingAs($user, $scopes);

        return $this;
    }

    /**
     * Create and return a valid OAuth access token for a user
     *
     * @param  User  $user  User to create token for
     * @param  array  $scopes  OAuth scopes (default: ['*'])
     * @return string Access token string
     */
    protected function generateAccessToken(User $user, array $scopes = ['*']): string
    {
        return $this->createAccessToken($user, $scopes);
    }

    /**
     * Helper to assert authentication log entry exists
     *
     * @param  array  $attributes  Attributes to check
     */
    protected function assertAuthenticationLogged(array $attributes): void
    {
        $this->assertDatabaseHas('authentication_logs', $attributes);
    }

    /**
     * Helper to assert webhook delivery was created
     *
     * @param  array  $attributes  Attributes to check
     */
    protected function assertWebhookDeliveryCreated(array $attributes): void
    {
        $this->assertDatabaseHas('webhook_deliveries', $attributes);
    }

    /**
     * Helper to assert security incident was created
     *
     * @param  array  $attributes  Attributes to check
     */
    protected function assertSecurityIncidentCreated(array $attributes): void
    {
        $this->assertDatabaseHas('security_incidents', $attributes);
    }

    /**
     * Helper to assert notification was sent to a user
     *
     * @param  User  $user  User who should have received notification
     * @param  string  $notificationClass  Full class name of notification
     */
    protected function assertNotificationSentTo(User $user, string $notificationClass): void
    {
        Notification::assertSentTo($user, $notificationClass);
    }

    /**
     * Helper to assert no notifications were sent
     */
    protected function assertNoNotificationsSent(): void
    {
        Notification::assertNothingSent();
    }

    /**
     * Helper to simulate failed login attempts for testing lockout
     *
     * @param  string  $email  Email to use for login attempts
     * @param  int  $attempts  Number of failed attempts
     */
    protected function simulateFailedLoginAttempts(string $email, int $attempts = 3): void
    {
        for ($i = 0; $i < $attempts; $i++) {
            $this->postJson('/api/v1/auth/login', [
                'email' => $email,
                'password' => 'wrong-password',
            ]);
        }
    }

    /**
     * Helper to generate PKCE code verifier and challenge
     *
     * @param  string  $method  'S256' or 'plain'
     * @return array ['verifier' => string, 'challenge' => string]
     */
    protected function generatePkceChallenge(string $method = 'S256'): array
    {
        $verifier = \Illuminate\Support\Str::random(64);

        if ($method === 'S256') {
            $challenge = rtrim(
                strtr(base64_encode(hash('sha256', $verifier, true)), '+/', '-_'),
                '='
            );
        } else {
            $challenge = $verifier;
        }

        return [
            'verifier' => $verifier,
            'challenge' => $challenge,
        ];
    }

    /**
     * Helper to create complete OAuth flow parameters
     *
     * @param  Application  $app  Application to create parameters for
     * @param  bool  $usePkce  Whether to include PKCE challenge
     * @return array
     */
    protected function generateOAuthParameters(Application $app, bool $usePkce = true): array
    {
        $params = [
            'client_id' => $app->client_id,
            'redirect_uri' => $app->redirect_uris[0] ?? 'https://example.com/callback',
            'response_type' => 'code',
            'state' => \Illuminate\Support\Str::random(40),
            'scope' => '*',
        ];

        if ($usePkce) {
            $pkce = $this->generatePkceChallenge();
            $params['code_challenge'] = $pkce['challenge'];
            $params['code_challenge_method'] = 'S256';
            $params['code_verifier'] = $pkce['verifier'];
        }

        return $params;
    }

    /**
     * Helper to assert JSON response has exact structure (no extra keys)
     *
     * @param  array  $structure  Expected structure
     * @param  array|null  $json  JSON to check (defaults to last response)
     */
    protected function assertJsonStructureExact(array $structure, $json = null): void
    {
        parent::assertJsonStructureExact($structure, $json);
    }

    /**
     * Helper to assert response has security headers
     */
    protected function assertHasSecurityHeaders(): void
    {
        $this->assertTrue(
            $this->response->headers->has('X-Frame-Options'),
            'Response missing X-Frame-Options header'
        );
        $this->assertTrue(
            $this->response->headers->has('X-Content-Type-Options'),
            'Response missing X-Content-Type-Options header'
        );
        $this->assertTrue(
            $this->response->headers->has('Strict-Transport-Security'),
            'Response missing Strict-Transport-Security header'
        );
    }

    /**
     * Helper to assert organization boundary isolation
     *
     * @param  User  $user  User attempting access
     * @param  string  $url  URL to test
     * @param  string  $method  HTTP method (default: GET)
     */
    protected function assertOrganizationBoundaryEnforced(User $user, string $url, string $method = 'GET'): void
    {
        $response = $this->actingAs($user)->json($method, $url);

        // Should return 404 (not 403!) to prevent information leakage
        $response->assertNotFound();
    }

    /**
     * Helper to wait for a condition (useful for async operations)
     *
     * @param  callable  $callback  Condition to wait for
     * @param  int  $timeout  Maximum seconds to wait
     * @param  int  $interval  Milliseconds between checks
     */
    protected function waitFor(callable $callback, int $timeout = 5, int $interval = 100): bool
    {
        $start = microtime(true);

        while ((microtime(true) - $start) < $timeout) {
            if ($callback()) {
                return true;
            }

            usleep($interval * 1000);
        }

        return false;
    }
}
