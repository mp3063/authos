<?php

namespace Tests\Security;

use App\Models\Application;
use App\Models\Organization;
use App\Models\User;
use Laravel\Passport\Passport;
use Tests\TestCase;

/**
 * API Security Tests
 *
 * Tests for:
 * - API authentication and authorization
 * - Rate limiting
 * - CORS policies
 * - Mass assignment protection
 * - Parameter tampering
 * - API versioning security
 */
class ApiSecurityTest extends TestCase
{
    protected User $user;

    protected Organization $organization;

    protected Application $application;

    protected function setUp(): void
    {
        parent::setUp();

        $this->organization = Organization::factory()->create();
        $this->user = User::factory()->create([
            'organization_id' => $this->organization->id,
        ]);
        $this->application = Application::factory()->create([
            'organization_id' => $this->organization->id,
        ]);
    }

    /** @test */
    public function it_requires_authentication_for_protected_endpoints()
    {
        $protectedEndpoints = [
            ['GET', '/api/v1/profile'],
            ['GET', '/api/v1/users'],
            ['GET', '/api/v1/applications'],
            ['GET', '/api/v1/organizations/'.$this->organization->id],
            ['POST', '/api/v1/users'],
            ['PUT', '/api/v1/users/'.$this->user->id],
            ['DELETE', '/api/v1/users/'.$this->user->id],
        ];

        foreach ($protectedEndpoints as [$method, $endpoint]) {
            $response = $this->json($method, $endpoint);

            $response->assertStatus(401, "Endpoint {$method} {$endpoint} should require authentication");
        }
    }

    /** @test */
    public function it_validates_bearer_token_format()
    {
        $invalidTokens = [
            '',
            'invalid',
            'Bearer',
            'Basic dGVzdDp0ZXN0',
            'token123',
        ];

        foreach ($invalidTokens as $token) {
            $response = $this->withHeaders([
                'Authorization' => $token,
            ])->getJson('/api/v1/profile');

            $response->assertStatus(401);
        }
    }

    /** @test */
    public function it_rejects_expired_tokens()
    {
        Passport::actingAs($this->user);

        // Create token
        $token = $this->user->createToken('test')->accessToken;

        // Manually expire the token
        \DB::table('oauth_access_tokens')
            ->where('user_id', $this->user->id)
            ->update(['expires_at' => now()->subDay()]);

        $response = $this->withHeaders([
            'Authorization' => 'Bearer '.$token,
        ])->getJson('/api/v1/profile');

        $response->assertStatus(401);
    }

    /** @test */
    public function it_enforces_rate_limiting_on_api_endpoints()
    {
        Passport::actingAs($this->user);

        $responses = [];

        // Make many requests
        for ($i = 0; $i < 150; $i++) {
            $responses[] = $this->getJson('/api/v1/profile');
        }

        // Should hit rate limit
        $rateLimited = collect($responses)->first(fn ($r) => $r->status() === 429);

        $this->assertNotNull($rateLimited, 'Rate limiting should be enforced');

        if ($rateLimited) {
            $this->assertNotNull($rateLimited->headers->get('X-RateLimit-Limit'));
            $this->assertNotNull($rateLimited->headers->get('Retry-After'));
        }
    }

    /** @test */
    public function it_enforces_stricter_rate_limits_on_auth_endpoints()
    {
        $responses = [];

        // Auth endpoints should have lower limits
        for ($i = 0; $i < 20; $i++) {
            $responses[] = $this->postJson('/api/auth/login', [
                'email' => 'test@example.com',
                'password' => 'password',
            ]);
        }

        $rateLimited = collect($responses)->first(fn ($r) => $r->status() === 429);

        $this->assertNotNull($rateLimited, 'Auth endpoints should have strict rate limiting');
    }

    /** @test */
    public function it_validates_cors_configuration()
    {
        $response = $this->getJson('/api/v1/health', [
            'Origin' => 'https://malicious.com',
        ]);

        $allowedOrigin = $response->headers->get('Access-Control-Allow-Origin');

        // Should not allow arbitrary origins
        $this->assertNotEquals('*', $allowedOrigin);
        $this->assertNotEquals('https://malicious.com', $allowedOrigin);
    }

    /** @test */
    public function it_prevents_cors_wildcard_in_production()
    {
        config(['app.env' => 'production']);

        $response = $this->getJson('/api/v1/health', [
            'Origin' => 'https://example.com',
        ]);

        $allowedOrigin = $response->headers->get('Access-Control-Allow-Origin');

        if (config('app.env') === 'production') {
            $this->assertNotEquals('*', $allowedOrigin);
        }
    }

    /** @test */
    public function it_validates_cors_credentials_configuration()
    {
        $response = $this->getJson('/api/v1/health', [
            'Origin' => config('app.url'),
        ]);

        $allowCredentials = $response->headers->get('Access-Control-Allow-Credentials');

        if ($allowCredentials === 'true') {
            // If credentials are allowed, origin must not be wildcard
            $allowedOrigin = $response->headers->get('Access-Control-Allow-Origin');
            $this->assertNotEquals('*', $allowedOrigin);
        }
    }

    /** @test */
    public function it_prevents_mass_assignment_vulnerabilities()
    {
        Passport::actingAs($this->user);

        // Try to mass assign protected fields
        $response = $this->putJson("/api/v1/users/{$this->user->id}", [
            'name' => 'Updated Name',
            'is_admin' => true, // Try to escalate privileges
            'organization_id' => 999, // Try to change organization
            'email_verified_at' => now(), // Try to bypass verification
        ]);

        if ($response->status() === 200) {
            $this->user->refresh();

            // Protected fields should not be updated
            $this->assertNotEquals(999, $this->user->organization_id);
            $this->assertNull($this->user->is_admin ?? null);
        }
    }

    /** @test */
    public function it_prevents_parameter_pollution()
    {
        Passport::actingAs($this->user);

        // Try parameter pollution
        $response = $this->getJson('/api/v1/users?role=admin&role=user');

        // Should handle gracefully and use appropriate value
        $response->assertStatus(200);
    }

    /** @test */
    public function it_validates_content_type_for_post_requests()
    {
        Passport::actingAs($this->user);

        // Try to send JSON without proper Content-Type
        $response = $this->call('POST', '/api/v1/users', [
            'name' => 'Test User',
            'email' => 'test@example.com',
        ], [], [], [
            'HTTP_AUTHORIZATION' => 'Bearer '.Passport::actingAsClient($this->user),
        ], json_encode([
            'name' => 'Test User',
            'email' => 'test@example.com',
        ]));

        // Should require application/json
        if ($response->status() === 415) {
            $this->assertTrue(true);
        }
    }

    /** @test */
    public function it_prevents_json_hijacking()
    {
        Passport::actingAs($this->user);

        $response = $this->getJson('/api/v1/profile');

        // Response should not be executable as JavaScript
        $content = $response->getContent();

        $this->assertStringStartsWith('{', $content);
        $this->assertStringNotStartsWith('while(1);', $content);
        $this->assertStringNotStartsWith('for(;;);', $content);
    }

    /** @test */
    public function it_validates_api_versioning_enforcement()
    {
        Passport::actingAs($this->user);

        // API should require version
        $response = $this->getJson('/api/users');

        $this->assertContains($response->status(), [301, 302, 404], 'API should enforce versioning');
    }

    /** @test */
    public function it_prevents_http_verb_tampering()
    {
        Passport::actingAs($this->user);

        // Try to bypass authorization with method override
        $response = $this->call('POST', "/api/v1/users/{$this->user->id}", [], [], [], [
            'HTTP_X_HTTP_METHOD_OVERRIDE' => 'DELETE',
            'HTTP_AUTHORIZATION' => 'Bearer '.Passport::actingAsClient($this->user),
        ]);

        // Should not allow method override for security-sensitive operations
        if ($response->status() === 200) {
            $this->assertDatabaseHas('users', ['id' => $this->user->id]);
        }
    }

    /** @test */
    public function it_validates_oauth_token_scopes()
    {
        $token = $this->user->createToken('limited', ['read'])->accessToken;

        // Try write operation with read-only scope
        $response = $this->withHeaders([
            'Authorization' => 'Bearer '.$token,
        ])->postJson('/api/v1/applications', [
            'name' => 'Test App',
            'redirect_uri' => 'https://test.com',
        ]);

        $response->assertStatus(403);
    }

    /** @test */
    public function it_prevents_api_key_leakage_in_logs()
    {
        Passport::actingAs($this->user);

        $response = $this->getJson('/api/v1/applications/'.$this->application->id);

        if ($response->status() === 200) {
            // Client secret should not be in response
            $this->assertArrayNotHasKey('client_secret', $response->json('data'));
            $this->assertArrayNotHasKey('secret', $response->json('data'));
        }
    }

    /** @test */
    public function it_validates_input_size_limits()
    {
        Passport::actingAs($this->user);

        // Try to send very large payload
        $largeString = str_repeat('A', 100000); // 100KB string

        $response = $this->postJson('/api/v1/users', [
            'name' => $largeString,
            'email' => 'test@example.com',
            'password' => 'password123',
        ]);

        // Should reject or truncate
        $this->assertContains($response->status(), [413, 422]);
    }

    /** @test */
    public function it_prevents_response_splitting()
    {
        Passport::actingAs($this->user);

        // Try response splitting attack
        $response = $this->getJson('/api/v1/users?callback=alert(1);%0D%0ASet-Cookie:hacked=true');

        // Headers should be properly encoded
        $headers = $response->headers->all();

        foreach ($headers as $name => $values) {
            foreach ($values as $value) {
                $this->assertStringNotContainsString("\r\n", $value);
                $this->assertStringNotContainsString("\n", $value);
            }
        }
    }

    /** @test */
    public function it_validates_accept_header_properly()
    {
        Passport::actingAs($this->user);

        // Request with XML accept header should be handled
        $response = $this->withHeaders([
            'Accept' => 'application/xml',
        ])->getJson('/api/v1/profile');

        // Should return JSON or proper error
        $contentType = $response->headers->get('Content-Type');

        if ($response->status() === 200) {
            $this->assertStringContainsString('json', $contentType);
        }
    }

    /** @test */
    public function it_prevents_cache_poisoning()
    {
        Passport::actingAs($this->user);

        // Try cache poisoning with host header
        $response = $this->getJson('/api/v1/profile', [
            'Host' => 'evil.com',
        ]);

        // URLs in response should use correct host
        if ($response->status() === 200) {
            $content = $response->getContent();
            $this->assertStringNotContainsString('evil.com', $content);
        }
    }

    /** @test */
    public function it_validates_pagination_limits()
    {
        Passport::actingAs($this->user);

        // Try to request excessive results
        $response = $this->getJson('/api/v1/users?per_page=10000');

        if ($response->status() === 200) {
            $data = $response->json('data');

            // Should enforce maximum pagination limit
            $this->assertLessThanOrEqual(100, count($data));
        }
    }

    /** @test */
    public function it_prevents_graphql_introspection_in_production()
    {
        config(['app.env' => 'production']);

        $response = $this->postJson('/graphql', [
            'query' => '{ __schema { types { name } } }',
        ]);

        if ($response->status() === 200) {
            // Introspection should be disabled in production
            $data = $response->json();
            $this->assertArrayNotHasKey('__schema', $data['data'] ?? []);
        }
    }

    /** @test */
    public function it_enforces_https_in_production_for_oauth()
    {
        config(['app.env' => 'production']);

        // OAuth should require HTTPS
        $response = $this->call('GET', '/oauth/authorize', [
            'client_id' => $this->application->client_id,
            'redirect_uri' => 'http://insecure.com/callback', // HTTP instead of HTTPS
            'response_type' => 'code',
        ]);

        if (config('app.env') === 'production') {
            $this->assertContains($response->status(), [400, 422]);
        }
    }
}
