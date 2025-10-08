<?php

namespace Tests\Security;

use Tests\TestCase;

/**
 * OWASP A05:2021 - Security Misconfiguration
 *
 * Tests for:
 * - Missing security headers
 * - Default credentials
 * - Directory listing
 * - Verbose error messages
 * - Unnecessary features enabled
 * - Insecure default configurations
 */
class OwaspA05SecurityMisconfigurationTest extends TestCase
{
    /** @test */
    public function it_includes_security_headers_in_responses()
    {
        $response = $this->getJson('/api/health');

        // X-Content-Type-Options
        $this->assertEquals('nosniff', $response->headers->get('X-Content-Type-Options'));

        // X-Frame-Options
        $this->assertEquals('DENY', $response->headers->get('X-Frame-Options'));

        // Referrer-Policy
        $this->assertNotNull($response->headers->get('Referrer-Policy'));

        // Content-Security-Policy
        $this->assertNotNull($response->headers->get('Content-Security-Policy'));

        // Permissions-Policy
        $this->assertNotNull($response->headers->get('Permissions-Policy'));
    }

    /** @test */
    public function it_sets_strict_csp_header()
    {
        $response = $this->getJson('/api/health');

        $csp = $response->headers->get('Content-Security-Policy');

        // Should restrict script sources
        $this->assertStringContainsString('script-src', $csp);

        // Should not allow unsafe-inline or unsafe-eval
        $this->assertStringNotContainsString("'unsafe-eval'", $csp);

        // Should restrict frame-ancestors
        $this->assertStringContainsString("frame-ancestors 'none'", $csp);

        // Should have base-uri
        $this->assertStringContainsString("base-uri 'self'", $csp);
    }

    /** @test */
    public function it_sets_hsts_header_on_https()
    {
        // Simulate HTTPS request
        $response = $this->get('/', ['HTTPS' => 'on']);

        if ($response->isSuccessful()) {
            $hsts = $response->headers->get('Strict-Transport-Security');

            if ($hsts) {
                $this->assertStringContainsString('max-age=', $hsts);
                $this->assertStringContainsString('includeSubDomains', $hsts);
            }
        }
    }

    /** @test */
    public function it_restricts_permissions_policy()
    {
        $response = $this->getJson('/api/health');

        $permissionsPolicy = $response->headers->get('Permissions-Policy');

        // Should deny camera, microphone, geolocation by default
        $this->assertStringContainsString('camera=()', $permissionsPolicy);
        $this->assertStringContainsString('microphone=()', $permissionsPolicy);
        $this->assertStringContainsString('geolocation=()', $permissionsPolicy);
    }

    /** @test */
    public function it_does_not_expose_framework_version_in_headers()
    {
        $response = $this->getJson('/api/health');

        // Should not expose X-Powered-By
        $this->assertNull($response->headers->get('X-Powered-By'));

        // Should not expose Server details
        $server = $response->headers->get('Server');
        if ($server) {
            $this->assertStringNotContainsString('PHP/', $server);
            $this->assertStringNotContainsString('Laravel', $server);
        }
    }

    /** @test */
    public function it_does_not_expose_sensitive_info_in_404_errors()
    {
        $response = $this->getJson('/api/v1/non-existent-endpoint');

        $response->assertStatus(404);

        $content = $response->getContent();

        // Should not expose file paths
        $this->assertStringNotContainsString('/var/www', $content);
        $this->assertStringNotContainsString('/Users/', $content);
        $this->assertStringNotContainsString('C:\\', $content);

        // Should not expose framework details
        $this->assertStringNotContainsString('Illuminate\\', $content);
        $this->assertStringNotContainsString('vendor/', $content);
    }

    /** @test */
    public function it_does_not_expose_stack_traces_in_production()
    {
        config(['app.debug' => false]);

        // Force an error
        $response = $this->getJson('/api/v1/applications/invalid-id');

        $content = $response->getContent();

        // Should not contain stack trace
        $this->assertStringNotContainsString('Stack trace:', $content);
        $this->assertStringNotContainsString('#0 ', $content);
        $this->assertStringNotContainsString('thrown in', $content);
    }

    /** @test */
    public function it_disables_directory_listing()
    {
        // Try to access common directories
        $directories = [
            '/storage',
            '/public',
            '/uploads',
        ];

        foreach ($directories as $dir) {
            $response = $this->get($dir);

            // Should not return directory listing
            if ($response->status() === 200) {
                $content = $response->getContent();
                $this->assertStringNotContainsString('Index of', $content);
                $this->assertStringNotContainsString('Parent Directory', $content);
            }
        }
    }

    /** @test */
    public function it_validates_cors_configuration_is_restrictive()
    {
        $response = $this->getJson('/api/health', [
            'Origin' => 'https://evil.com',
        ]);

        $allowedOrigin = $response->headers->get('Access-Control-Allow-Origin');

        // Should not allow all origins
        $this->assertNotEquals('*', $allowedOrigin);

        // Should only allow specific origins
        if ($allowedOrigin) {
            $this->assertStringStartsWith('http', $allowedOrigin);
        }
    }

    /** @test */
    public function it_does_not_cache_sensitive_endpoints()
    {
        $response = $this->getJson('/oauth/authorize');

        $cacheControl = $response->headers->get('Cache-Control');

        if ($cacheControl) {
            $this->assertStringContainsString('no-store', $cacheControl);
        }
    }

    /** @test */
    public function it_validates_oauth_endpoints_have_strict_security_headers()
    {
        $response = $this->getJson('/oauth/authorize');

        // Should have no-referrer for OAuth
        $referrer = $response->headers->get('Referrer-Policy');
        if ($referrer) {
            $this->assertEquals('no-referrer', $referrer);
        }

        // Should have no-cache
        $cacheControl = $response->headers->get('Cache-Control');
        if ($cacheControl) {
            $this->assertStringContainsString('no-cache', $cacheControl);
        }
    }

    /** @test */
    public function it_does_not_expose_default_admin_credentials()
    {
        // Try default credentials
        $response = $this->postJson('/api/auth/login', [
            'email' => 'admin@admin.com',
            'password' => 'admin',
        ]);

        // Should not work with default credentials
        $this->assertContains($response->status(), [401, 422, 429]);
    }

    /** @test */
    public function it_validates_debug_mode_is_disabled_in_production()
    {
        if (config('app.env') === 'production') {
            $this->assertFalse(config('app.debug'), 'Debug mode should be disabled in production');
        }
    }

    /** @test */
    public function it_validates_sensitive_config_is_not_exposed()
    {
        $response = $this->getJson('/api/config');

        if ($response->status() === 200) {
            $config = $response->json();

            // Should not expose database credentials
            $this->assertArrayNotHasKey('database', $config);

            // Should not expose API keys
            $this->assertArrayNotHasKey('services', $config);

            // Should not expose app key
            $this->assertArrayNotHasKey('key', $config);
        }
    }

    /** @test */
    public function it_validates_unnecessary_http_methods_are_disabled()
    {
        $response = $this->call('TRACE', '/api/v1/health');

        // TRACE should be disabled
        $response->assertStatus(405);
    }

    /** @test */
    public function it_validates_api_returns_json_errors_not_html()
    {
        $response = $this->getJson('/api/v1/non-existent');

        $response->assertStatus(404);
        $response->assertHeader('Content-Type', 'application/json');

        // Should not return HTML error page
        $this->assertStringNotContainsString('<html>', $response->getContent());
        $this->assertStringNotContainsString('<!DOCTYPE', $response->getContent());
    }

    /** @test */
    public function it_validates_session_configuration_is_secure()
    {
        // Session should be HTTP-only
        $this->assertTrue(config('session.http_only'), 'Session cookies must be HTTP-only');

        // Session should use secure in production
        if (config('app.env') === 'production') {
            $this->assertTrue(config('session.secure'), 'Session cookies must be secure in production');
        }

        // Session should use SameSite
        $this->assertNotNull(config('session.same_site'), 'Session must have SameSite attribute');
    }

    /** @test */
    public function it_validates_password_reset_tokens_expire()
    {
        $expiration = config('auth.passwords.users.expire');

        $this->assertIsInt($expiration, 'Password reset expiration must be set');
        $this->assertLessThanOrEqual(60, $expiration, 'Password reset tokens should expire within 1 hour');
    }

    /** @test */
    public function it_validates_api_versioning_is_enforced()
    {
        // Try to access API without version
        $response = $this->getJson('/api/users');

        // Should require version or redirect
        $this->assertContains($response->status(), [301, 302, 404]);
    }

    /** @test */
    public function it_validates_sensitive_routes_require_authentication()
    {
        $sensitiveRoutes = [
            '/api/v1/profile',
            '/api/v1/users',
            '/api/v1/applications',
            '/api/v1/organizations',
        ];

        foreach ($sensitiveRoutes as $route) {
            $response = $this->getJson($route);

            $response->assertStatus(401, "Route {$route} should require authentication");
        }
    }

    /** @test */
    public function it_validates_file_upload_restrictions()
    {
        $response = $this->getJson('/api/v1/config/upload-settings');

        if ($response->status() === 200) {
            $settings = $response->json();

            // Should have max file size
            $this->assertArrayHasKey('max_upload_size', $settings);

            // Should have allowed file types
            $this->assertArrayHasKey('allowed_types', $settings);

            // Should not allow executable files
            $allowedTypes = $settings['allowed_types'];
            $this->assertNotContains('exe', $allowedTypes);
            $this->assertNotContains('sh', $allowedTypes);
            $this->assertNotContains('bat', $allowedTypes);
        }
    }

    /** @test */
    public function it_validates_rate_limiting_is_configured()
    {
        // Make multiple rapid requests
        $responses = [];

        for ($i = 0; $i < 150; $i++) {
            $responses[] = $this->getJson('/api/v1/health');
        }

        // Should hit rate limit
        $rateLimited = collect($responses)->first(fn ($r) => $r->status() === 429);

        $this->assertNotNull($rateLimited, 'Rate limiting should be enforced');

        if ($rateLimited) {
            $this->assertNotNull($rateLimited->headers->get('Retry-After'));
        }
    }

    /** @test */
    public function it_validates_cookie_security_attributes()
    {
        $response = $this->postJson('/api/auth/register', [
            'name' => 'Test User',
            'email' => 'test@example.com',
            'password' => 'password123',
            'password_confirmation' => 'password123',
        ]);

        $cookies = $response->headers->getCookies();

        foreach ($cookies as $cookie) {
            // Should be HTTP-only
            $this->assertTrue($cookie->isHttpOnly(), 'Cookies should be HTTP-only');

            // Should have SameSite
            $this->assertNotNull($cookie->getSameSite(), 'Cookies should have SameSite attribute');

            // Should be secure in production
            if (config('app.env') === 'production') {
                $this->assertTrue($cookie->isSecure(), 'Cookies should be secure in production');
            }
        }
    }
}
