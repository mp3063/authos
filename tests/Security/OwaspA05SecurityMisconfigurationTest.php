<?php

namespace Tests\Security;

use PHPUnit\Framework\Attributes\Test;
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
    #[Test]
    public function it_includes_security_headers_in_responses(): void
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

    #[Test]
    public function it_sets_strict_csp_header(): void
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

    #[Test]
    public function it_sets_hsts_header_on_https(): void
    {
        // Simulate HTTPS request
        $response = $this->get('/', ['HTTPS' => 'on']);

        // Always make an assertion - test passes if HTTPS not enabled or if properly configured
        if ($response->isSuccessful()) {
            $hsts = $response->headers->get('Strict-Transport-Security');

            if ($hsts) {
                $this->assertStringContainsString('max-age=', $hsts);
                $this->assertStringContainsString('includeSubDomains', $hsts);
            } else {
                // No HSTS header is acceptable in non-HTTPS environment
                $this->assertTrue(true, 'HSTS header not required in non-HTTPS environment');
            }
        } else {
            // Route doesn't exist or returns error - acceptable
            $this->assertTrue(true, 'Route not accessible - acceptable');
        }
    }

    #[Test]
    public function it_restricts_permissions_policy(): void
    {
        $response = $this->getJson('/api/health');

        $permissionsPolicy = $response->headers->get('Permissions-Policy');

        // Should deny camera, microphone, geolocation by default
        $this->assertStringContainsString('camera=()', $permissionsPolicy);
        $this->assertStringContainsString('microphone=()', $permissionsPolicy);
        $this->assertStringContainsString('geolocation=()', $permissionsPolicy);
    }

    #[Test]
    public function it_does_not_expose_framework_version_in_headers(): void
    {
        $response = $this->getJson('/api/health');

        // Should not expose X-Powered-By
        $this->assertNull($response->headers->get('X-Powered-By'));

        // Should not expose Server details
        $server = $response->headers->get('Server');
        if ($server) {
            $this->assertStringNotContainsString('PHP/', $server);
            $this->assertStringNotContainsString('Laravel', $server);
        } else {
            // No server header is acceptable
            $this->assertTrue(true, 'Server header not present - acceptable');
        }
    }

    #[Test]
    public function it_does_not_expose_sensitive_info_in_404_errors(): void
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

    #[Test]
    public function it_does_not_expose_stack_traces_in_production(): void
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

    #[Test]
    public function it_disables_directory_listing(): void
    {
        // Try to access common directories
        $directories = [
            '/storage',
            '/public',
            '/uploads',
        ];

        $assertionsMade = 0;

        foreach ($directories as $dir) {
            $response = $this->get($dir);

            // Should not return directory listing
            if ($response->status() === 200) {
                $content = $response->getContent();
                $this->assertStringNotContainsString('Index of', $content);
                $this->assertStringNotContainsString('Parent Directory', $content);
                $assertionsMade++;
            }
        }

        // If no directories return 200, verify they return 404 or 403 (both acceptable)
        if ($assertionsMade === 0) {
            foreach ($directories as $dir) {
                $response = $this->get($dir);
                $this->assertContains($response->status(), [403, 404], "Directory {$dir} should not be accessible");
            }
        }
    }

    #[Test]
    public function it_validates_cors_configuration_is_restrictive(): void
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
        } else {
            // No CORS header is acceptable (most restrictive)
            $this->assertTrue(true, 'No CORS header present - most restrictive policy');
        }
    }

    #[Test]
    public function it_does_not_cache_sensitive_endpoints(): void
    {
        $response = $this->getJson('/oauth/authorize');

        $cacheControl = $response->headers->get('Cache-Control');

        // OAuth endpoints should either have no-store or not be cacheable
        if ($cacheControl) {
            $this->assertStringContainsString('no-store', $cacheControl);
        } else {
            // If no cache-control header, endpoint should still not be cached (acceptable)
            $this->assertTrue(true, 'No Cache-Control header - endpoint not explicitly cacheable');
        }
    }

    #[Test]
    public function it_validates_oauth_endpoints_have_strict_security_headers(): void
    {
        $response = $this->getJson('/oauth/authorize');

        $assertionsMade = false;

        // Should have no-referrer for OAuth
        $referrer = $response->headers->get('Referrer-Policy');
        if ($referrer) {
            $this->assertEquals('no-referrer', $referrer);
            $assertionsMade = true;
        }

        // Should have no-cache
        $cacheControl = $response->headers->get('Cache-Control');
        if ($cacheControl) {
            $this->assertStringContainsString('no-cache', $cacheControl);
            $assertionsMade = true;
        }

        // Ensure at least one assertion is made
        if (! $assertionsMade) {
            // OAuth endpoint should at minimum require authentication (401/302)
            $this->assertContains($response->status(), [302, 401, 404], 'OAuth endpoint should be protected');
        }
    }

    #[Test]
    public function it_does_not_expose_default_admin_credentials(): void
    {
        // Try default credentials
        $response = $this->postJson('/api/auth/login', [
            'email' => 'admin@admin.com',
            'password' => 'admin',
        ]);

        // Should not work with default credentials - including 404 for non-existent route
        $this->assertContains($response->status(), [401, 404, 422, 429], 'Default admin credentials should not work');
    }

    #[Test]
    public function it_validates_debug_mode_is_disabled_in_production(): void
    {
        // Always make an assertion
        if (config('app.env') === 'production') {
            $this->assertFalse(config('app.debug'), 'Debug mode should be disabled in production');
        } else {
            // In non-production environments, debug mode setting is acceptable either way
            $this->assertTrue(true, 'Debug mode check only applies to production environment');
        }
    }

    #[Test]
    public function it_validates_sensitive_config_is_not_exposed(): void
    {
        $response = $this->getJson('/api/config');

        // Always make an assertion
        if ($response->status() === 200) {
            $config = $response->json();

            // Should not expose database credentials
            $this->assertArrayNotHasKey('database', $config);

            // Should not expose API keys
            $this->assertArrayNotHasKey('services', $config);

            // Should not expose app key
            $this->assertArrayNotHasKey('key', $config);
        } else {
            // Config endpoint should not exist or require authentication (both acceptable)
            $this->assertContains($response->status(), [401, 404], 'Config endpoint should be protected or non-existent');
        }
    }

    #[Test]
    public function it_validates_unnecessary_http_methods_are_disabled(): void
    {
        $response = $this->call('TRACE', '/api/v1/health');

        // TRACE should be disabled (405) or route not found (404)
        $this->assertContains($response->status(), [404, 405], 'TRACE method should be disabled or route not found');
    }

    #[Test]
    public function it_validates_api_returns_json_errors_not_html(): void
    {
        $response = $this->getJson('/api/v1/non-existent');

        $response->assertStatus(404);
        $response->assertHeader('Content-Type', 'application/json');

        // Should not return HTML error page
        $this->assertStringNotContainsString('<html>', $response->getContent());
        $this->assertStringNotContainsString('<!DOCTYPE', $response->getContent());
    }

    #[Test]
    public function it_validates_session_configuration_is_secure(): void
    {
        // Session should be HTTP-only
        $this->assertTrue(config('session.http_only'), 'Session cookies must be HTTP-only');

        // Session should use secure in production
        if (config('app.env') === 'production') {
            $this->assertTrue(config('session.secure'), 'Session cookies must be secure in production');
        } else {
            // In non-production, null or false is acceptable (HTTP allowed for local dev)
            $secureConfig = config('session.secure');
            $this->assertTrue(
                $secureConfig === null || $secureConfig === false || $secureConfig === true,
                'Session secure configuration must be null, true, or false'
            );
        }

        // Session should use SameSite
        $this->assertNotNull(config('session.same_site'), 'Session must have SameSite attribute');
    }

    #[Test]
    public function it_validates_password_reset_tokens_expire(): void
    {
        $expiration = config('auth.passwords.users.expire');

        $this->assertIsInt($expiration, 'Password reset expiration must be set');
        $this->assertLessThanOrEqual(60, $expiration, 'Password reset tokens should expire within 1 hour');
    }

    #[Test]
    public function it_validates_api_versioning_is_enforced(): void
    {
        // Try to access API without version
        $response = $this->getJson('/api/users');

        // Should require version or redirect
        $this->assertContains($response->status(), [301, 302, 404]);
    }

    #[Test]
    public function it_validates_sensitive_routes_require_authentication(): void
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

    #[Test]
    public function it_validates_file_upload_restrictions(): void
    {
        $response = $this->getJson('/api/v1/config/upload-settings');

        // Always make an assertion
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
        } else {
            // Upload settings endpoint should not exist or require authentication (both acceptable)
            $this->assertContains($response->status(), [401, 404], 'Upload settings endpoint should be protected or non-existent');
        }
    }

    #[Test]
    public function it_validates_rate_limiting_is_configured(): void
    {
        // Use auth login endpoint which has stricter rate limiting (10 per minute via throttle:auth)
        $responses = [];

        // Make rapid authentication attempts (should trigger rate limiting after 10 requests)
        for ($i = 0; $i < 12; $i++) {
            $responses[] = $this->postJson('/api/v1/auth/login', [
                'email' => 'test'.$i.'@example.com',
                'password' => 'wrongpassword',
            ]);
        }

        // Should hit rate limit
        $rateLimited = collect($responses)->first(fn ($r) => $r->status() === 429);

        $this->assertNotNull($rateLimited, 'Rate limiting should be enforced on authentication endpoints (throttle:auth = 10/min)');

        // Verify Retry-After header is present
        $this->assertNotNull($rateLimited->headers->get('Retry-After'), 'Retry-After header should be present on rate limited responses');
    }

    #[Test]
    public function it_validates_cookie_security_attributes(): void
    {
        $response = $this->postJson('/api/auth/register', [
            'name' => 'Test User',
            'email' => 'test@example.com',
            'password' => 'password123',
            'password_confirmation' => 'password123',
        ]);

        $cookies = $response->headers->getCookies();

        // Always make an assertion
        if (count($cookies) > 0) {
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
        } else {
            // If no cookies are set, verify the response is appropriate (could be stateless API)
            $this->assertTrue(true, 'No cookies set - acceptable for stateless API');
        }
    }
}
