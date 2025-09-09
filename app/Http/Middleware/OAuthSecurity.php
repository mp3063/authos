<?php

namespace App\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Log;
use Symfony\Component\HttpFoundation\Response as ResponseInterface;

class OAuthSecurity
{
    /**
     * Handle an incoming request.
     */
    public function handle(Request $request, Closure $next): ResponseInterface
    {
        // Rate limiting for OAuth endpoints
        $this->applyRateLimiting($request);

        // Validate required OAuth parameters
        if ($this->isOAuthRequest($request)) {
            $this->validateOAuthRequest($request);
        }

        // Log OAuth security events
        $this->logSecurityEvent($request);

        $response = $next($request);

        // Add security headers to OAuth responses
        $this->addSecurityHeaders($response);

        return $response;
    }

    /**
     * Apply rate limiting to OAuth requests
     */
    protected function applyRateLimiting(Request $request): void
    {
        $clientId = $request->input('client_id') ?? 'unknown';
        $ipAddress = $request->ip();

        // Client-based rate limiting
        $clientKey = "oauth_rate_limit_client_{$clientId}";
        $clientRequests = Cache::get($clientKey, 0);

        if ($clientRequests >= config('oauth.rate_limits.per_client', 100)) {
            Log::warning('OAuth rate limit exceeded for client', [
                'client_id' => $clientId,
                'ip_address' => $ipAddress,
                'requests' => $clientRequests,
            ]);

            abort(429, 'Too many requests for this client');
        }

        Cache::put($clientKey, $clientRequests + 1, 3600); // 1 hour window

        // IP-based rate limiting for additional security
        $ipKey = "oauth_rate_limit_ip_{$ipAddress}";
        $ipRequests = Cache::get($ipKey, 0);

        if ($ipRequests >= config('oauth.rate_limits.per_ip', 200)) {
            Log::warning('OAuth rate limit exceeded for IP', [
                'ip_address' => $ipAddress,
                'requests' => $ipRequests,
            ]);

            abort(429, 'Too many requests from this IP');
        }

        Cache::put($ipKey, $ipRequests + 1, 3600);
    }

    /**
     * Check if this is an OAuth request
     */
    protected function isOAuthRequest(Request $request): bool
    {
        return $request->is('oauth/*') ||
               $request->is('api/oauth/*') ||
               $request->has('client_id');
    }

    /**
     * Validate OAuth request parameters
     */
    protected function validateOAuthRequest(Request $request): void
    {
        // Check for HTTPS in production
        if (app()->environment('production') && ! $request->secure()) {
            Log::error('OAuth request over insecure connection', [
                'ip_address' => $request->ip(),
                'user_agent' => $request->userAgent(),
            ]);

            abort(400, 'OAuth requests must use HTTPS');
        }

        // Validate state parameter length (prevents CSRF)
        if ($request->has('state') && strlen($request->input('state')) > 512) {
            abort(400, 'State parameter too long');
        }

        // Validate redirect URI format
        if ($request->has('redirect_uri')) {
            $redirectUri = $request->input('redirect_uri');

            if (! filter_var($redirectUri, FILTER_VALIDATE_URL)) {
                abort(400, 'Invalid redirect URI format');
            }

            // Block dangerous protocols
            $scheme = parse_url($redirectUri, PHP_URL_SCHEME);
            if (! in_array($scheme, ['http', 'https', 'custom'])) {
                abort(400, 'Invalid redirect URI scheme');
            }
        }

        // Check for suspicious client_id patterns
        if ($request->has('client_id')) {
            $clientId = $request->input('client_id');

            if (strlen($clientId) > 255 || ! preg_match('/^[\w\-\.]+$/', $clientId)) {
                Log::warning('Suspicious client_id detected', [
                    'client_id' => $clientId,
                    'ip_address' => $request->ip(),
                ]);

                abort(400, 'Invalid client ID format');
            }
        }
    }

    /**
     * Log OAuth security events
     */
    protected function logSecurityEvent(Request $request): void
    {
        if ($this->isOAuthRequest($request)) {
            Log::info('OAuth request', [
                'method' => $request->method(),
                'uri' => $request->getRequestUri(),
                'client_id' => $request->input('client_id'),
                'ip_address' => $request->ip(),
                'user_agent' => $request->userAgent(),
                'timestamp' => now()->toISOString(),
            ]);
        }
    }

    /**
     * Add security headers to OAuth responses
     */
    protected function addSecurityHeaders($response): void
    {
        $response->headers->set('Cache-Control', 'no-store, no-cache, must-revalidate, max-age=0');
        $response->headers->set('Pragma', 'no-cache');
        $response->headers->set('X-Content-Type-Options', 'nosniff');
        $response->headers->set('X-Frame-Options', 'DENY');
        $response->headers->set('Referrer-Policy', 'no-referrer');
    }
}
