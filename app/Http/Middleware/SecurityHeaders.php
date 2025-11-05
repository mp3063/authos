<?php

namespace App\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;

class SecurityHeaders
{
    public function handle(Request $request, Closure $next): Response
    {
        $response = $next($request);

        if (! config('app.security_headers_enabled', true)) {
            return $response;
        }

        // Standard Security Headers
        $response->headers->set('X-Content-Type-Options', 'nosniff');
        $response->headers->set('X-Frame-Options', 'DENY');
        $response->headers->set('X-XSS-Protection', '1; mode=block');
        $response->headers->set('Referrer-Policy', 'strict-origin-when-cross-origin');

        // HSTS Header for HTTPS connections
        if ($request->isSecure()) {
            $response->headers->set(
                'Strict-Transport-Security',
                'max-age=31536000; includeSubDomains; preload'
            );
        }

        // Permissions-Policy (Feature-Policy replacement)
        $permissionsPolicy = [
            'camera=()',
            'microphone=()',
            'geolocation=()',
            'payment=()',
            'usb=()',
            'magnetometer=()',
            'gyroscope=()',
            'accelerometer=()',
        ];
        $response->headers->set('Permissions-Policy', implode(', ', $permissionsPolicy));

        // Content Security Policy - Strict configuration
        $csp = $this->getContentSecurityPolicy($request);
        $response->headers->set('Content-Security-Policy', implode('; ', $csp));

        // OAuth-specific security headers
        if ($this->isOAuthEndpoint($request)) {
            $response->headers->set('Cache-Control', 'no-store, no-cache, must-revalidate, max-age=0');
            $response->headers->set('Pragma', 'no-cache');
            $response->headers->set('Referrer-Policy', 'no-referrer');
        }

        // API endpoint security headers
        if ($request->is('api/*')) {
            $response->headers->set('X-Content-Type-Options', 'nosniff');
            $response->headers->set('Cache-Control', 'no-store, max-age=0');
        }

        return $response;
    }

    protected function getContentSecurityPolicy(Request $request): array
    {
        // Base CSP for all requests
        $csp = [
            "default-src 'self'",
            "script-src 'self'",
            "style-src 'self'",
            "img-src 'self' data: https:",
            "font-src 'self' data:",
            "connect-src 'self'",
            "frame-ancestors 'none'",
            "base-uri 'self'",
            "form-action 'self'",
            'upgrade-insecure-requests',
        ];

        // For admin panel (Filament), allow specific inline styles and scripts
        // In production, use nonces instead of unsafe-inline
        if ($request->is('admin/*')) {
            $nonce = base64_encode(random_bytes(16));
            $request->attributes->set('csp_nonce', $nonce);

            $csp = [
                "default-src 'self'",
                "script-src 'self' 'nonce-{$nonce}'",
                "style-src 'self' 'nonce-{$nonce}'",
                "img-src 'self' data: https:",
                "font-src 'self' data:",
                "connect-src 'self'",
                "frame-ancestors 'none'",
                "base-uri 'self'",
                "form-action 'self'",
            ];
        }

        return $csp;
    }

    protected function isOAuthEndpoint(Request $request): bool
    {
        return $request->is('oauth/*') ||
               $request->is('api/oauth/*') ||
               $request->is('.well-known/*') ||
               $request->is('api/.well-known/*');
    }
}
