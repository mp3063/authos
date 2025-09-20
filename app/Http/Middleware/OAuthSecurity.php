<?php

namespace App\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Log;
use Symfony\Component\HttpFoundation\Response as ResponseInterface;

class OAuthSecurity
{
    /**
     * Handle an incoming request.
     */
    public function handle(Request $request, Closure $next): ResponseInterface
    {
        // Log OAuth security events for monitoring
        $this->logSecurityEvent($request);

        // Basic HTTPS validation for production OAuth requests
        if ($this->isOAuthRequest($request) && app()->environment('production') && ! $request->secure()) {
            Log::error('OAuth request over insecure connection', [
                'ip_address' => $request->ip(),
                'user_agent' => $request->userAgent(),
            ]);

            abort(400, 'OAuth requests must use HTTPS');
        }

        return $next($request);
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
}
