<?php

namespace App\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\RateLimiter;
use Symfony\Component\HttpFoundation\Response;

class ApiRateLimiter
{
    /**
     * Rate limiting configurations for different endpoint categories
     */
    protected array $rateLimits = [
        'authentication' => [
            'limit' => 10,
            'window' => 60, // 1 minute
            'by' => 'ip',
        ],
        'registration' => [
            'limit' => 5,
            'window' => 3600, // 1 hour
            'by' => 'ip',
        ],
        'password_reset' => [
            'limit' => 3,
            'window' => 3600, // 1 hour
            'by' => 'ip',
        ],
        'api_standard' => [
            'limit' => 1000,
            'window' => 3600, // 1 hour
            'by' => 'user',
        ],
        'api_bulk' => [
            'limit' => 100,
            'window' => 3600, // 1 hour
            'by' => 'user',
        ],
        'api_admin' => [
            'limit' => 200,
            'window' => 3600, // 1 hour
            'by' => 'user',
        ],
        'mfa' => [
            'limit' => 20,
            'window' => 3600, // 1 hour
            'by' => 'user',
        ],
        'oauth' => [
            'limit' => 20,
            'window' => 60, // 1 minute
            'by' => 'ip',
        ],
    ];

    /**
     * Handle an incoming request
     */
    public function handle(Request $request, Closure $next, string $category = 'api_standard'): Response
    {
        $config = $this->rateLimits[$category] ?? $this->rateLimits['api_standard'];
        
        $key = $this->generateKey($request, $config['by'], $category);
        $limit = $this->getLimit($request, $config);
        $window = $config['window'];

        $executed = RateLimiter::attempt(
            $key,
            $limit,
            function () use ($next, $request) {
                return $next($request);
            },
            $window
        );

        if (!$executed) {
            return $this->buildResponse($key, $limit, $window);
        }

        return $this->addHeaders($executed, $key, $limit, $window);
    }

    /**
     * Generate rate limiting key
     */
    protected function generateKey(Request $request, string $by, string $category): string
    {
        $identifier = match($by) {
            'ip' => $request->ip(),
            'user' => $request->user()?->id ?? $request->ip(),
            default => $request->ip(),
        };

        return sprintf('rate_limit:%s:%s:%s', $category, $by, $identifier);
    }

    /**
     * Get dynamic limit based on user/context
     */
    protected function getLimit(Request $request, array $config): int
    {
        $baseLimit = $config['limit'];
        
        // Increase limits for authenticated users with higher roles
        if ($request->user()) {
            $user = $request->user();
            
            // Super admin gets 5x limit
            if ($user->hasRole('super-admin')) {
                return $baseLimit * 5;
            }
            
            // Organization admin gets 3x limit
            if ($user->hasRole('organization-admin')) {
                return $baseLimit * 3;
            }
            
            // Application admin gets 2x limit
            if ($user->hasRole('application-admin')) {
                return $baseLimit * 2;
            }
        }

        return $baseLimit;
    }

    /**
     * Build rate limit exceeded response
     */
    protected function buildResponse(string $key, int $limit, int $window): Response
    {
        $retryAfter = RateLimiter::availableIn($key);
        $remaining = RateLimiter::remaining($key, $limit);
        
        $response = response()->json([
            'error' => 'rate_limit_exceeded',
            'error_description' => 'Too many requests. Please try again later.',
            'details' => [
                'limit' => $limit,
                'window' => $window,
                'retry_after' => $retryAfter,
            ],
        ], 429);

        return $this->addHeaders($response, $key, $limit, $window, $retryAfter);
    }

    /**
     * Add rate limiting headers to response
     */
    protected function addHeaders($response, string $key, int $limit, int $window, ?int $retryAfter = null)
    {
        $remaining = RateLimiter::remaining($key, $limit);
        $resetTime = now()->addSeconds($window)->timestamp;

        $response->headers->add([
            'X-RateLimit-Limit' => $limit,
            'X-RateLimit-Remaining' => max(0, $remaining),
            'X-RateLimit-Reset' => $resetTime,
            'X-RateLimit-Window' => $window,
        ]);

        if ($retryAfter !== null) {
            $response->headers->add([
                'X-RateLimit-Retry-After' => $retryAfter,
                'Retry-After' => $retryAfter,
            ]);
        }

        return $response;
    }

    /**
     * Get rate limiting status for API endpoint
     */
    public static function getStatus(Request $request, string $category = 'api_standard'): array
    {
        $middleware = new self();
        $config = $middleware->rateLimits[$category] ?? $middleware->rateLimits['api_standard'];
        
        $key = $middleware->generateKey($request, $config['by'], $category);
        $limit = $middleware->getLimit($request, $config);
        $window = $config['window'];
        
        $remaining = RateLimiter::remaining($key, $limit);
        $availableIn = RateLimiter::availableIn($key);
        $resetTime = now()->addSeconds($window)->timestamp;

        return [
            'limit' => $limit,
            'remaining' => max(0, $remaining),
            'reset_at' => $resetTime,
            'available_in' => $availableIn,
            'window' => $window,
        ];
    }
}