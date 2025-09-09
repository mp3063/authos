<?php

namespace App\Http\Middleware;

use Closure;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Log;
use Symfony\Component\HttpFoundation\Response;

class ApiResponseCache
{
    /**
     * Handle an incoming request.
     */
    public function handle(Request $request, Closure $next, int $ttl = 300): Response
    {
        // Only cache GET requests
        if ($request->method() !== 'GET') {
            return $next($request);
        }

        // Skip caching for certain endpoints
        if ($this->shouldSkipCaching($request)) {
            return $next($request);
        }

        $cacheKey = $this->getCacheKey($request);

        // Try to get from cache
        $cachedResponse = Cache::get($cacheKey);

        if ($cachedResponse) {
            Log::debug('API cache hit', ['key' => $cacheKey]);

            return response()->json($cachedResponse['data'], $cachedResponse['status'])
                ->withHeaders($cachedResponse['headers'])
                ->header('X-Cache', 'HIT')
                ->header('X-Cache-Key', $cacheKey);
        }

        // Get response from controller
        $response = $next($request);

        // Only cache successful JSON responses
        if ($response instanceof JsonResponse && $response->getStatusCode() === 200) {
            $responseData = [
                'data' => $response->getData(true),
                'status' => $response->getStatusCode(),
                'headers' => $this->getCacheableHeaders($response),
            ];

            Cache::put($cacheKey, $responseData, $ttl);

            Log::debug('API cache miss, stored', ['key' => $cacheKey, 'ttl' => $ttl]);

            $response->header('X-Cache', 'MISS')
                ->header('X-Cache-Key', $cacheKey)
                ->header('X-Cache-TTL', $ttl);
        }

        return $response;
    }

    /**
     * Generate cache key for the request.
     */
    private function getCacheKey(Request $request): string
    {
        $user = auth('api')->user();
        $userId = $user ? $user->id : 'anonymous';

        // Include user permissions in cache key for authorization-dependent responses
        $permissions = $user ? $user->getAllPermissions()->pluck('name')->sort()->implode(',') : '';

        $key = sprintf(
            'api_cache:%s:%s:%s:%s:%s',
            $request->getMethod(),
            str_replace('/', '_', $request->getPathInfo()),
            md5($request->getQueryString() ?: ''),
            $userId,
            md5($permissions)
        );

        return $key;
    }

    /**
     * Check if caching should be skipped for this request.
     */
    private function shouldSkipCaching(Request $request): bool
    {
        $skipPatterns = [
            '/api/auth/user',           // Current user info changes frequently
            '/api/profile',             // Profile info changes frequently
            '/api/.*\/sessions',        // Session data is dynamic
            '/api/.*\/tokens',          // Token data is sensitive and dynamic
            '/api/.*\/analytics',       // Analytics data should be fresh
        ];

        $path = $request->getPathInfo();

        foreach ($skipPatterns as $pattern) {
            if (preg_match('#'.$pattern.'#', $path)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Get headers that should be cached.
     */
    private function getCacheableHeaders(JsonResponse $response): array
    {
        $cacheableHeaders = [
            'Content-Type',
            'X-Total-Count',
            'X-Page-Count',
            'X-Per-Page',
            'X-Current-Page',
        ];

        $headers = [];
        foreach ($cacheableHeaders as $header) {
            if ($response->headers->has($header)) {
                $headers[$header] = $response->headers->get($header);
            }
        }

        return $headers;
    }
}
