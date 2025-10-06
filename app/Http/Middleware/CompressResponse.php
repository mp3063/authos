<?php

namespace App\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;

class CompressResponse
{
    /**
     * Handle an incoming request and compress the response.
     */
    public function handle(Request $request, Closure $next): Response
    {
        $response = $next($request);

        // Only compress if enabled in config
        if (! config('performance.compression.enabled', true)) {
            return $response;
        }

        // Check if client supports compression
        $acceptEncoding = $request->header('Accept-Encoding', '');
        if (! str_contains($acceptEncoding, 'gzip')) {
            return $response;
        }

        // Only compress responses above minimum size
        $minLength = config('performance.compression.min_length', 1024);
        $content = $response->getContent();
        if (strlen($content) < $minLength) {
            return $response;
        }

        // Check if content type should be compressed
        $contentType = $response->headers->get('Content-Type', '');
        $compressibleTypes = config('performance.compression.types', [
            'application/json',
            'application/javascript',
            'text/html',
            'text/css',
            'text/plain',
        ]);

        $shouldCompress = false;
        foreach ($compressibleTypes as $type) {
            if (str_contains($contentType, $type)) {
                $shouldCompress = true;
                break;
            }
        }

        if (! $shouldCompress) {
            return $response;
        }

        // Don't compress if already compressed
        if ($response->headers->has('Content-Encoding')) {
            return $response;
        }

        // Compress the content
        $compressionLevel = config('performance.compression.level', 6);
        $compressedContent = gzencode($content, $compressionLevel);

        if ($compressedContent === false) {
            // Compression failed, return original response
            return $response;
        }

        // Calculate compression ratio
        $originalSize = strlen($content);
        $compressedSize = strlen($compressedContent);
        $ratio = round((1 - ($compressedSize / $originalSize)) * 100, 2);

        // Set compressed content and headers
        $response->setContent($compressedContent);
        $response->headers->set('Content-Encoding', 'gzip');
        $response->headers->set('Content-Length', (string) $compressedSize);
        $response->headers->set('X-Original-Size', (string) $originalSize);
        $response->headers->set('X-Compressed-Size', (string) $compressedSize);
        $response->headers->set('X-Compression-Ratio', $ratio.'%');

        // Add Vary header to indicate compression varies by Accept-Encoding
        $response->headers->set('Vary', 'Accept-Encoding', false);

        return $response;
    }
}
