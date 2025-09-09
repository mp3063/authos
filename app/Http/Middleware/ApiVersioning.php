<?php

namespace App\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;

class ApiVersioning
{
    /**
     * Supported API versions
     */
    protected array $supportedVersions = [
        'v1' => '1.0',
        'v2' => '2.0', // Future version
    ];

    /**
     * Default API version
     */
    protected string $defaultVersion = 'v1';

    /**
     * Handle an incoming request
     */
    public function handle(Request $request, Closure $next, ?string $requiredVersion = null): Response
    {
        $version = $this->getRequestedVersion($request);

        // Validate version if required
        if ($requiredVersion && $version !== $requiredVersion) {
            return $this->versionMismatchResponse($version, $requiredVersion);
        }

        // Validate version is supported
        if (! $this->isVersionSupported($version)) {
            return $this->unsupportedVersionResponse($version);
        }

        // Check if version is deprecated
        if ($this->isVersionDeprecated($version)) {
            $response = $next($request);

            return $this->addDeprecationHeaders($response, $version);
        }

        // Set version in request for controllers to access
        $request->merge(['api_version' => $version]);

        $response = $next($request);

        // Add version headers to response
        return $this->addVersionHeaders($response, $version);
    }

    /**
     * Get the requested API version from headers or URL
     */
    protected function getRequestedVersion(Request $request): string
    {
        // 1. Check URL path first (/api/v1/...)
        if (preg_match('/^\/api\/(v\d+)\//', $request->getPathInfo(), $matches)) {
            return $matches[1];
        }

        // 2. Check Accept header (Accept: application/vnd.authos.v1+json)
        $acceptHeader = $request->header('Accept', '');
        if (preg_match('/application\/vnd\.authos\.(v\d+)\+json/', $acceptHeader, $matches)) {
            return $matches[1];
        }

        // 3. Check X-API-Version header
        $versionHeader = $request->header('X-API-Version');
        if ($versionHeader && $this->isVersionSupported($versionHeader)) {
            return $versionHeader;
        }

        // 4. Default version
        return $this->defaultVersion;
    }

    /**
     * Check if version is supported
     */
    protected function isVersionSupported(string $version): bool
    {
        return isset($this->supportedVersions[$version]);
    }

    /**
     * Check if version is deprecated
     */
    protected function isVersionDeprecated(string $version): bool
    {
        // Define deprecated versions here
        $deprecatedVersions = [
            // 'v1' => '2024-12-31', // Example: v1 deprecated on 2024-12-31
        ];

        if (! isset($deprecatedVersions[$version])) {
            return false;
        }

        return now() >= $deprecatedVersions[$version];
    }

    /**
     * Return version mismatch response
     */
    protected function versionMismatchResponse(string $requested, string $required): Response
    {
        return response()->json([
            'error' => 'version_mismatch',
            'error_description' => "API version mismatch. Requested: {$requested}, Required: {$required}",
            'supported_versions' => array_keys($this->supportedVersions),
            'requested_version' => $requested,
            'required_version' => $required,
        ], 400);
    }

    /**
     * Return unsupported version response
     */
    protected function unsupportedVersionResponse(string $version): Response
    {
        return response()->json([
            'error' => 'unsupported_version',
            'error_description' => "API version '{$version}' is not supported.",
            'supported_versions' => array_keys($this->supportedVersions),
            'requested_version' => $version,
            'latest_version' => array_key_last($this->supportedVersions),
        ], 400);
    }

    /**
     * Add version headers to response
     */
    protected function addVersionHeaders(Response $response, string $version): Response
    {
        $response->headers->add([
            'X-API-Version' => $version,
            'X-API-Version-Number' => $this->supportedVersions[$version],
            'X-API-Latest-Version' => array_key_last($this->supportedVersions),
        ]);

        return $response;
    }

    /**
     * Add deprecation headers to response
     */
    protected function addDeprecationHeaders(Response $response, string $version): Response
    {
        $response->headers->add([
            'X-API-Deprecated' => 'true',
            'X-API-Deprecation-Date' => '2024-12-31', // Example date
            'X-API-Sunset-Date' => '2025-06-30', // Example sunset date
            'Warning' => '299 - "API version '.$version.' is deprecated"',
        ]);

        return $response;
    }

    /**
     * Get current API version from request
     */
    public static function getCurrentVersion(Request $request): string
    {
        return $request->get('api_version', 'v1');
    }

    /**
     * Get version information
     */
    public static function getVersionInfo(): array
    {
        $middleware = new self;

        return [
            'supported_versions' => array_keys($middleware->supportedVersions),
            'default_version' => $middleware->defaultVersion,
            'latest_version' => array_key_last($middleware->supportedVersions),
            'version_details' => $middleware->supportedVersions,
        ];
    }
}
