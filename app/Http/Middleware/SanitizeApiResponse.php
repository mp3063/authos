<?php

namespace App\Http\Middleware;

use Closure;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;

class SanitizeApiResponse
{
    /**
     * Sensitive fields that should be removed from API responses
     */
    protected array $sensitiveFields = [
        'password',
        'password_confirmation',
        'remember_token',
        'client_secret',
        'secret',
        'private_key',
        'private_keys',
        'encryption_key',
        'api_key',
        'token_secret',
        'refresh_token_secret',
        'webhook_secret',
        'database_password',
        'smtp_password',
        'oauth_token_secret',
        'jwt_secret',
        'app_key',
        'stripe_secret',
        'paypal_secret',
    ];

    /**
     * Fields that should be masked instead of removed
     */
    protected array $maskableFields = [
        'email' => 'email',
        'phone' => 'phone',
        'ip_address' => 'ip',
    ];

    /**
     * Handle an incoming request.
     */
    public function handle(Request $request, Closure $next): Response
    {
        $response = $next($request);

        // Only process JSON responses
        if ($response instanceof JsonResponse) {
            $data = $response->getData(true);

            // Don't sanitize validation error responses (status 422)
            if ($response->getStatusCode() === 422) {
                return $response;
            }

            // Allow secret field for TOTP setup endpoints
            $allowSecrets = $this->shouldAllowSecrets($request);

            $sanitizedData = $this->sanitizeData($data, $allowSecrets);
            $response->setData($sanitizedData);
        }

        return $response;
    }

    /**
     * Determine if secrets should be allowed for this request
     */
    protected function shouldAllowSecrets(Request $request): bool
    {
        $allowedPaths = [
            'api/v1/mfa/setup',       // Added for MFA setup endpoint
            'api/v1/mfa/setup/totp',
            'api/v1/applications/*/client-credentials',
            'api/v1/applications/*/credentials/regenerate',
            'api/v1/webhooks',        // Webhook creation returns secret
            'api/v1/webhooks/*/rotate-secret',  // Webhook secret rotation
        ];

        foreach ($allowedPaths as $path) {
            if ($request->is($path)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Recursively sanitize data by removing sensitive fields
     */
    protected function sanitizeData(mixed $data, bool $allowSecrets = false): mixed
    {
        if (is_array($data)) {
            $sanitized = [];

            foreach ($data as $key => $value) {
                // Remove sensitive fields entirely, unless secrets are allowed
                if (in_array($key, $this->sensitiveFields)) {
                    if ($allowSecrets && in_array($key, ['secret', 'client_secret'])) {
                        $sanitized[$key] = $value;

                        continue;
                    }

                    continue;
                }

                // Mask certain fields in production environments only
                if (array_key_exists($key, $this->maskableFields) && app()->environment('production')) {
                    $sanitized[$key] = $this->maskField($value, $this->maskableFields[$key]);
                } else {
                    $sanitized[$key] = $this->sanitizeData($value, $allowSecrets);
                }
            }

            return $sanitized;
        }

        return $data;
    }

    /**
     * Mask sensitive field values
     */
    protected function maskField(mixed $value, string $type): mixed
    {
        if (! is_string($value) || empty($value)) {
            return $value;
        }

        return match ($type) {
            'email' => $this->maskEmail($value),
            'phone' => $this->maskPhone($value),
            'ip' => $this->maskIpAddress($value),
            default => '***masked***'
        };
    }

    /**
     * Mask email address
     */
    protected function maskEmail(string $email): string
    {
        if (! str_contains($email, '@')) {
            return $email;
        }

        [$local, $domain] = explode('@', $email, 2);

        if (strlen($local) <= 2) {
            return $email; // Don't mask very short local parts
        }

        $maskedLocal = substr($local, 0, 1).str_repeat('*', strlen($local) - 2).substr($local, -1);

        return $maskedLocal.'@'.$domain;
    }

    /**
     * Mask phone number
     */
    protected function maskPhone(string $phone): string
    {
        if (strlen($phone) < 4) {
            return $phone;
        }

        return substr($phone, 0, 2).str_repeat('*', strlen($phone) - 4).substr($phone, -2);
    }

    /**
     * Mask IP address
     */
    protected function maskIpAddress(string $ip): string
    {
        if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
            $parts = explode('.', $ip);

            return $parts[0].'.'.$parts[1].'.***.'.$parts[3];
        }

        if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)) {
            $parts = explode(':', $ip);

            return implode(':', array_slice($parts, 0, 3)).':***:'.end($parts);
        }

        return $ip;
    }
}
