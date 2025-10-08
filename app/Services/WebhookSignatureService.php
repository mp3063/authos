<?php

namespace App\Services;

use App\Models\WebhookDelivery;

class WebhookSignatureService extends BaseService
{
    /**
     * Generate HMAC-SHA256 signature for webhook payload
     */
    public function generateSignature(string $payload, string $secret, int $timestamp): string
    {
        $signatureBase = $timestamp.'.'.$payload;

        return hash_hmac('sha256', $signatureBase, $secret);
    }

    /**
     * Verify webhook signature
     */
    public function verifySignature(
        string $payload,
        string $signature,
        string $secret,
        int $timestamp
    ): bool {
        // Check timestamp age (prevent replay attacks)
        if (! $this->validateTimestamp($timestamp)) {
            return false;
        }

        // Calculate expected signature
        $expectedSignature = $this->generateSignature($payload, $secret, $timestamp);

        // Timing-safe comparison
        return hash_equals($expectedSignature, $signature);
    }

    /**
     * Validate timestamp is not too old (5 minute window)
     */
    public function validateTimestamp(int $timestamp, int $maxAgeSeconds = 300): bool
    {
        $currentTime = time();
        $age = abs($currentTime - $timestamp);

        return $age <= $maxAgeSeconds;
    }

    /**
     * Build HTTP headers for webhook request
     */
    public function buildHeaders(WebhookDelivery $delivery, string $signature, int $timestamp): array
    {
        $headers = [
            'Content-Type' => 'application/json',
            'User-Agent' => 'AuthOS-Webhooks/1.0',
            'X-Webhook-Signature' => 'sha256='.$signature,
            'X-Webhook-Timestamp' => (string) $timestamp,
            'X-Webhook-Event' => $delivery->event_type,
            'X-Webhook-Delivery-ID' => (string) $delivery->id,
            'X-Webhook-Attempt' => (string) $delivery->attempt_number,
        ];

        // Add custom headers from webhook configuration
        if ($delivery->webhook->headers) {
            $headers = array_merge($headers, $delivery->webhook->headers);
        }

        return $headers;
    }

    /**
     * Extract signature from header value
     */
    public function extractSignature(string $headerValue): ?string
    {
        if (str_starts_with($headerValue, 'sha256=')) {
            return substr($headerValue, 7);
        }

        return null;
    }

    /**
     * Generate a new webhook secret
     * Format: whsec_<base62-encoded-random-bytes>
     */
    public function generateSecret(): string
    {
        // Generate 32 random bytes and encode as base62
        $bytes = random_bytes(32);
        $base62 = $this->base62Encode($bytes);

        return 'whsec_'.$base62;
    }

    /**
     * Base62 encode binary data
     */
    private function base62Encode(string $data): string
    {
        $chars = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz';
        $base = strlen($chars);

        // Convert binary to big integer
        $num = gmp_init('0x'.bin2hex($data), 16);
        $result = '';

        while (gmp_cmp($num, '0') > 0) {
            [$num, $remainder] = gmp_div_qr($num, $base);
            $result = $chars[gmp_intval($remainder)].$result;
        }

        return $result ?: '0';
    }
}
