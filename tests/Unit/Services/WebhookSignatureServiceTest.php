<?php

namespace Tests\Unit\Services;

use App\Services\WebhookSignatureService;
use Tests\TestCase;

class WebhookSignatureServiceTest extends TestCase
{
    private WebhookSignatureService $service;

    protected function setUp(): void
    {
        parent::setUp();

        $this->service = new WebhookSignatureService;
    }

    public function test_generates_valid_signature(): void
    {
        $secret = 'test_secret_key_123';
        $payload = json_encode(['event' => 'user.created', 'data' => ['id' => 1]]);
        $timestamp = time();

        $signature = $this->service->generateSignature($payload, $secret, $timestamp);

        $this->assertNotEmpty($signature);
        $this->assertIsString($signature);
        $this->assertMatchesRegularExpression('/^[a-f0-9]{64}$/', $signature); // SHA-256 hex
    }

    public function test_verifies_valid_signature(): void
    {
        $secret = 'test_secret_key_123';
        $payload = json_encode(['event' => 'user.created', 'data' => ['id' => 1]]);
        $timestamp = time();

        $signature = $this->service->generateSignature($payload, $secret, $timestamp);

        $isValid = $this->service->verifySignature($payload, $signature, $secret, $timestamp);

        $this->assertTrue($isValid);
    }

    public function test_rejects_invalid_signature(): void
    {
        $secret = 'test_secret_key_123';
        $payload = json_encode(['event' => 'user.created', 'data' => ['id' => 1]]);
        $timestamp = time();

        $invalidSignature = 'invalid_signature_hash';

        $isValid = $this->service->verifySignature($payload, $invalidSignature, $secret, $timestamp);

        $this->assertFalse($isValid);
    }

    public function test_rejects_signature_with_wrong_secret(): void
    {
        $secret = 'test_secret_key_123';
        $wrongSecret = 'wrong_secret_key_456';
        $payload = json_encode(['event' => 'user.created', 'data' => ['id' => 1]]);
        $timestamp = time();

        $signature = $this->service->generateSignature($payload, $secret, $timestamp);

        $isValid = $this->service->verifySignature($payload, $signature, $wrongSecret, $timestamp);

        $this->assertFalse($isValid);
    }

    public function test_rejects_expired_timestamp(): void
    {
        $secret = 'test_secret_key_123';
        $payload = json_encode(['event' => 'user.created', 'data' => ['id' => 1]]);
        $expiredTimestamp = time() - 600; // 10 minutes ago

        $signature = $this->service->generateSignature($payload, $secret, $expiredTimestamp);

        $isValid = $this->service->verifySignature($payload, $signature, $secret, $expiredTimestamp, 300);

        $this->assertFalse($isValid);
    }

    public function test_accepts_recent_timestamp(): void
    {
        $secret = 'test_secret_key_123';
        $payload = json_encode(['event' => 'user.created', 'data' => ['id' => 1]]);
        $recentTimestamp = time() - 60; // 1 minute ago

        $signature = $this->service->generateSignature($payload, $secret, $recentTimestamp);

        $isValid = $this->service->verifySignature($payload, $signature, $secret, $recentTimestamp, 300);

        $this->assertTrue($isValid);
    }

    public function test_generates_secure_secret(): void
    {
        $secret = $this->service->generateSecret();

        $this->assertNotEmpty($secret);
        $this->assertIsString($secret);
        $this->assertGreaterThanOrEqual(32, strlen($secret));
        $this->assertMatchesRegularExpression('/^whsec_[a-zA-Z0-9]+$/', $secret);
    }

    public function test_generates_unique_secrets(): void
    {
        $secret1 = $this->service->generateSecret();
        $secret2 = $this->service->generateSecret();

        $this->assertNotEquals($secret1, $secret2);
    }

    public function test_signature_changes_with_different_payload(): void
    {
        $secret = 'test_secret_key_123';
        $payload1 = json_encode(['event' => 'user.created', 'data' => ['id' => 1]]);
        $payload2 = json_encode(['event' => 'user.updated', 'data' => ['id' => 1]]);
        $timestamp = time();

        $signature1 = $this->service->generateSignature($payload1, $secret, $timestamp);
        $signature2 = $this->service->generateSignature($payload2, $secret, $timestamp);

        $this->assertNotEquals($signature1, $signature2);
    }

    public function test_signature_changes_with_different_timestamp(): void
    {
        $secret = 'test_secret_key_123';
        $payload = json_encode(['event' => 'user.created', 'data' => ['id' => 1]]);
        $timestamp1 = time();
        $timestamp2 = time() + 10;

        $signature1 = $this->service->generateSignature($payload, $secret, $timestamp1);
        $signature2 = $this->service->generateSignature($payload, $secret, $timestamp2);

        $this->assertNotEquals($signature1, $signature2);
    }
}
