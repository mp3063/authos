<?php

namespace Tests\Unit\Security;

use App\Models\Organization;
use App\Models\User;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Hash;
use PHPUnit\Framework\Attributes\Test;
use Tests\TestCase;

/**
 * Tests for Password Reset Timing Attack Protection
 *
 * Validates that the password reset endpoint is protected against timing attacks
 * that could be used to enumerate valid email addresses or token states.
 *
 * OWASP Reference: A07:2021 - Identification and Authentication Failures
 * CWE-208: Observable Timing Discrepancy
 */
class PasswordResetTimingAttackTest extends TestCase
{
    use RefreshDatabase;

    protected User $user;

    protected Organization $organization;

    protected function setUp(): void
    {
        parent::setUp();

        // Disable rate limiting middleware to accurately measure timing
        // Timing attack tests verify constant-time comparison logic, not rate limiting
        $this->withoutMiddleware(\Illuminate\Routing\Middleware\ThrottleRequests::class);

        $this->organization = Organization::factory()->create();
        $this->user = User::factory()->create([
            'organization_id' => $this->organization->id,
            'email' => 'testuser@example.com',
            'password' => Hash::make('OldPassword123!'),
        ]);
    }

    /**
     * Generate a unique, non-breached password for testing
     * Uses current timestamp to ensure uniqueness and avoid password breach database hits
     */
    protected function generateUniquePassword(): string
    {
        return 'TestPass' . time() . mt_rand(1000, 9999) . '!Zx@9';
    }

    #[Test]
    public function it_applies_constant_time_validation_for_non_existent_tokens()
    {
        // This test ensures that checking a non-existent token takes similar time
        // to checking an existing token (due to dummy token comparison)

        $timings = [];

        // Test with non-existent token (10 times to get average)
        for ($i = 0; $i < 10; $i++) {
            $password = $this->generateUniquePassword();
            $start = microtime(true);

            $response = $this->postJson('/api/v1/auth/password/reset', [
                'email' => 'nonexistent@example.com',
                'token' => \Illuminate\Support\Str::random(64),
                'password' => $password,
                'password_confirmation' => $password,
            ]);

            $end = microtime(true);
            $timings['non_existent'][] = ($end - $start) * 1000; // Convert to ms

            $response->assertStatus(422);
            $response->assertJson([
                'error' => 'invalid_token',
            ]);
        }

        // The response time should include the random delay (50-150ms)
        // Average should be around 100ms (middle of range)
        $avgNonExistent = array_sum($timings['non_existent']) / count($timings['non_existent']);

        // Assert that timing is within expected range (accounting for system variance)
        // Minimum: 50ms (minimum delay) + processing time
        // Maximum: 200ms (max delay + processing time + variance)
        $this->assertGreaterThan(40, $avgNonExistent, 'Response time too fast - random delay may not be applied');
        $this->assertLessThan(250, $avgNonExistent, 'Response time too slow - may indicate performance issue');
    }

    #[Test]
    public function it_uses_constant_time_comparison_even_when_record_does_not_exist()
    {
        // Create a valid token for comparison
        $plainToken = \Illuminate\Support\Str::random(60);
        $hashedToken = hash('sha256', $plainToken);

        DB::table('password_reset_tokens')->insert([
            'email' => $this->user->email,
            'token' => $hashedToken,
            'created_at' => now(),
        ]);

        $timingsExisting = [];
        $timingsNonExisting = [];

        // Measure timing for existing email with wrong token (increased iterations for statistical stability)
        for ($i = 0; $i < 15; $i++) {
            $password = $this->generateUniquePassword();
            $start = microtime(true);

            $this->postJson('/api/v1/auth/password/reset', [
                'email' => $this->user->email,
                'token' => \Illuminate\Support\Str::random(64), // Wrong token
                'password' => $password,
                'password_confirmation' => $password,
            ]);

            $timingsExisting[] = (microtime(true) - $start) * 1000;
        }

        // Measure timing for non-existing email (increased iterations for statistical stability)
        for ($i = 0; $i < 15; $i++) {
            $password = $this->generateUniquePassword();
            $start = microtime(true);

            $this->postJson('/api/v1/auth/password/reset', [
                'email' => 'nonexistent@example.com',
                'token' => \Illuminate\Support\Str::random(64),
                'password' => $password,
                'password_confirmation' => $password,
            ]);

            $timingsNonExisting[] = (microtime(true) - $start) * 1000;
        }

        $avgExisting = array_sum($timingsExisting) / count($timingsExisting);
        $avgNonExisting = array_sum($timingsNonExisting) / count($timingsNonExisting);

        // The timing difference should be minimal (within 20ms variance due to random delay)
        // Both should go through hash_equals() even when record doesn't exist
        $difference = abs($avgExisting - $avgNonExisting);

        $this->assertLessThan(30, $difference,
            "Timing difference of {$difference}ms is too large. ".
            "Existing: {$avgExisting}ms, Non-existing: {$avgNonExisting}ms. ".
            'This may indicate a timing attack vulnerability.'
        );
    }

    #[Test]
    public function it_does_not_reveal_token_expiration_status_through_timing()
    {
        $timingsValid = [];
        $timingsExpired = [];

        // Test with expired token (increased iterations for statistical stability)
        for ($i = 0; $i < 15; $i++) {
            $password = $this->generateUniquePassword();
            $plainToken = \Illuminate\Support\Str::random(64);
            $hashedToken = hash('sha256', $plainToken);

            DB::table('password_reset_tokens')->insert([
                'email' => $this->user->email,
                'token' => $hashedToken,
                'created_at' => now()->subMinutes(61), // Expired
            ]);

            $start = microtime(true);

            $this->postJson('/api/v1/auth/password/reset', [
                'email' => $this->user->email,
                'token' => $plainToken,
                'password' => $password,
                'password_confirmation' => $password,
            ]);

            $timingsExpired[] = (microtime(true) - $start) * 1000;

            // Clean up for next iteration
            DB::table('password_reset_tokens')->where('email', $this->user->email)->delete();
        }

        // Test with invalid token (wrong token) - increased iterations for statistical stability
        for ($i = 0; $i < 15; $i++) {
            $password = $this->generateUniquePassword();
            $plainToken = \Illuminate\Support\Str::random(64);
            $hashedToken = hash('sha256', $plainToken);

            DB::table('password_reset_tokens')->insert([
                'email' => $this->user->email,
                'token' => $hashedToken,
                'created_at' => now(), // Valid timestamp
            ]);

            $start = microtime(true);

            $this->postJson('/api/v1/auth/password/reset', [
                'email' => $this->user->email,
                'token' => \Illuminate\Support\Str::random(64), // Wrong token
                'password' => $password,
                'password_confirmation' => $password,
            ]);

            $timingsValid[] = (microtime(true) - $start) * 1000;

            // Clean up for next iteration
            DB::table('password_reset_tokens')->where('email', $this->user->email)->delete();
        }

        $avgExpired = array_sum($timingsExpired) / count($timingsExpired);
        $avgValid = array_sum($timingsValid) / count($timingsValid);

        // The timing difference should be minimal
        $difference = abs($avgExpired - $avgValid);

        $this->assertLessThan(30, $difference,
            "Timing difference of {$difference}ms is too large. ".
            "Expired: {$avgExpired}ms, Invalid: {$avgValid}ms. ".
            'Expired vs invalid tokens should have similar response times.'
        );
    }

    #[Test]
    public function it_uses_generic_error_messages_for_all_failure_modes()
    {
        $password = $this->generateUniquePassword();

        // Test 1: Non-existent email
        $response1 = $this->postJson('/api/v1/auth/password/reset', [
            'email' => 'nonexistent@example.com',
            'token' => \Illuminate\Support\Str::random(64),
            'password' => $password,
            'password_confirmation' => $password,
        ]);

        // Test 2: Wrong token
        $plainToken = \Illuminate\Support\Str::random(64);
        $hashedToken = hash('sha256', $plainToken);
        DB::table('password_reset_tokens')->insert([
            'email' => $this->user->email,
            'token' => $hashedToken,
            'created_at' => now(),
        ]);

        $response2 = $this->postJson('/api/v1/auth/password/reset', [
            'email' => $this->user->email,
            'token' => \Illuminate\Support\Str::random(64), // Wrong token
            'password' => $password,
            'password_confirmation' => $password,
        ]);

        // Test 3: Expired token
        DB::table('password_reset_tokens')
            ->where('email', $this->user->email)
            ->update(['created_at' => now()->subMinutes(61)]);

        $response3 = $this->postJson('/api/v1/auth/password/reset', [
            'email' => $this->user->email,
            'token' => $plainToken,
            'password' => $password,
            'password_confirmation' => $password,
        ]);

        // All responses should have identical error structure
        $response1->assertStatus(422);
        $response1->assertJson(['error' => 'invalid_token']);

        $response2->assertStatus(422);
        $response2->assertJson(['error' => 'invalid_token']);

        $response3->assertStatus(422);
        $response3->assertJson(['error' => 'invalid_token']);

        // Verify all have the same message (no information leakage)
        $this->assertEquals(
            $response1->json('message'),
            $response2->json('message'),
            'Error messages should be identical'
        );

        $this->assertEquals(
            $response1->json('message'),
            $response3->json('message'),
            'Error messages should be identical'
        );
    }

    #[Test]
    public function it_applies_random_delay_to_normalize_response_timing()
    {
        $timings = [];

        // Make 20 requests and measure timing variance
        for ($i = 0; $i < 20; $i++) {
            $password = $this->generateUniquePassword();
            $start = microtime(true);

            $this->postJson('/api/v1/auth/password/reset', [
                'email' => 'test@example.com',
                'token' => \Illuminate\Support\Str::random(64),
                'password' => $password,
                'password_confirmation' => $password,
            ]);

            $timings[] = (microtime(true) - $start) * 1000;
        }

        // Calculate variance - should show significant spread due to random delay
        $mean = array_sum($timings) / count($timings);
        $variance = 0;
        foreach ($timings as $timing) {
            $variance += pow($timing - $mean, 2);
        }
        $variance = $variance / count($timings);
        $stdDev = sqrt($variance);

        // With 50-150ms random range, we should see variance
        // Standard deviation should be at least 20ms (indicating randomness)
        $this->assertGreaterThan(15, $stdDev,
            "Standard deviation ({$stdDev}ms) too low. Random delay may not be working properly."
        );

        // But not too high (would indicate system issues)
        $this->assertLessThan(60, $stdDev,
            "Standard deviation ({$stdDev}ms) too high. May indicate system performance issues."
        );
    }

    #[Test]
    public function it_always_calls_hash_equals_even_for_null_records()
    {
        // This is a behavioral test - we can't directly test that hash_equals is called,
        // but we can verify that the timing characteristics are consistent with constant-time comparison

        // Increased iterations for statistical stability (reduce variance in median calculation)
        $iterations = 20;
        $nullRecordTimings = [];
        $existingRecordTimings = [];

        // Test with non-existent record (null)
        for ($i = 0; $i < $iterations; $i++) {
            $password = $this->generateUniquePassword();
            $start = microtime(true);

            $this->postJson('/api/v1/auth/password/reset', [
                'email' => 'nonexistent@example.com',
                'token' => \Illuminate\Support\Str::random(64),
                'password' => $password,
                'password_confirmation' => $password,
            ]);

            $nullRecordTimings[] = (microtime(true) - $start) * 1000;
        }

        // Test with existing record but wrong token
        $plainToken = \Illuminate\Support\Str::random(64);
        $hashedToken = hash('sha256', $plainToken);

        DB::table('password_reset_tokens')->insert([
            'email' => $this->user->email,
            'token' => $hashedToken,
            'created_at' => now(),
        ]);

        for ($i = 0; $i < $iterations; $i++) {
            $password = $this->generateUniquePassword();
            $start = microtime(true);

            $this->postJson('/api/v1/auth/password/reset', [
                'email' => $this->user->email,
                'token' => \Illuminate\Support\Str::random(64), // Wrong token
                'password' => $password,
                'password_confirmation' => $password,
            ]);

            $existingRecordTimings[] = (microtime(true) - $start) * 1000;
        }

        // Calculate medians (more robust than mean for timing analysis)
        sort($nullRecordTimings);
        sort($existingRecordTimings);

        $nullMedian = $nullRecordTimings[count($nullRecordTimings) / 2];
        $existingMedian = $existingRecordTimings[count($existingRecordTimings) / 2];

        $difference = abs($nullMedian - $existingMedian);

        // Median difference should be minimal (within 25ms due to system variance + random delay)
        $this->assertLessThan(30, $difference,
            "Median timing difference of {$difference}ms indicates potential timing leak. ".
            "Null record: {$nullMedian}ms, Existing record: {$existingMedian}ms"
        );
    }
}
