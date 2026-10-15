<?php

namespace Tests\Unit\Security;

use App\Models\Organization;
use App\Models\User;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Routing\Middleware\ThrottleRequests;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Str;
use Illuminate\Testing\TestResponse;
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

    private const int PRODUCTION_BCRYPT_ROUNDS = 12;

    private const int SAMPLE_PAIRS = 10;

    private const float MEDIAN_TOLERANCE_RATIO = 0.3;

    private const int MINIMUM_RANDOM_DELAY_MS = 50;

    protected User $user;

    protected Organization $organization;

    protected function setUp(): void
    {
        parent::setUp();

        // Disable rate limiting middleware to accurately measure timing
        // Timing attack tests verify constant-time comparison logic, not rate limiting
        $this->withoutMiddleware(ThrottleRequests::class);

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
        return 'TestPass'.time().mt_rand(1000, 9999).'!Zx@9';
    }

    #[Test]
    public function it_applies_constant_time_validation_for_non_existent_tokens()
    {
        for ($i = 0; $i < 10; $i++) {
            $start = microtime(true);
            $response = $this->postReset('nonexistent@example.com', Str::random(64));
            $elapsedMs = (microtime(true) - $start) * 1000;

            $response->assertStatus(422);
            $response->assertJson(['error' => 'invalid_token']);
            $this->assertGreaterThanOrEqual(self::MINIMUM_RANDOM_DELAY_MS, $elapsedMs, 'Response faster than the minimum random delay');
        }
    }

    #[Test]
    public function it_uses_constant_time_comparison_even_when_record_does_not_exist()
    {
        $this->useProductionBcryptCost();
        DB::table('password_reset_tokens')->insert([
            'email' => $this->user->email,
            'token' => Hash::make(Str::random(60)),
            'created_at' => now(),
        ]);

        [$existing, $unknown] = $this->sampleInterleaved(
            fn () => $this->postReset($this->user->email, Str::random(64)),
            fn () => $this->postReset('nonexistent@example.com', Str::random(64)),
        );

        $this->assertMediansWithinTolerance($existing, $unknown, 'existing email, wrong token', 'unknown email');
    }

    #[Test]
    public function it_does_not_reveal_token_expiration_status_through_timing()
    {
        $this->useProductionBcryptCost();
        $plainToken = Str::random(64);
        $hashedToken = Hash::make($plainToken);
        $insertToken = fn ($createdAt) => DB::table('password_reset_tokens')->insert([
            'email' => $this->user->email,
            'token' => $hashedToken,
            'created_at' => $createdAt,
        ]);
        $clearTokens = fn () => DB::table('password_reset_tokens')->where('email', $this->user->email)->delete();

        [$expired, $invalid] = $this->sampleInterleaved(
            function () use ($insertToken, $clearTokens, $plainToken) {
                $insertToken(now()->subMinutes(61));
                $response = $this->postReset($this->user->email, $plainToken);
                $clearTokens();

                return $response;
            },
            function () use ($insertToken, $clearTokens) {
                $insertToken(now());
                $response = $this->postReset($this->user->email, Str::random(64));
                $clearTokens();

                return $response;
            },
        );

        $this->assertMediansWithinTolerance($expired, $invalid, 'expired token', 'wrong token');
    }

    #[Test]
    public function it_uses_generic_error_messages_for_all_failure_modes()
    {
        $password = $this->generateUniquePassword();

        // Test 1: Non-existent email
        $response1 = $this->postJson('/api/v1/auth/password/reset', [
            'email' => 'nonexistent@example.com',
            'token' => Str::random(64),
            'password' => $password,
            'password_confirmation' => $password,
        ]);

        // Test 2: Wrong token
        $plainToken = Str::random(64);
        $hashedToken = Hash::make($plainToken);
        DB::table('password_reset_tokens')->insert([
            'email' => $this->user->email,
            'token' => $hashedToken,
            'created_at' => now(),
        ]);

        $response2 = $this->postJson('/api/v1/auth/password/reset', [
            'email' => $this->user->email,
            'token' => Str::random(64), // Wrong token
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

        for ($i = 0; $i < 20; $i++) {
            $start = microtime(true);
            $this->postReset('test@example.com', Str::random(64));
            $timings[] = (microtime(true) - $start) * 1000;
        }

        $this->assertGreaterThanOrEqual(self::MINIMUM_RANDOM_DELAY_MS, min($timings), 'Random delay may not be applied');
        $this->assertGreaterThan(20, max($timings) - min($timings),
            'All 20 responses fell within 20ms of each other; the delay may not be random. Timings: '.implode(', ', array_map('round', $timings))
        );
    }

    private function useProductionBcryptCost(): void
    {
        config(['hashing.bcrypt.rounds' => self::PRODUCTION_BCRYPT_ROUNDS]);
        Hash::forgetDrivers();
    }

    private function postReset(string $email, string $token): TestResponse
    {
        $password = $this->generateUniquePassword();

        return $this->postJson('/api/v1/auth/password/reset', [
            'email' => $email,
            'token' => $token,
            'password' => $password,
            'password_confirmation' => $password,
        ]);
    }

    /**
     * @return array{0: list<float>, 1: list<float>}
     */
    private function sampleInterleaved(callable $first, callable $second): array
    {
        $measure = function (callable $request): float {
            $start = microtime(true);
            $request()->assertStatus(422);

            return (microtime(true) - $start) * 1000;
        };

        $measure($first);
        $measure($second);

        $firstTimings = [];
        $secondTimings = [];
        for ($i = 0; $i < self::SAMPLE_PAIRS; $i++) {
            if ($i % 2 === 0) {
                $firstTimings[] = $measure($first);
                $secondTimings[] = $measure($second);
            } else {
                $secondTimings[] = $measure($second);
                $firstTimings[] = $measure($first);
            }
        }

        return [$firstTimings, $secondTimings];
    }

    /**
     * @param  list<float>  $firstTimings
     * @param  list<float>  $secondTimings
     */
    private function assertMediansWithinTolerance(array $firstTimings, array $secondTimings, string $firstLabel, string $secondLabel): void
    {
        $firstMedian = $this->median($firstTimings);
        $secondMedian = $this->median($secondTimings);
        $difference = abs($firstMedian - $secondMedian);
        $tolerance = self::MEDIAN_TOLERANCE_RATIO * max($firstMedian, $secondMedian);

        $this->assertLessThan($tolerance, $difference, sprintf(
            'Median timing difference of %.1fms exceeds %.1fms. %s: %.1fms, %s: %.1fms.',
            $difference, $tolerance, $firstLabel, $firstMedian, $secondLabel, $secondMedian
        ));
    }

    /**
     * @param  list<float>  $timings
     */
    private function median(array $timings): float
    {
        sort($timings);
        $middle = intdiv(count($timings), 2);

        return count($timings) % 2 === 0
            ? ($timings[$middle - 1] + $timings[$middle]) / 2
            : $timings[$middle];
    }
}
