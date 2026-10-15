<?php

namespace Tests\Integration\Auth;

use App\Models\Organization;
use App\Models\User;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Notification;
use Illuminate\Support\Str;
use Illuminate\Testing\TestResponse;
use Laravel\Passport\Token;
use PHPUnit\Framework\Attributes\Test;
use Tests\TestCase;

/**
 * Integration tests for Password Reset Flow
 *
 * Tests the complete password reset workflow including:
 * - Request reset with email enumeration protection
 * - Token hashing and expiration
 * - Password reset with validation
 * - Token single-use enforcement
 * - Session revocation on password change
 */
class PasswordResetFlowTest extends TestCase
{
    use RefreshDatabase;

    protected User $user;

    protected Organization $organization;

    protected function setUp(): void
    {
        parent::setUp();

        $this->organization = Organization::factory()->create();
        $this->user = User::factory()->create([
            'organization_id' => $this->organization->id,
            'email' => 'testuser@example.com',
            'password' => Hash::make('OldPassword123!'),
        ]);

        Notification::fake();
    }

    #[Test]
    public function it_can_request_password_reset_for_valid_email()
    {
        $response = $this->postJson('/api/v1/auth/password/email', [
            'email' => $this->user->email,
        ]);

        $response->assertOk();
        $response->assertJson([
            'message' => 'If that email address is in our system, we have sent a password reset link to it.',
        ]);

        // Verify token was created and hashed
        $tokenRecord = DB::table('password_reset_tokens')
            ->where('email', $this->user->email)
            ->first();

        $this->assertNotNull($tokenRecord);
        $this->assertEquals($this->user->email, $tokenRecord->email);
        $this->assertGreaterThan(40, strlen($tokenRecord->token)); // Hashed tokens are longer
        $this->assertNotNull($tokenRecord->created_at);
    }

    #[Test]
    public function it_returns_generic_message_for_invalid_email()
    {
        $response = $this->postJson('/api/v1/auth/password/email', [
            'email' => 'nonexistent@example.com',
        ]);

        // SECURITY: Same response for valid and invalid emails (prevent enumeration)
        $response->assertOk();
        $response->assertJson([
            'message' => 'If that email address is in our system, we have sent a password reset link to it.',
        ]);

        // Verify no token was created
        $tokenRecord = DB::table('password_reset_tokens')
            ->where('email', 'nonexistent@example.com')
            ->first();

        $this->assertNull($tokenRecord);
    }

    #[Test]
    public function it_can_reset_password_with_valid_token()
    {
        // Request reset
        $this->postJson('/api/v1/auth/password/email', [
            'email' => $this->user->email,
        ]);

        // Get the hashed token from database
        $hashedToken = DB::table('password_reset_tokens')
            ->where('email', $this->user->email)
            ->value('token');

        $this->assertNotNull($hashedToken);

        // Note: In real implementation, the plain token would be in the email
        // For testing, we need to simulate having the plain token
        // We'll generate a new token and hash to simulate the flow
        $plainToken = Str::random(60);
        $hashedToken = Hash::make($plainToken);

        // Update the database with our test token
        DB::table('password_reset_tokens')
            ->where('email', $this->user->email)
            ->update(['token' => $hashedToken]);

        // Create a token for the user to verify revocation
        $oldToken = $this->user->createToken('Test Token')->token;

        // Reset password (use a unique password unlikely to be in breach databases)
        $response = $this->postJson('/api/v1/auth/password/reset', [
            'email' => $this->user->email,
            'token' => $plainToken,
            'password' => 'Zx9!kP2#qL5@wN8&',
            'password_confirmation' => 'Zx9!kP2#qL5@wN8&',
        ]);

        $response->assertOk();
        $response->assertJsonStructure([
            'message',
            'user' => ['id', 'name', 'email'],
            'token' => ['access_token', 'token_type', 'expires_at'],
        ]);

        // Verify password was changed
        $this->user->refresh();
        $this->assertTrue(Hash::check('Zx9!kP2#qL5@wN8&', $this->user->password));
        $this->assertNotNull($this->user->password_changed_at);

        // Verify token was deleted (single-use)
        $tokenRecord = DB::table('password_reset_tokens')
            ->where('email', $this->user->email)
            ->first();

        $this->assertNull($tokenRecord);

        // Verify old tokens were revoked
        $oldToken->refresh();
        $this->assertTrue($oldToken->revoked);
    }

    #[Test]
    public function it_prevents_token_reuse()
    {
        // Request reset
        $this->postJson('/api/v1/auth/password/email', [
            'email' => $this->user->email,
        ]);

        // Simulate having the plain token
        $plainToken = Str::random(60);
        $hashedToken = Hash::make($plainToken);

        DB::table('password_reset_tokens')
            ->where('email', $this->user->email)
            ->update(['token' => $hashedToken]);

        // Use token once
        $response1 = $this->postJson('/api/v1/auth/password/reset', [
            'email' => $this->user->email,
            'token' => $plainToken,
            'password' => 'Ky8@mT3!vR7#nQ2%',
            'password_confirmation' => 'Ky8@mT3!vR7#nQ2%',
        ]);

        $response1->assertOk();

        // Try to reuse token
        $response2 = $this->postJson('/api/v1/auth/password/reset', [
            'email' => $this->user->email,
            'token' => $plainToken,
            'password' => 'Bv6#hG9@pF4!xW1&',
            'password_confirmation' => 'Bv6#hG9@pF4!xW1&',
        ]);

        $response2->assertStatus(422);
        $response2->assertJson([
            'message' => 'Invalid or expired password reset token.',
            'error' => 'invalid_token',
        ]);
    }

    #[Test]
    public function it_validates_token_expiration()
    {
        // Create an expired token (older than 60 minutes)
        $plainToken = Str::random(60);
        $hashedToken = Hash::make($plainToken);

        DB::table('password_reset_tokens')->insert([
            'email' => $this->user->email,
            'token' => $hashedToken,
            'created_at' => now()->subMinutes(61), // Expired
        ]);

        $response = $this->postJson('/api/v1/auth/password/reset', [
            'email' => $this->user->email,
            'token' => $plainToken,
            'password' => 'Jm4!dX8@cN2#tB9&',
            'password_confirmation' => 'Jm4!dX8@cN2#tB9&',
        ]);

        $response->assertStatus(422);
        // SECURITY: Generic error message prevents revealing whether token is expired vs invalid
        // This prevents timing attacks and information leakage
        $response->assertJsonFragment(['error' => 'invalid_token']);

        // Verify token was deleted
        $tokenRecord = DB::table('password_reset_tokens')
            ->where('email', $this->user->email)
            ->first();

        $this->assertNull($tokenRecord);
    }

    #[Test]
    public function it_validates_password_complexity()
    {
        // Request reset
        $this->postJson('/api/v1/auth/password/email', [
            'email' => $this->user->email,
        ]);

        $plainToken = Str::random(60);
        $hashedToken = Hash::make($plainToken);

        DB::table('password_reset_tokens')
            ->where('email', $this->user->email)
            ->update(['token' => $hashedToken]);

        // Try with weak password
        $response = $this->postJson('/api/v1/auth/password/reset', [
            'email' => $this->user->email,
            'token' => $plainToken,
            'password' => 'weak',
            'password_confirmation' => 'weak',
        ]);

        $response->assertStatus(422);
        $response->assertJsonValidationErrors(['password']);
    }

    #[Test]
    public function it_enforces_rate_limiting()
    {
        // Make 6 requests (limit is 5 per hour)
        for ($i = 0; $i < 6; $i++) {
            $response = $this->postJson('/api/v1/auth/password/email', [
                'email' => $this->user->email,
            ]);

            if ($i < 5) {
                $response->assertOk();
            } else {
                $response->assertStatus(429); // Too Many Requests
            }
        }
    }

    #[Test]
    public function it_revokes_all_tokens_on_password_change()
    {
        // Create multiple tokens
        $token1 = $this->user->createToken('Token 1')->token;
        $token2 = $this->user->createToken('Token 2')->token;
        $token3 = $this->user->createToken('Token 3')->token;

        // Verify tokens are active
        $this->assertFalse($token1->revoked);
        $this->assertFalse($token2->revoked);
        $this->assertFalse($token3->revoked);

        // Reset password
        $plainToken = Str::random(60);
        $hashedToken = Hash::make($plainToken);

        DB::table('password_reset_tokens')->insert([
            'email' => $this->user->email,
            'token' => $hashedToken,
            'created_at' => now(),
        ]);

        $this->postJson('/api/v1/auth/password/reset', [
            'email' => $this->user->email,
            'token' => $plainToken,
            'password' => 'Wp3@fY7!hK9#mS5&',
            'password_confirmation' => 'Wp3@fY7!hK9#mS5&',
        ]);

        // Verify all tokens were revoked
        $token1->refresh();
        $token2->refresh();
        $token3->refresh();

        $this->assertTrue($token1->revoked);
        $this->assertTrue($token2->revoked);
        $this->assertTrue($token3->revoked);
    }

    #[Test]
    public function it_validates_required_fields()
    {
        // Test email endpoint
        $response = $this->postJson('/api/v1/auth/password/email', []);

        $response->assertStatus(422);
        $response->assertJsonValidationErrors(['email']);

        // Test reset endpoint
        $response = $this->postJson('/api/v1/auth/password/reset', []);

        $response->assertStatus(422);
        $response->assertJsonValidationErrors(['email', 'token', 'password']);
    }

    #[Test]
    public function it_replaces_existing_tokens_on_new_request()
    {
        // Request reset
        $this->postJson('/api/v1/auth/password/email', [
            'email' => $this->user->email,
        ]);

        $firstToken = DB::table('password_reset_tokens')
            ->where('email', $this->user->email)
            ->first();

        $this->assertNotNull($firstToken);

        // Request another reset (should replace the first token)
        sleep(1); // Ensure different timestamp
        $this->postJson('/api/v1/auth/password/email', [
            'email' => $this->user->email,
        ]);

        // Should only have one token
        $tokens = DB::table('password_reset_tokens')
            ->where('email', $this->user->email)
            ->get();

        $this->assertCount(1, $tokens);

        // Token should be different
        $secondToken = $tokens->first();
        $this->assertNotEquals($firstToken->created_at, $secondToken->created_at);
    }

    #[Test]
    public function it_challenges_a_user_with_mfa_instead_of_signing_them_in_after_a_reset(): void
    {
        $user = User::factory()->withMfa()->create();

        $response = $this->resetPasswordFor($user);

        $response->assertStatus(202)
            ->assertJsonPath('mfa_required', true)
            ->assertJsonStructure(['message', 'challenge_token', 'available_methods'])
            ->assertJsonMissingPath('token');
        $this->assertTrue(Hash::check('Zx9!kP2#qL5@wN8&', $user->fresh()->password));
        $this->assertSame(0, $user->tokens()->count());
        $this->assertDatabaseHas('authentication_logs', ['user_id' => $user->id, 'event' => 'mfa_required']);
    }

    #[Test]
    public function it_issues_only_a_setup_token_to_a_member_who_must_set_up_mfa_after_a_reset(): void
    {
        $organization = Organization::factory()->create(['settings' => ['require_mfa' => true]]);
        $user = User::factory()->forOrganization($organization)->create();

        $response = $this->resetPasswordFor($user);

        $response->assertForbidden()
            ->assertJsonPath('error', 'mfa_setup_required')
            ->assertJsonStructure(['message', 'setup_token', 'token_type', 'expires_in'])
            ->assertJsonMissingPath('token');
        $this->assertTrue(Hash::check('Zx9!kP2#qL5@wN8&', $user->fresh()->password));
        $this->assertSame([['mfa.setup']], $user->tokens()->pluck('scopes')->all());
        $this->assertDatabaseHas('authentication_logs', ['user_id' => $user->id, 'event' => 'mfa_setup_required']);
    }

    private function resetPasswordFor(User $user): TestResponse
    {
        DB::table('password_reset_tokens')->insert([
            'email' => $user->email,
            'token' => Hash::make('plain-reset-token'),
            'created_at' => now(),
        ]);

        return $this->postJson('/api/v1/auth/password/reset', [
            'email' => $user->email,
            'token' => 'plain-reset-token',
            'password' => 'Zx9!kP2#qL5@wN8&',
            'password_confirmation' => 'Zx9!kP2#qL5@wN8&',
        ]);
    }
}
