<?php

namespace Tests\Integration\Auth;

use App\Models\User;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Hash;
use PHPUnit\Framework\Attributes\Test;
use Tests\Integration\IntegrationTestCase;

class LegacyPasswordResetTokenTest extends IntegrationTestCase
{
    #[Test]
    public function it_answers_a_reset_against_a_legacy_sha256_token_like_an_invalid_token(): void
    {
        $user = User::factory()->create(['password' => Hash::make('OldPassword123!')]);
        DB::table('password_reset_tokens')->insert([
            'email' => $user->email,
            'token' => hash('sha256', 'legacy-plain-token'),
            'created_at' => now(),
        ]);

        $response = $this->postJson('/api/v1/auth/password/reset', [
            'email' => $user->email,
            'token' => 'legacy-plain-token',
            'password' => 'Zx9!kP2#qL5@wN8&',
            'password_confirmation' => 'Zx9!kP2#qL5@wN8&',
        ]);

        $response->assertStatus(422)->assertJson([
            'message' => 'Invalid or expired password reset token.',
            'error' => 'invalid_token',
        ]);
        $this->assertTrue(Hash::check('OldPassword123!', $user->fresh()->password));
    }

    #[Test]
    public function it_deletes_non_bcrypt_reset_tokens_and_keeps_bcrypt_ones(): void
    {
        DB::table('password_reset_tokens')->insert([
            ['email' => 'legacy@example.com', 'token' => hash('sha256', 'legacy'), 'created_at' => now()],
            ['email' => 'current@example.com', 'token' => Hash::make('current'), 'created_at' => now()],
        ]);

        (require database_path('migrations/2026_10_15_183117_delete_legacy_password_reset_tokens.php'))->up();

        $this->assertSame(['current@example.com'], DB::table('password_reset_tokens')->pluck('email')->all());
    }
}
