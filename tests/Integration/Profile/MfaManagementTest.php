<?php

namespace Tests\Integration\Profile;

use App\Models\User;
use Illuminate\Support\Facades\Hash;
use PragmaRX\Google2FA\Google2FA;
use Tests\Integration\IntegrationTestCase;

/**
 * MFA Management Integration Tests
 *
 * Tests complete Multi-Factor Authentication flows including:
 * - TOTP setup and QR code generation
 * - TOTP verification and validation
 * - MFA enable/disable operations
 * - Recovery code generation and regeneration
 * - Using recovery codes for authentication
 * - Viewing backup codes with password verification
 * - Invalid and expired TOTP code handling
 * - MFA status checking
 *
 * @see \App\Http\Controllers\Api\ProfileController
 */
class MfaManagementTest extends IntegrationTestCase
{
    protected User $user;

    protected Google2FA $google2fa;

    protected function setUp(): void
    {
        parent::setUp();

        // Create test user without MFA enabled
        $this->user = $this->createUser([
            'name' => 'Test User',
            'email' => 'test@example.com',
            'password' => Hash::make('password123'),
            'email_verified_at' => now(),
        ]);

        $this->google2fa = new Google2FA();
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function user_can_setup_totp_mfa(): void
    {
        // ARRANGE: User without MFA

        // ACT: Setup TOTP
        $response = $this->actingAs($this->user, 'api')
            ->postJson('/api/v1/mfa/setup');

        // ASSERT: Returns secret and QR code URL
        $response->assertOk();
        $response->assertJsonStructure([
            'success',
            'data' => [
                'secret',
                'qr_code_url',
                'backup_codes',
            ],
            'message',
        ]);

        $data = $response->json('data');
        $this->assertNotEmpty($data['secret']);
        $this->assertStringContainsString('otpauth://totp/', $data['qr_code_url']);
        // Email in QR code URL is URL-encoded (@ becomes %40)
        $this->assertStringContainsString(urlencode($this->user->email), $data['qr_code_url']);

        // Verify secret stored in database (encrypted)
        $this->user->refresh();
        $this->assertNotNull($this->user->two_factor_secret);

        // Verify MFA not yet enabled (requires verification)
        $this->assertNull($this->user->two_factor_confirmed_at);
        $this->assertFalse($this->user->hasMfaEnabled());
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function user_can_verify_and_enable_totp(): void
    {
        // ARRANGE: User with TOTP setup
        $secret = $this->google2fa->generateSecretKey();
        $this->user->update([
            'two_factor_secret' => encrypt($secret),
        ]);

        // Generate valid TOTP code
        $validCode = $this->google2fa->getCurrentOtp($secret);

        // ACT: Verify TOTP code
        $response = $this->actingAs($this->user, 'api')
            ->postJson('/api/v1/mfa/verify/totp', [
                'code' => $validCode,
            ]);

        // ASSERT: MFA enabled successfully
        $response->assertOk();
        $response->assertJsonStructure([
            'data' => [
                'backup_codes',
            ],
            'message',
        ]);

        // Verify backup codes generated
        $backupCodes = $response->json('data.backup_codes');
        $this->assertCount(8, $backupCodes);
        foreach ($backupCodes as $code) {
            $this->assertEquals(8, strlen($code)); // 8 character codes
            $this->assertMatchesRegularExpression('/^[A-Z0-9]+$/', $code);
        }

        // Verify MFA enabled in database
        $this->user->refresh();
        $this->assertTrue($this->user->hasMfaEnabled());
        $this->assertNotNull($this->user->two_factor_confirmed_at);
        $this->assertEquals(['totp'], $this->user->mfa_methods);
        $this->assertNotNull($this->user->two_factor_recovery_codes);

        // ASSERT: MFA enabled event logged
        $this->assertAuthenticationLogged([
            'user_id' => $this->user->id,
            'event' => 'mfa_enabled',
        ]);
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function invalid_totp_code_rejected(): void
    {
        // ARRANGE: User with TOTP setup
        $secret = $this->google2fa->generateSecretKey();
        $this->user->update([
            'two_factor_secret' => encrypt($secret),
        ]);

        // ACT: Submit invalid code
        $response = $this->actingAs($this->user, 'api')
            ->postJson('/api/v1/mfa/verify/totp', [
                'code' => '000000', // Invalid code
            ]);

        // ASSERT: Verification fails
        $response->assertUnauthorized();
        $response->assertJson([
            'error' => 'authentication_failed',
            'error_description' => 'Invalid TOTP code.',
        ]);

        // Verify MFA not enabled
        $this->user->refresh();
        $this->assertFalse($this->user->hasMfaEnabled());
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function user_can_disable_mfa_with_password(): void
    {
        // ARRANGE: User with MFA enabled
        $secret = $this->google2fa->generateSecretKey();
        $backupCodes = $this->generateBackupCodes();

        $this->user->update([
            'two_factor_secret' => encrypt($secret),
            'two_factor_confirmed_at' => now(),
            'mfa_methods' => ['totp'],
            'two_factor_recovery_codes' => json_encode($backupCodes),
        ]);

        $this->assertTrue($this->user->hasMfaEnabled());

        // Generate valid TOTP code
        $validCode = $this->google2fa->getCurrentOtp($secret);

        // ACT: Disable MFA with password and code
        $response = $this->actingAs($this->user, 'api')
            ->postJson('/api/v1/mfa/disable/totp', [
                'password' => 'password123',
                'code' => $validCode,
            ]);

        // ASSERT: MFA disabled successfully
        $response->assertOk();
        $response->assertJson([
            'message' => 'TOTP disabled successfully.',
        ]);

        // Verify MFA disabled in database
        $this->user->refresh();
        $this->assertFalse($this->user->hasMfaEnabled());
        $this->assertNull($this->user->two_factor_secret);
        $this->assertNull($this->user->two_factor_confirmed_at);
        $this->assertNull($this->user->mfa_methods);
        $this->assertNull($this->user->two_factor_recovery_codes);

        // ASSERT: MFA disabled event logged
        $this->assertAuthenticationLogged([
            'user_id' => $this->user->id,
            'event' => 'mfa_disabled',
        ]);
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function mfa_disable_rejects_incorrect_password(): void
    {
        // ARRANGE: User with MFA enabled
        $secret = $this->google2fa->generateSecretKey();
        $this->user->update([
            'two_factor_secret' => encrypt($secret),
            'two_factor_confirmed_at' => now(),
            'mfa_methods' => ['totp'],
        ]);

        // ACT: Attempt to disable with wrong password
        $response = $this->actingAs($this->user, 'api')
            ->postJson('/api/v1/mfa/disable/totp', [
                'password' => 'wrongPassword',
                'code' => $this->google2fa->getCurrentOtp($secret),
            ]);

        // ASSERT: Request rejected
        $response->assertUnauthorized();
        $response->assertJson([
            'error' => 'authentication_failed',
            'error_description' => 'Password is incorrect.',
        ]);

        // Verify MFA still enabled
        $this->user->refresh();
        $this->assertTrue($this->user->hasMfaEnabled());
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function user_can_generate_recovery_codes(): void
    {
        // ARRANGE: User with MFA enabled
        $secret = $this->google2fa->generateSecretKey();
        $this->user->update([
            'two_factor_secret' => encrypt($secret),
            'two_factor_confirmed_at' => now(),
            'mfa_methods' => ['totp'],
            'two_factor_recovery_codes' => json_encode($this->generateBackupCodes()),
        ]);

        // ACT: Get recovery codes with password
        $response = $this->actingAs($this->user, 'api')
            ->postJson('/api/v1/mfa/recovery-codes', [
                'password' => 'password123',
            ]);

        // ASSERT: Returns recovery codes
        $response->assertOk();
        $response->assertJsonStructure([
            'data' => [
                'recovery_codes',
            ],
        ]);

        $codes = $response->json('data.recovery_codes');
        $this->assertIsArray($codes);
        $this->assertCount(8, $codes);
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function user_can_regenerate_recovery_codes(): void
    {
        // ARRANGE: User with MFA and existing recovery codes
        $secret = $this->google2fa->generateSecretKey();
        $oldBackupCodes = $this->generateBackupCodes();

        $this->user->update([
            'two_factor_secret' => encrypt($secret),
            'two_factor_confirmed_at' => now(),
            'mfa_methods' => ['totp'],
            'two_factor_recovery_codes' => json_encode($oldBackupCodes),
        ]);

        // ACT: Regenerate recovery codes
        $response = $this->actingAs($this->user, 'api')
            ->postJson('/api/v1/mfa/recovery-codes/regenerate', [
                'password' => 'password123',
            ]);

        // ASSERT: New codes generated
        $response->assertOk();
        $response->assertJsonStructure([
            'data' => [
                'recovery_codes',
            ],
            'message',
        ]);

        $newCodes = $response->json('data.recovery_codes');
        $this->assertCount(8, $newCodes);

        // Verify codes are different from old ones
        $this->assertNotEquals($oldBackupCodes, $newCodes);

        // Verify stored in database
        $this->user->refresh();
        $storedCodes = json_decode($this->user->two_factor_recovery_codes, true);
        $this->assertEquals($newCodes, $storedCodes);

        // ASSERT: Regeneration logged
        $this->assertAuthenticationLogged([
            'user_id' => $this->user->id,
            'event' => 'recovery_codes_regenerated',
        ]);
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function recovery_code_operations_require_mfa_enabled(): void
    {
        // ARRANGE: User without MFA enabled

        // ACT: Attempt to get recovery codes
        $response = $this->actingAs($this->user, 'api')
            ->postJson('/api/v1/mfa/recovery-codes', [
                'password' => 'password123',
            ]);

        // ASSERT: Request rejected
        $response->assertNotFound();
        $response->assertJson([
            'error' => 'resource_not_found',
            'error_description' => 'MFA is not enabled.',
        ]);

        // ACT: Attempt to regenerate recovery codes
        $response2 = $this->actingAs($this->user, 'api')
            ->postJson('/api/v1/mfa/recovery-codes/regenerate', [
                'password' => 'password123',
            ]);

        // ASSERT: Request rejected
        $response2->assertNotFound();
        $response2->assertJson([
            'error' => 'resource_not_found',
            'error_description' => 'MFA is not enabled.',
        ]);
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function user_can_view_mfa_status(): void
    {
        // ARRANGE: User with MFA enabled
        $secret = $this->google2fa->generateSecretKey();
        $backupCodes = $this->generateBackupCodes();

        $this->user->update([
            'two_factor_secret' => encrypt($secret),
            'two_factor_confirmed_at' => now(),
            'mfa_methods' => ['totp'],
            'two_factor_recovery_codes' => json_encode($backupCodes),
            'mfa_backup_codes' => $backupCodes,
        ]);

        // ACT: Get MFA status
        $response = $this->actingAs($this->user, 'api')
            ->getJson('/api/v1/mfa/status');

        // ASSERT: Returns complete MFA status
        $response->assertOk();
        $response->assertJsonStructure([
            'data' => [
                'mfa_enabled',
                'mfa_methods',
                'backup_codes',
                'backup_codes_count',
                'totp_configured',
            ],
        ]);

        $data = $response->json('data');
        $this->assertTrue($data['mfa_enabled']);
        $this->assertEquals(['totp'], $data['mfa_methods']);
        $this->assertEquals(8, $data['backup_codes_count']);
        $this->assertTrue($data['totp_configured']);
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function cannot_setup_mfa_when_already_enabled(): void
    {
        // ARRANGE: User with MFA already enabled
        $secret = $this->google2fa->generateSecretKey();
        $this->user->update([
            'two_factor_secret' => encrypt($secret),
            'two_factor_confirmed_at' => now(),
            'mfa_methods' => ['totp'],
        ]);

        // ACT: Attempt to setup TOTP again
        $response = $this->actingAs($this->user, 'api')
            ->postJson('/api/v1/mfa/setup');

        // ASSERT: Request rejected
        $response->assertStatus(409); // Conflict
        $response->assertJson([
            'success' => false,
            'error' => 'resource_conflict',
            'error_description' => 'MFA is already enabled for this account.',
        ]);
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function user_can_enable_mfa_via_enable_endpoint(): void
    {
        // ARRANGE: User with TOTP setup but not confirmed
        $secret = $this->google2fa->generateSecretKey();
        $this->user->update([
            'two_factor_secret' => encrypt($secret),
        ]);

        // Generate valid TOTP code
        $validCode = $this->google2fa->getCurrentOtp($secret);

        // ACT: Enable MFA via /enable endpoint
        $response = $this->actingAs($this->user, 'api')
            ->postJson('/api/v1/mfa/enable', [
                'code' => $validCode,
            ]);

        // ASSERT: MFA enabled successfully
        $response->assertOk();
        $response->assertJsonStructure([
            'success',
            'data' => [
                'backup_codes',
                'mfa_enabled',
                'methods',
            ],
            'message',
        ]);

        $data = $response->json('data');
        $this->assertTrue($data['mfa_enabled']);
        $this->assertEquals(['totp'], $data['methods']);
        $this->assertCount(8, $data['backup_codes']);

        // Verify in database
        $this->user->refresh();
        $this->assertTrue($this->user->hasMfaEnabled());
        $this->assertNotNull($this->user->two_factor_confirmed_at);

        // ASSERT: Event logged
        $this->assertAuthenticationLogged([
            'user_id' => $this->user->id,
            'event' => 'mfa_enabled',
        ]);
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function user_can_disable_mfa_via_disable_endpoint(): void
    {
        // ARRANGE: User with MFA enabled
        $secret = $this->google2fa->generateSecretKey();
        $this->user->update([
            'two_factor_secret' => encrypt($secret),
            'two_factor_confirmed_at' => now(),
            'mfa_methods' => ['totp'],
            'two_factor_recovery_codes' => json_encode($this->generateBackupCodes()),
        ]);

        // ACT: Disable MFA via /disable endpoint
        $response = $this->actingAs($this->user, 'api')
            ->postJson('/api/v1/mfa/disable', [
                'password' => 'password123',
            ]);

        // ASSERT: MFA disabled successfully
        $response->assertOk();
        $response->assertJsonStructure([
            'success',
            'data' => [
                'mfa_enabled',
                'methods',
            ],
            'message',
        ]);

        $data = $response->json('data');
        $this->assertFalse($data['mfa_enabled']);
        $this->assertEmpty($data['methods']);

        // Verify in database
        $this->user->refresh();
        $this->assertFalse($this->user->hasMfaEnabled());
        $this->assertNull($this->user->two_factor_secret);
        $this->assertNull($this->user->mfa_methods);

        // ASSERT: Event logged
        $this->assertAuthenticationLogged([
            'user_id' => $this->user->id,
            'event' => 'mfa_disabled',
        ]);
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function totp_verification_requires_setup_first(): void
    {
        // ARRANGE: User without TOTP setup

        // ACT: Attempt to verify without setup
        $response = $this->actingAs($this->user, 'api')
            ->postJson('/api/v1/mfa/verify/totp', [
                'code' => '123456',
            ]);

        // ASSERT: Request rejected
        $response->assertNotFound();
        $response->assertJson([
            'error' => 'resource_not_found',
            'error_description' => 'TOTP setup not initiated.',
        ]);
    }

    /**
     * Helper: Generate 8 random backup codes
     */
    protected function generateBackupCodes(): array
    {
        $codes = [];
        for ($i = 0; $i < 8; $i++) {
            $codes[] = strtoupper(substr(str_shuffle('0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ'), 0, 8));
        }

        return $codes;
    }
}
