<?php

namespace Tests\Feature\Api;

use App\Models\AuthenticationLog;
use App\Models\Organization;
use App\Models\User;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Http\UploadedFile;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Storage;
use Laravel\Passport\Passport;
use PragmaRX\Google2FA\Google2FA;
use Spatie\Permission\Models\Role;
use Tests\TestCase;

class ProfileApiTest extends TestCase
{
    use RefreshDatabase;

    private Organization $organization;

    private User $user;

    protected function setUp(): void
    {
        parent::setUp();

        $this->organization = Organization::factory()->create();

        // Create required roles
        Role::firstOrCreate(['name' => 'User', 'guard_name' => 'api']);
        Role::firstOrCreate(['name' => 'Super Admin', 'guard_name' => 'api']);
        Role::firstOrCreate(['name' => 'user', 'guard_name' => 'web']);
        Role::firstOrCreate(['name' => 'super admin', 'guard_name' => 'web']);

        $this->user = User::factory()
            ->forOrganization($this->organization)
            ->create([
                'password' => Hash::make('password123'),
                'profile' => [
                    'bio' => 'Test bio',
                    'department' => 'Engineering',
                    'preferences' => [
                        'timezone' => 'UTC',
                        'language' => 'en',
                        'theme' => 'light',
                    ],
                ],
            ]);

        // Set team context and assign role properly
        $userRole = Role::where('name', 'User')->where('guard_name', 'api')->first();
        $this->user->setPermissionsTeamId($this->user->organization_id);
        $this->user->assignRole($userRole);
    }

    public function test_get_profile_returns_complete_user_data(): void
    {
        Passport::actingAs($this->user, ['profile']);

        $response = $this->getJson('/api/v1/profile');

        $response->assertStatus(200)
            ->assertJsonStructure([
                'data' => [
                    'id',
                    'name',
                    'email',
                    'avatar',
                    'email_verified_at',
                    'profile',
                    'mfa_enabled',
                    'mfa_methods',
                    'organization' => [
                        'id',
                        'name',
                        'slug',
                    ],
                    'roles',
                    'created_at',
                    'updated_at',
                ],
            ])
            ->assertJson([
                'data' => [
                    'id' => $this->user->id,
                    'email' => $this->user->email,
                    'name' => $this->user->name,
                    'mfa_enabled' => false,
                    'profile' => [
                        'bio' => 'Test bio',
                        'department' => 'Engineering',
                    ],
                    'organization' => [
                        'id' => $this->organization->id,
                        'name' => $this->organization->name,
                        'slug' => $this->organization->slug,
                    ],
                ],
            ]);
    }

    public function test_get_profile_requires_authentication(): void
    {
        $response = $this->getJson('/api/v1/profile');

        $response->assertStatus(401)
            ->assertJson(['message' => 'Unauthenticated.']);
    }

    public function test_update_profile_with_valid_data_succeeds(): void
    {
        Passport::actingAs($this->user, ['profile']);

        $updateData = [
            'name' => 'Updated Name',
            'email' => 'updated@example.com',
            'profile' => [
                'bio' => 'Updated bio',
                'department' => 'Marketing',
                'job_title' => 'Senior Developer',
            ],
        ];

        $response = $this->putJson('/api/v1/profile', $updateData);

        $response->assertStatus(200)
            ->assertJsonStructure([
                'data' => [
                    'id',
                    'name',
                    'email',
                    'avatar',
                    'email_verified_at',
                    'profile',
                    'mfa_enabled',
                    'updated_at',
                ],
                'message',
            ])
            ->assertJson([
                'data' => [
                    'name' => 'Updated Name',
                    'email' => 'updated@example.com',
                    'email_verified_at' => null, // Should be reset when email changes
                ],
                'message' => 'Profile updated successfully',
            ]);

        $this->assertDatabaseHas('users', [
            'id' => $this->user->id,
            'name' => 'Updated Name',
            'email' => 'updated@example.com',
            'email_verified_at' => null,
        ]);

        // Verify profile data was merged correctly
        $updatedUser = $this->user->fresh();
        $this->assertEquals('Updated bio', $updatedUser->profile['bio']);
        $this->assertEquals('Marketing', $updatedUser->profile['department']);
        $this->assertEquals('Senior Developer', $updatedUser->profile['job_title']);

        // Verify authentication log
        $this->assertDatabaseHas('authentication_logs', [
            'user_id' => $this->user->id,
            'event' => 'profile_updated',
        ]);
    }

    public function test_update_profile_with_duplicate_email_fails(): void
    {
        $otherUser = User::factory()
            ->forOrganization($this->organization)
            ->create(['email' => 'existing@example.com']);

        Passport::actingAs($this->user, ['profile']);

        $updateData = [
            'email' => 'existing@example.com',
        ];

        $response = $this->putJson('/api/v1/profile', $updateData);

        $response->assertStatus(422)
            ->assertJsonStructure([
                'error',
                'error_description',
                'details',
            ])
            ->assertJson([
                'error' => 'validation_failed',
            ]);
    }

    public function test_update_profile_requires_authentication(): void
    {
        $updateData = ['name' => 'Updated Name'];

        $response = $this->putJson('/api/v1/profile', $updateData);

        $response->assertStatus(401);
    }

    public function test_upload_avatar_with_valid_image_succeeds(): void
    {
        Storage::fake('public');
        Passport::actingAs($this->user, ['profile']);

        $file = UploadedFile::fake()->image('avatar.png', 400, 400)->size(1024);

        $response = $this->postJson('/api/v1/profile/avatar', [
            'avatar' => $file,
        ]);

        $response->assertStatus(200)
            ->assertJsonStructure([
                'data' => [
                    'avatar',
                    'avatar_url',
                ],
                'message',
            ])
            ->assertJson([
                'message' => 'Avatar uploaded successfully',
            ]);

        // Verify avatar was stored
        $updatedUser = $this->user->fresh();
        $this->assertNotNull($updatedUser->avatar);
        Storage::disk('public')->assertExists($updatedUser->avatar);
    }

    public function test_upload_avatar_replaces_existing_avatar(): void
    {
        Storage::fake('public');
        Passport::actingAs($this->user, ['profile']);

        // Create an existing avatar
        $oldAvatarPath = 'avatars/old-avatar.png';
        Storage::disk('public')->put($oldAvatarPath, 'old avatar content');
        $this->user->update(['avatar' => $oldAvatarPath]);

        $file = UploadedFile::fake()->image('new-avatar.png', 400, 400);

        $response = $this->postJson('/api/v1/profile/avatar', [
            'avatar' => $file,
        ]);

        $response->assertStatus(200);

        // Verify old avatar was deleted and new one was created
        Storage::disk('public')->assertMissing($oldAvatarPath);

        $updatedUser = $this->user->fresh();
        $this->assertNotEquals($oldAvatarPath, $updatedUser->avatar);
        Storage::disk('public')->assertExists($updatedUser->avatar);
    }

    public function test_upload_avatar_with_invalid_file_fails(): void
    {
        Passport::actingAs($this->user, ['profile']);

        // Test with non-image file
        $file = UploadedFile::fake()->create('document.pdf', 1024);

        $response = $this->postJson('/api/v1/profile/avatar', [
            'avatar' => $file,
        ]);

        $response->assertStatus(422)
            ->assertJsonStructure([
                'error',
                'error_description',
                'details',
            ]);
    }

    public function test_upload_avatar_with_oversized_file_fails(): void
    {
        Passport::actingAs($this->user, ['profile']);

        // Test with oversized file (>2MB)
        $file = UploadedFile::fake()->image('large-avatar.png')->size(3000);

        $response = $this->postJson('/api/v1/profile/avatar', [
            'avatar' => $file,
        ]);

        $response->assertStatus(422);
    }

    public function test_remove_avatar_deletes_existing_avatar(): void
    {
        Storage::fake('public');
        Passport::actingAs($this->user, ['profile']);

        // Create an existing avatar
        $avatarPath = 'avatars/test-avatar.png';
        Storage::disk('public')->put($avatarPath, 'avatar content');
        $this->user->update(['avatar' => $avatarPath]);

        $response = $this->deleteJson('/api/v1/profile/avatar');

        $response->assertStatus(200)
            ->assertJson([
                'message' => 'Avatar removed successfully',
            ]);

        // Verify avatar was deleted
        Storage::disk('public')->assertMissing($avatarPath);
        $this->assertDatabaseHas('users', [
            'id' => $this->user->id,
            'avatar' => null,
        ]);
    }

    public function test_remove_avatar_when_no_avatar_exists(): void
    {
        Passport::actingAs($this->user, ['profile']);

        $response = $this->deleteJson('/api/v1/profile/avatar');

        $response->assertStatus(200)
            ->assertJson([
                'message' => 'Avatar removed successfully',
            ]);
    }

    public function test_get_preferences_returns_merged_preferences(): void
    {
        Passport::actingAs($this->user, ['profile']);

        $response = $this->getJson('/api/v1/profile/preferences');

        $response->assertStatus(200)
            ->assertJsonStructure([
                'data' => [
                    'timezone',
                    'language',
                    'theme',
                    'date_format',
                    'time_format',
                    'email_notifications',
                    'security_alerts',
                    'marketing_emails',
                ],
            ])
            ->assertJson([
                'data' => [
                    'timezone' => 'UTC',
                    'language' => 'en',
                    'theme' => 'light',
                    'date_format' => 'Y-m-d',
                    'time_format' => 'H:i',
                    'email_notifications' => true,
                    'security_alerts' => true,
                    'marketing_emails' => false,
                ],
            ]);
    }

    public function test_update_preferences_with_valid_data_succeeds(): void
    {
        Passport::actingAs($this->user, ['profile']);

        $preferences = [
            'timezone' => 'America/New_York',
            'language' => 'es',
            'theme' => 'dark',
            'date_format' => 'm/d/Y',
            'time_format' => 'h:i A',
            'email_notifications' => false,
            'marketing_emails' => true,
        ];

        $response = $this->putJson('/api/v1/profile/preferences', $preferences);

        $response->assertStatus(200)
            ->assertJson([
                'data' => $preferences,
                'message' => 'Preferences updated successfully',
            ]);

        // Verify preferences were stored correctly
        $updatedUser = $this->user->fresh();
        $storedPreferences = $updatedUser->profile['preferences'];

        $this->assertEquals('America/New_York', $storedPreferences['timezone']);
        $this->assertEquals('es', $storedPreferences['language']);
        $this->assertEquals('dark', $storedPreferences['theme']);
        $this->assertEquals('m/d/Y', $storedPreferences['date_format']);
        $this->assertEquals('h:i A', $storedPreferences['time_format']);
        $this->assertFalse($storedPreferences['email_notifications']);
        $this->assertTrue($storedPreferences['marketing_emails']);
    }

    public function test_update_preferences_with_invalid_data_fails(): void
    {
        Passport::actingAs($this->user, ['profile']);

        $preferences = [
            'timezone' => 'Invalid/Timezone',
            'language' => 'invalid_language',
            'theme' => 'invalid_theme',
        ];

        $response = $this->putJson('/api/v1/profile/preferences', $preferences);

        $response->assertStatus(422)
            ->assertJsonStructure([
                'error',
                'error_description',
                'details',
            ]);
    }

    public function test_get_security_returns_security_information(): void
    {
        Passport::actingAs($this->user, ['profile']);

        // Create some authentication logs for testing
        AuthenticationLog::factory()->create([
            'user_id' => $this->user->id,
            'event' => 'login_success',
            'ip_address' => '192.168.1.1',
            'user_agent' => 'Test Browser',
        ]);

        $response = $this->getJson('/api/v1/profile/security');

        $response->assertStatus(200)
            ->assertJsonStructure([
                'data' => [
                    'mfa_enabled',
                    'mfa_methods',
                    'recovery_codes_count',
                    'password_changed_at',
                    'active_sessions',
                    'recent_logins',
                ],
            ])
            ->assertJson([
                'data' => [
                    'mfa_enabled' => false,
                    'mfa_methods' => [],
                    'recovery_codes_count' => 0,
                ],
            ]);
    }

    public function test_change_password_with_correct_current_password_succeeds(): void
    {
        Passport::actingAs($this->user, ['profile']);

        $passwordData = [
            'current_password' => 'password123',
            'password' => 'UniqueStrongP@ssw0rd2024!',
            'password_confirmation' => 'UniqueStrongP@ssw0rd2024!',
        ];

        $response = $this->postJson('/api/v1/profile/change-password', $passwordData);

        $response->assertStatus(200)
            ->assertJson([
                'message' => 'Password changed successfully',
            ]);

        // Verify password was changed
        $updatedUser = $this->user->fresh();
        $this->assertTrue(Hash::check('UniqueStrongP@ssw0rd2024!', $updatedUser->password));
        $this->assertNotNull($updatedUser->password_changed_at);

        // Verify authentication log
        $this->assertDatabaseHas('authentication_logs', [
            'user_id' => $this->user->id,
            'event' => 'password_changed',
        ]);
    }

    public function test_change_password_with_incorrect_current_password_fails(): void
    {
        Passport::actingAs($this->user, ['profile']);

        $passwordData = [
            'current_password' => 'wrong_password',
            'password' => 'UniqueStrongP@ssw0rd2024!',
            'password_confirmation' => 'UniqueStrongP@ssw0rd2024!',
        ];

        $response = $this->postJson('/api/v1/profile/change-password', $passwordData);

        $response->assertStatus(401)
            ->assertJson([
                'error' => 'authentication_failed',
                'error_description' => 'Current password is incorrect.',
            ]);
    }

    public function test_change_password_with_weak_password_fails(): void
    {
        Passport::actingAs($this->user, ['profile']);

        $passwordData = [
            'current_password' => 'password123',
            'password' => '123',
            'password_confirmation' => '123',
        ];

        $response = $this->postJson('/api/v1/profile/change-password', $passwordData);

        $response->assertStatus(422);
    }

    public function test_get_mfa_status_for_user_without_mfa(): void
    {
        Passport::actingAs($this->user, ['profile']);

        $response = $this->getJson('/api/v1/mfa/status');

        $response->assertStatus(200)
            ->assertJson([
                'data' => [
                    'mfa_enabled' => false,
                    'mfa_methods' => [],
                    'backup_codes_count' => 0,
                    'totp_configured' => false,
                ],
            ]);
    }

    public function test_setup_totp_initiates_mfa_setup(): void
    {
        Passport::actingAs($this->user, ['profile']);

        $response = $this->postJson('/api/v1/mfa/setup/totp');

        $response->assertStatus(200)
            ->assertJsonStructure([
                'data' => [
                    'secret',
                    'qr_code_url',
                    'backup_codes',
                ],
                'message',
            ])
            ->assertJson([
                'message' => 'TOTP setup initiated. Please verify to complete setup.',
            ]);

        // Verify secret was stored temporarily
        $updatedUser = $this->user->fresh();
        $this->assertNotNull($updatedUser->two_factor_secret);
    }

    public function test_setup_totp_fails_when_mfa_already_enabled(): void
    {
        $this->user->update(['mfa_methods' => ['totp']]);
        Passport::actingAs($this->user, ['profile']);

        $response = $this->postJson('/api/v1/mfa/setup/totp');

        $response->assertStatus(409)
            ->assertJson([
                'error' => 'resource_conflict',
                'error_description' => 'MFA is already enabled for this account.',
            ]);
    }

    public function test_verify_totp_with_valid_code_enables_mfa(): void
    {
        $google2fa = new Google2FA;
        $secret = $google2fa->generateSecretKey();
        $this->user->update(['two_factor_secret' => encrypt($secret)]);

        Passport::actingAs($this->user, ['profile']);

        $validCode = $google2fa->getCurrentOtp($secret);

        $response = $this->postJson('/api/v1/mfa/verify/totp', [
            'code' => $validCode,
        ]);

        $response->assertStatus(200)
            ->assertJsonStructure([
                'data' => [
                    'backup_codes',
                ],
                'message',
            ])
            ->assertJson([
                'message' => 'TOTP enabled successfully. Please store your backup codes safely.',
            ]);

        // Verify MFA was enabled
        $updatedUser = $this->user->fresh();
        $this->assertTrue($updatedUser->hasMfaEnabled());
        $this->assertNotNull($updatedUser->two_factor_recovery_codes);
        $this->assertNotNull($updatedUser->two_factor_confirmed_at);

        // Verify authentication log
        $this->assertDatabaseHas('authentication_logs', [
            'user_id' => $this->user->id,
            'event' => 'mfa_enabled',
        ]);
    }

    public function test_verify_totp_with_invalid_code_fails(): void
    {
        $google2fa = new Google2FA;
        $secret = $google2fa->generateSecretKey();
        $this->user->update(['two_factor_secret' => encrypt($secret)]);

        Passport::actingAs($this->user, ['profile']);

        $response = $this->postJson('/api/v1/mfa/verify/totp', [
            'code' => '000000', // Invalid code
        ]);

        $response->assertStatus(401)
            ->assertJson([
                'error' => 'authentication_failed',
                'error_description' => 'Invalid TOTP code.',
            ]);
    }

    public function test_disable_totp_with_valid_credentials_succeeds(): void
    {
        $google2fa = new Google2FA;
        $secret = $google2fa->generateSecretKey();

        $this->user->update([
            'two_factor_secret' => encrypt($secret),
            'mfa_methods' => ['totp'],
            'two_factor_recovery_codes' => json_encode(['backup1', 'backup2']),
        ]);

        Passport::actingAs($this->user, ['profile']);

        $validCode = $google2fa->getCurrentOtp($secret);

        $response = $this->postJson('/api/v1/mfa/disable/totp', [
            'password' => 'password123',
            'code' => $validCode,
        ]);

        $response->assertStatus(200)
            ->assertJson([
                'message' => 'TOTP disabled successfully.',
            ]);

        // Verify MFA was disabled
        $updatedUser = $this->user->fresh();
        $this->assertFalse($updatedUser->hasMfaEnabled());
        $this->assertNull($updatedUser->two_factor_secret);
        $this->assertNull($updatedUser->mfa_methods);

        // Verify authentication log
        $this->assertDatabaseHas('authentication_logs', [
            'user_id' => $this->user->id,
            'event' => 'mfa_disabled',
        ]);
    }

    public function test_get_recovery_codes_with_valid_password_succeeds(): void
    {
        $recoveryCodes = ['CODE1', 'CODE2', 'CODE3'];
        $this->user->update([
            'mfa_methods' => ['totp'],
            'two_factor_recovery_codes' => json_encode($recoveryCodes),
        ]);

        Passport::actingAs($this->user, ['profile']);

        $response = $this->postJson('/api/v1/mfa/recovery-codes', [
            'password' => 'password123',
        ]);

        $response->assertStatus(200)
            ->assertJson([
                'data' => [
                    'recovery_codes' => $recoveryCodes,
                ],
            ]);
    }

    public function test_get_recovery_codes_without_mfa_fails(): void
    {
        Passport::actingAs($this->user, ['profile']);

        $response = $this->postJson('/api/v1/mfa/recovery-codes', [
            'password' => 'password123',
        ]);

        $response->assertStatus(404)
            ->assertJson([
                'error' => 'resource_not_found',
                'error_description' => 'MFA is not enabled.',
            ]);
    }

    public function test_regenerate_recovery_codes_with_valid_password_succeeds(): void
    {
        $this->user->update([
            'mfa_methods' => ['totp'],
            'two_factor_recovery_codes' => json_encode(['OLD1', 'OLD2']),
        ]);

        Passport::actingAs($this->user, ['profile']);

        $response = $this->postJson('/api/v1/mfa/recovery-codes/regenerate', [
            'password' => 'password123',
        ]);

        $response->assertStatus(200)
            ->assertJsonStructure([
                'data' => [
                    'recovery_codes',
                ],
                'message',
            ])
            ->assertJson([
                'message' => 'Recovery codes regenerated successfully.',
            ]);

        // Verify new codes were generated
        $responseData = $response->json();
        $this->assertCount(8, $responseData['data']['recovery_codes']);
        $this->assertNotContains('OLD1', $responseData['data']['recovery_codes']);

        // Verify authentication log
        $this->assertDatabaseHas('authentication_logs', [
            'user_id' => $this->user->id,
            'event' => 'recovery_codes_regenerated',
        ]);
    }

    public function test_all_profile_endpoints_require_authentication(): void
    {
        $endpoints = [
            ['GET', '/api/v1/profile'],
            ['PUT', '/api/v1/profile'],
            ['POST', '/api/v1/profile/avatar'],
            ['DELETE', '/api/v1/profile/avatar'],
            ['GET', '/api/v1/profile/preferences'],
            ['PUT', '/api/v1/profile/preferences'],
            ['GET', '/api/v1/profile/security'],
            ['POST', '/api/v1/profile/change-password'],
            ['GET', '/api/v1/mfa/status'],
            ['POST', '/api/v1/mfa/setup/totp'],
            ['POST', '/api/v1/mfa/verify/totp'],
            ['POST', '/api/v1/mfa/disable/totp'],
            ['POST', '/api/v1/mfa/recovery-codes'],
            ['POST', '/api/v1/mfa/recovery-codes/regenerate'],
        ];

        foreach ($endpoints as [$method, $endpoint]) {
            $response = $this->json($method, $endpoint);
            $response->assertStatus(401, "Endpoint {$method} {$endpoint} should require authentication");
        }
    }
}
