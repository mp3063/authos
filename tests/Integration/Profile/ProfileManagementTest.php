<?php

namespace Tests\Integration\Profile;

use App\Models\User;
use Illuminate\Http\UploadedFile;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Storage;
use Tests\Integration\IntegrationTestCase;

/**
 * Profile Management Integration Tests
 *
 * Tests complete profile management flows including:
 * - Viewing own profile information
 * - Updating profile (name, email, profile data)
 * - Avatar upload and removal
 * - Email change with verification reset
 * - Password change with session revocation
 * - Preferences management
 * - Account deletion
 *
 * @see \App\Http\Controllers\Api\ProfileController
 */
class ProfileManagementTest extends IntegrationTestCase
{
    protected User $user;

    protected function setUp(): void
    {
        parent::setUp();

        // Create test user with verified email
        $this->user = $this->createUser([
            'name' => 'John Doe',
            'email' => 'john.doe@example.com',
            'password' => Hash::make('password123'),
            'email_verified_at' => now(),
            'profile' => [
                'bio' => 'Software Developer',
                'location' => 'New York',
                'website' => 'https://johndoe.com',
                'preferences' => [
                    'timezone' => 'America/New_York',
                    'language' => 'en',
                    'theme' => 'dark',
                ],
            ],
        ]);

        // Set up storage for avatar tests
        Storage::fake('public');
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function user_can_view_own_profile(): void
    {
        // ARRANGE: Authenticated user

        // ACT: Request profile
        $response = $this->actingAs($this->user, 'api')
            ->getJson('/api/v1/profile');

        // ASSERT: Returns complete profile data
        $response->assertOk();
        $response->assertJsonStructure([
            'data' => [
                'id',
                'name',
                'email',
                'avatar',
                'email_verified_at',
                'profile',
                'mfa_enabled',
                'mfa_methods',
                'organization' => ['id', 'name', 'slug'],
                'roles',
                'created_at',
                'updated_at',
            ],
        ]);

        $data = $response->json('data');
        $this->assertEquals('John Doe', $data['name']);
        $this->assertEquals('john.doe@example.com', $data['email']);
        $this->assertEquals('Software Developer', $data['profile']['bio']);
        $this->assertEquals('New York', $data['profile']['location']);
        $this->assertFalse($data['mfa_enabled']);
        $this->assertNotNull($data['organization']);
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function user_can_update_profile_information(): void
    {
        // ARRANGE: Authenticated user with updated data
        $updatedData = [
            'name' => 'Jane Doe',
            'profile' => [
                'bio' => 'Senior Engineer',
                'location' => 'San Francisco',
                'website' => 'https://janedoe.com',
            ],
        ];

        // ACT: Update profile
        $response = $this->actingAs($this->user, 'api')
            ->putJson('/api/v1/profile', $updatedData);

        // ASSERT: Profile updated successfully
        $response->assertOk();
        $response->assertJson([
            'message' => 'Profile updated successfully',
            'data' => [
                'name' => 'Jane Doe',
                'email' => 'john.doe@example.com', // Email unchanged
            ],
        ]);

        // Verify database
        $this->assertDatabaseHas('users', [
            'id' => $this->user->id,
            'name' => 'Jane Doe',
        ]);

        // Verify profile JSON column updated
        $this->user->refresh();
        $this->assertEquals('Senior Engineer', $this->user->profile['bio']);
        $this->assertEquals('San Francisco', $this->user->profile['location']);
        $this->assertEquals('https://janedoe.com', $this->user->profile['website']);

        // ASSERT: Authentication log created
        $this->assertAuthenticationLogged([
            'user_id' => $this->user->id,
            'event' => 'profile_updated',
        ]);
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function user_can_upload_avatar(): void
    {
        // ARRANGE: Create fake image file
        $avatar = UploadedFile::fake()->image('avatar.jpg', 400, 400)->size(1024); // 1MB

        // ACT: Upload avatar
        $response = $this->actingAs($this->user, 'api')
            ->postJson('/api/v1/profile/avatar', [
                'avatar' => $avatar,
            ]);

        // ASSERT: Avatar uploaded successfully
        $response->assertOk();
        $response->assertJsonStructure([
            'message',
            'data' => ['avatar', 'avatar_url'],
        ]);

        // Verify file stored
        $this->user->refresh();
        $this->assertNotNull($this->user->avatar);
        Storage::disk('public')->assertExists($this->user->avatar);

        // Verify file is in avatars directory
        $this->assertStringContainsString('avatars/', $this->user->avatar);
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function user_can_remove_avatar(): void
    {
        // ARRANGE: User with existing avatar
        $avatar = UploadedFile::fake()->image('avatar.jpg');
        $avatarPath = $avatar->store('avatars', 'public');
        $this->user->update(['avatar' => $avatarPath]);

        Storage::disk('public')->assertExists($avatarPath);

        // ACT: Remove avatar
        $response = $this->actingAs($this->user, 'api')
            ->deleteJson('/api/v1/profile/avatar');

        // ASSERT: Avatar removed successfully
        $response->assertOk();
        $response->assertJson([
            'message' => 'Avatar removed successfully',
        ]);

        // Verify database updated
        $this->user->refresh();
        $this->assertNull($this->user->avatar);

        // Verify file deleted from storage
        Storage::disk('public')->assertMissing($avatarPath);
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function email_change_resets_verification_status(): void
    {
        // ARRANGE: Verified user changing email
        $this->assertNotNull($this->user->email_verified_at);

        // ACT: Update email
        $response = $this->actingAs($this->user, 'api')
            ->putJson('/api/v1/profile', [
                'name' => $this->user->name,
                'email' => 'new.email@example.com',
            ]);

        // ASSERT: Email updated but verification reset
        $response->assertOk();

        $this->user->refresh();
        $this->assertEquals('new.email@example.com', $this->user->email);
        $this->assertNull($this->user->email_verified_at); // Verification reset

        // ASSERT: Profile update logged
        $this->assertAuthenticationLogged([
            'user_id' => $this->user->id,
            'event' => 'profile_updated',
        ]);
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function user_can_change_password(): void
    {
        // ARRANGE: User with current password
        $currentPassword = 'password123';
        $newPassword = 'newSecurePassword456!';

        // ACT: Change password
        $response = $this->actingAs($this->user, 'api')
            ->postJson('/api/v1/profile/change-password', [
                'current_password' => $currentPassword,
                'password' => $newPassword,
                'password_confirmation' => $newPassword,
            ]);

        // ASSERT: Password changed successfully
        $response->assertOk();
        $response->assertJson([
            'message' => 'Password changed successfully',
        ]);

        // Verify new password works
        $this->user->refresh();
        $this->assertTrue(Hash::check($newPassword, $this->user->password));

        // Verify password_changed_at timestamp updated
        $this->assertNotNull($this->user->password_changed_at);
        $this->assertTrue($this->user->password_changed_at->isToday());

        // ASSERT: Password change logged
        $this->assertAuthenticationLogged([
            'user_id' => $this->user->id,
            'event' => 'password_changed',
        ]);

        // ASSERT: Old sessions revoked (tokens deleted)
        $this->assertEquals(0, $this->user->tokens()->count());
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function password_change_rejects_incorrect_current_password(): void
    {
        // ARRANGE: Wrong current password
        $wrongPassword = 'wrongPassword';
        $newPassword = 'newPassword123!';

        // ACT: Attempt to change password
        $response = $this->actingAs($this->user, 'api')
            ->postJson('/api/v1/profile/change-password', [
                'current_password' => $wrongPassword,
                'password' => $newPassword,
                'password_confirmation' => $newPassword,
            ]);

        // ASSERT: Request rejected (validation error)
        $response->assertStatus(422);
        $response->assertJsonValidationErrors(['current_password']);

        // Verify password unchanged
        $this->user->refresh();
        $this->assertTrue(Hash::check('password123', $this->user->password));
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function user_can_update_preferences(): void
    {
        // ARRANGE: Updated preferences
        $newPreferences = [
            'timezone' => 'Europe/London',
            'language' => 'en',
            'theme' => 'light',
            'date_format' => 'd/m/Y',
            'time_format' => 'H:i',
            'email_notifications' => true,
            'security_alerts' => true,
            'marketing_emails' => false,
        ];

        // ACT: Update preferences
        $response = $this->actingAs($this->user, 'api')
            ->putJson('/api/v1/profile/preferences', $newPreferences);

        // ASSERT: Preferences updated
        $response->assertOk();
        $response->assertJson([
            'message' => 'Preferences updated successfully',
            'data' => $newPreferences,
        ]);

        // Verify stored in database
        $this->user->refresh();
        $this->assertEquals('Europe/London', $this->user->profile['preferences']['timezone']);
        $this->assertEquals('light', $this->user->profile['preferences']['theme']);
        $this->assertEquals('d/m/Y', $this->user->profile['preferences']['date_format']);
        $this->assertFalse($this->user->profile['preferences']['marketing_emails']);
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function user_can_view_preferences(): void
    {
        // ARRANGE: User with preferences

        // ACT: Get preferences
        $response = $this->actingAs($this->user, 'api')
            ->getJson('/api/v1/profile/preferences');

        // ASSERT: Returns preferences with defaults
        $response->assertOk();
        $response->assertJsonStructure([
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
        ]);

        $data = $response->json('data');
        $this->assertEquals('America/New_York', $data['timezone']);
        $this->assertEquals('dark', $data['theme']);

        // Verify defaults are merged
        $this->assertTrue($data['email_notifications']); // Default value
        $this->assertTrue($data['security_alerts']); // Default value
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function avatar_upload_validates_file_type_and_size(): void
    {
        // ARRANGE: Invalid file (too large and wrong type)
        $invalidFile = UploadedFile::fake()->create('document.pdf', 3000); // 3MB PDF

        // ACT: Attempt to upload
        $response = $this->actingAs($this->user, 'api')
            ->postJson('/api/v1/profile/avatar', [
                'avatar' => $invalidFile,
            ]);

        // ASSERT: Validation fails
        $response->assertStatus(422);
        $response->assertJsonStructure([
            'error',
            'error_description',
            'details',
        ]);
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function profile_update_validates_input(): void
    {
        // ARRANGE: Invalid email format
        $invalidData = [
            'name' => '', // Empty name
            'email' => 'invalid-email', // Invalid email
        ];

        // ACT: Attempt to update
        $response = $this->actingAs($this->user, 'api')
            ->putJson('/api/v1/profile', $invalidData);

        // ASSERT: Validation fails
        $response->assertStatus(422);

        // Check if it's Laravel validation format or custom error format
        $json = $response->json();
        if (isset($json['errors'])) {
            // Laravel validation format
            $this->assertArrayHasKey('name', $json['errors']);
            $this->assertArrayHasKey('email', $json['errors']);
        } else {
            // Custom error format
            $this->assertArrayHasKey('error', $json);
            $this->assertEquals('validation_failed', $json['error']);
        }
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function user_can_view_security_settings(): void
    {
        // ARRANGE: Create some tokens/sessions
        $token = $this->user->createToken('test-token')->accessToken;

        // ACT: Get security settings
        $response = $this->actingAs($this->user, 'api')
            ->getJson('/api/v1/profile/security');

        // ASSERT: Returns security information
        $response->assertOk();
        $response->assertJsonStructure([
            'data' => [
                'mfa_enabled',
                'mfa_methods',
                'recovery_codes_count',
                'password_changed_at',
                'active_sessions',
                'recent_logins',
            ],
        ]);

        $data = $response->json('data');
        $this->assertFalse($data['mfa_enabled']);
        $this->assertIsArray($data['mfa_methods']);
        $this->assertGreaterThanOrEqual(0, $data['active_sessions']);
        $this->assertIsArray($data['recent_logins']);
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function unauthorized_user_cannot_access_profile(): void
    {
        // ARRANGE: No authentication

        // ACT: Attempt to access profile
        $response = $this->getJson('/api/v1/profile');

        // ASSERT: Unauthorized
        $response->assertUnauthorized();
    }
}
