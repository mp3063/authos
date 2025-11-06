<?php

namespace Tests\Integration\Users;

use App\Models\Organization;
use App\Models\User;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Http\UploadedFile;
use Illuminate\Support\Facades\Storage;
use Laravel\Passport\Passport;
use Tests\TestCase;

/**
 * Integration tests for User Profile Management
 *
 * Tests the complete user profile lifecycle including:
 * - Viewing own profile with all details
 * - Updating profile information
 * - Avatar upload and removal
 * - Preferences management
 * - Display name changes
 * - Authorization controls
 */
class UserProfileTest extends TestCase
{
    use RefreshDatabase;

    private Organization $organization;
    private User $user;

    protected function setUp(): void
    {
        parent::setUp();

        Storage::fake('public');

        $this->organization = Organization::factory()->create([
            'name' => 'Test Organization',
        ]);

        $this->user = $this->createApiUser([
            'organization_id' => $this->organization->id,
            'email' => 'testuser@test.com',
            'name' => 'Test User',
            'profile' => [
                'title' => 'Developer',
                'department' => 'Engineering',
            ],
        ]);
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function it_views_own_profile_with_all_details(): void
    {
        // ARRANGE
        Passport::actingAs($this->user);

        // ACT
        $response = $this->getJson('/api/v1/profile');

        // ASSERT
        $response->assertStatus(200)
            ->assertJson([
                'success' => true,
                'data' => [
                    'id' => $this->user->id,
                    'name' => 'Test User',
                    'email' => 'testuser@test.com',
                    'organization_id' => $this->organization->id,
                    'is_active' => true,
                    'mfa_enabled' => false,
                ],
            ])
            ->assertJsonStructure([
                'success',
                'data' => [
                    'id',
                    'name',
                    'email',
                    'avatar',
                    'profile',
                    'organization_id',
                    'organization',
                    'is_active',
                    'mfa_enabled',
                    'created_at',
                    'updated_at',
                    'roles',
                ],
            ]);

        // Verify profile data
        $this->assertEquals('Developer', $response->json('data.profile.title'));
        $this->assertEquals('Engineering', $response->json('data.profile.department'));
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function it_updates_profile_information_successfully(): void
    {
        // ARRANGE
        Passport::actingAs($this->user);

        $updateData = [
            'name' => 'Updated Name',
            'profile' => [
                'title' => 'Senior Developer',
                'department' => 'Engineering',
                'bio' => 'Experienced developer with 5 years in backend systems',
                'location' => 'San Francisco, CA',
                'timezone' => 'America/Los_Angeles',
            ],
        ];

        // ACT
        $response = $this->putJson('/api/v1/profile', $updateData);

        // ASSERT
        $response->assertStatus(200)
            ->assertJson([
                'success' => true,
                'message' => 'Profile updated successfully',
                'data' => [
                    'name' => 'Updated Name',
                ],
            ]);

        // Verify database
        $this->user->refresh();
        $this->assertEquals('Updated Name', $this->user->name);
        $this->assertEquals('Senior Developer', $this->user->profile['title']);
        $this->assertEquals('San Francisco, CA', $this->user->profile['location']);
        $this->assertEquals('America/Los_Angeles', $this->user->profile['timezone']);

        // Verify audit log
        $this->assertDatabaseHas('authentication_logs', [
            'user_id' => $this->user->id,
            'action' => 'profile_updated',
        ]);
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function it_uploads_avatar_successfully(): void
    {
        // ARRANGE
        Passport::actingAs($this->user);

        $file = UploadedFile::fake()->image('avatar.jpg', 500, 500)->size(1000);

        // ACT
        $response = $this->postJson('/api/v1/profile/avatar', [
            'avatar' => $file,
        ]);

        // ASSERT
        $response->assertStatus(200)
            ->assertJson([
                'success' => true,
                'message' => 'Avatar uploaded successfully',
            ])
            ->assertJsonStructure([
                'data' => [
                    'avatar_url',
                ],
            ]);

        // Verify file was stored
        $avatarUrl = $response->json('data.avatar_url');
        $this->assertNotEmpty($avatarUrl);

        // Verify database
        $this->user->refresh();
        $this->assertNotNull($this->user->avatar);

        // Verify audit log
        $this->assertDatabaseHas('authentication_logs', [
            'user_id' => $this->user->id,
            'action' => 'avatar_updated',
        ]);
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function it_removes_avatar_successfully(): void
    {
        // ARRANGE
        Passport::actingAs($this->user);

        // First upload an avatar
        $file = UploadedFile::fake()->image('avatar.jpg');
        $uploadResponse = $this->postJson('/api/v1/profile/avatar', ['avatar' => $file]);
        $this->assertEquals(200, $uploadResponse->status());

        $this->user->refresh();
        $oldAvatar = $this->user->avatar;
        $this->assertNotNull($oldAvatar);

        // ACT - Remove avatar
        $response = $this->deleteJson('/api/v1/profile/avatar');

        // ASSERT
        $response->assertStatus(200)
            ->assertJson([
                'success' => true,
                'message' => 'Avatar removed successfully',
            ]);

        // Verify database
        $this->user->refresh();
        $this->assertNull($this->user->avatar);

        // Verify audit log
        $this->assertDatabaseHas('authentication_logs', [
            'user_id' => $this->user->id,
            'action' => 'avatar_removed',
        ]);
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function it_updates_user_preferences(): void
    {
        // ARRANGE
        Passport::actingAs($this->user);

        $preferences = [
            'theme' => 'dark',
            'language' => 'en',
            'notifications' => [
                'email' => true,
                'sms' => false,
                'push' => true,
            ],
            'dashboard' => [
                'widgets' => ['overview', 'activity', 'security'],
                'default_view' => 'grid',
            ],
        ];

        // ACT
        $response = $this->putJson('/api/v1/profile/preferences', $preferences);

        // ASSERT
        $response->assertStatus(200)
            ->assertJson([
                'success' => true,
                'message' => 'Preferences updated successfully',
                'data' => $preferences,
            ]);

        // Verify database
        $this->user->refresh();
        $this->assertEquals('dark', $this->user->metadata['preferences']['theme']);
        $this->assertEquals('en', $this->user->metadata['preferences']['language']);
        $this->assertTrue($this->user->metadata['preferences']['notifications']['email']);
        $this->assertFalse($this->user->metadata['preferences']['notifications']['sms']);
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function it_retrieves_user_preferences(): void
    {
        // ARRANGE
        Passport::actingAs($this->user);

        $preferences = [
            'theme' => 'light',
            'language' => 'es',
            'notifications' => ['email' => true],
        ];

        $this->user->update([
            'metadata' => ['preferences' => $preferences],
        ]);

        // ACT
        $response = $this->getJson('/api/v1/profile/preferences');

        // ASSERT
        $response->assertStatus(200)
            ->assertJson([
                'success' => true,
                'data' => $preferences,
            ]);
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function it_updates_display_name(): void
    {
        // ARRANGE
        Passport::actingAs($this->user);

        $oldName = $this->user->name;
        $newName = 'John Doe';

        // ACT
        $response = $this->putJson('/api/v1/profile', [
            'name' => $newName,
        ]);

        // ASSERT
        $response->assertStatus(200)
            ->assertJson([
                'success' => true,
                'data' => [
                    'name' => $newName,
                ],
            ]);

        // Verify database
        $this->user->refresh();
        $this->assertEquals($newName, $this->user->name);
        $this->assertNotEquals($oldName, $this->user->name);

        // Verify audit log
        $this->assertDatabaseHas('authentication_logs', [
            'user_id' => $this->user->id,
            'action' => 'profile_updated',
        ]);
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function it_validates_avatar_upload(): void
    {
        // ARRANGE
        Passport::actingAs($this->user);

        // Test invalid file type
        $invalidFile = UploadedFile::fake()->create('document.pdf', 1000);

        // ACT
        $response = $this->postJson('/api/v1/profile/avatar', [
            'avatar' => $invalidFile,
        ]);

        // ASSERT
        $response->assertStatus(422)
            ->assertJsonValidationErrors(['avatar']);
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function it_validates_avatar_size_limit(): void
    {
        // ARRANGE
        Passport::actingAs($this->user);

        // Create file larger than allowed (e.g., 10MB)
        $largeFile = UploadedFile::fake()->image('avatar.jpg')->size(11000); // 11MB

        // ACT
        $response = $this->postJson('/api/v1/profile/avatar', [
            'avatar' => $largeFile,
        ]);

        // ASSERT
        $response->assertStatus(422)
            ->assertJsonValidationErrors(['avatar']);
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function it_validates_profile_update_data(): void
    {
        // ARRANGE
        Passport::actingAs($this->user);

        $invalidData = [
            'name' => '', // Empty name
            'email' => 'invalid-email', // Invalid email format
            'profile' => 'not-an-array', // Invalid profile type
        ];

        // ACT
        $response = $this->putJson('/api/v1/profile', $invalidData);

        // ASSERT
        $response->assertStatus(422)
            ->assertJsonValidationErrors(['name', 'email', 'profile']);
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function it_prevents_email_change_to_existing_email(): void
    {
        // ARRANGE
        $otherUser = User::factory()->create([
            'organization_id' => $this->organization->id,
            'email' => 'existing@test.com',
        ]);

        Passport::actingAs($this->user);

        // ACT
        $response = $this->putJson('/api/v1/profile', [
            'email' => 'existing@test.com', // Already taken
        ]);

        // ASSERT
        $response->assertStatus(422)
            ->assertJsonValidationErrors(['email']);

        // Verify email was not changed
        $this->user->refresh();
        $this->assertEquals('testuser@test.com', $this->user->email);
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function it_merges_profile_data_without_overwriting(): void
    {
        // ARRANGE
        Passport::actingAs($this->user);

        $this->user->update([
            'profile' => [
                'title' => 'Developer',
                'department' => 'Engineering',
                'skills' => ['PHP', 'Laravel'],
            ],
        ]);

        // ACT - Update only bio, keeping other fields
        $response = $this->putJson('/api/v1/profile', [
            'profile' => [
                'bio' => 'New bio',
            ],
        ]);

        // ASSERT
        $response->assertStatus(200);

        // Verify all profile fields are preserved
        $this->user->refresh();
        $this->assertEquals('Developer', $this->user->profile['title']);
        $this->assertEquals('Engineering', $this->user->profile['department']);
        $this->assertEquals(['PHP', 'Laravel'], $this->user->profile['skills']);
        $this->assertEquals('New bio', $this->user->profile['bio']);
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function it_returns_default_preferences_for_new_user(): void
    {
        // ARRANGE
        $newUser = $this->createApiUser([
            'organization_id' => $this->organization->id,
            'email' => 'newuser@test.com',
        ]);

        Passport::actingAs($newUser);

        // ACT
        $response = $this->getJson('/api/v1/profile/preferences');

        // ASSERT
        $response->assertStatus(200)
            ->assertJsonStructure([
                'success',
                'data',
            ]);

        // Should return empty or default preferences
        $this->assertIsArray($response->json('data'));
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function it_handles_large_profile_data(): void
    {
        // ARRANGE
        Passport::actingAs($this->user);

        $largeProfile = [
            'title' => 'Senior Software Engineer',
            'department' => 'Engineering',
            'skills' => array_fill(0, 50, 'Skill'),
            'certifications' => array_fill(0, 20, 'Certification'),
            'projects' => array_fill(0, 30, ['name' => 'Project', 'description' => 'Description']),
        ];

        // ACT
        $response = $this->putJson('/api/v1/profile', [
            'profile' => $largeProfile,
        ]);

        // ASSERT
        $response->assertStatus(200);

        // Verify data was saved
        $this->user->refresh();
        $this->assertCount(50, $this->user->profile['skills']);
        $this->assertCount(20, $this->user->profile['certifications']);
        $this->assertCount(30, $this->user->profile['projects']);
    }
}
