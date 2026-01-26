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
                'data' => [
                    'id' => $this->user->id,
                    'name' => 'Test User',
                    'email' => 'testuser@test.com',
                    'mfa_enabled' => false,
                    'organization' => [
                        'id' => $this->organization->id,
                        'name' => 'Test Organization',
                    ],
                ],
            ])
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
                    'organization',
                    'roles',
                    'created_at',
                    'updated_at',
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
            'event' => 'profile_updated',
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
                'message' => 'Avatar uploaded successfully',
            ])
            ->assertJsonStructure([
                'data' => [
                    'avatar',
                    'avatar_url',
                ],
            ]);

        // Verify file was stored
        $avatarUrl = $response->json('data.avatar_url');
        $this->assertNotEmpty($avatarUrl);

        // Verify database
        $this->user->refresh();
        $this->assertNotNull($this->user->avatar);
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
                'message' => 'Avatar removed successfully',
            ]);

        // Verify database
        $this->user->refresh();
        $this->assertNull($this->user->avatar);
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function it_updates_user_preferences(): void
    {
        // ARRANGE
        Passport::actingAs($this->user);

        $preferences = [
            'theme' => 'dark',
            'language' => 'en',
            'timezone' => 'America/New_York',
            'date_format' => 'Y-m-d',
            'time_format' => 'H:i',
        ];

        // ACT
        $response = $this->putJson('/api/v1/profile/preferences', $preferences);

        // ASSERT
        $response->assertStatus(200)
            ->assertJson([
                'message' => 'Preferences updated successfully',
                'data' => [
                    'theme' => 'dark',
                    'language' => 'en',
                    'timezone' => 'America/New_York',
                ],
            ]);

        // Verify database - preferences are stored in profile['preferences']
        $this->user->refresh();
        $this->assertEquals('dark', $this->user->profile['preferences']['theme']);
        $this->assertEquals('en', $this->user->profile['preferences']['language']);
        $this->assertEquals('America/New_York', $this->user->profile['preferences']['timezone']);
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function it_retrieves_user_preferences(): void
    {
        // ARRANGE
        Passport::actingAs($this->user);

        $customPreferences = [
            'theme' => 'dark',
            'language' => 'es',
        ];

        // Store preferences in profile['preferences']
        $this->user->update([
            'profile' => array_merge($this->user->profile ?? [], [
                'preferences' => $customPreferences,
            ]),
        ]);

        // ACT
        $response = $this->getJson('/api/v1/profile/preferences');

        // ASSERT
        $response->assertStatus(200)
            ->assertJsonStructure(['data'])
            ->assertJson([
                'data' => [
                    'theme' => 'dark',
                    'language' => 'es',
                ],
            ]);

        // Verify default preferences are merged with custom ones
        $data = $response->json('data');
        $this->assertEquals('dark', $data['theme']);
        $this->assertEquals('es', $data['language']);
        $this->assertArrayHasKey('timezone', $data);
        $this->assertArrayHasKey('date_format', $data);
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
            'event' => 'profile_updated',
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
            ->assertJson([
                'error' => 'validation_failed',
                'error_description' => 'The given data was invalid.',
            ])
            ->assertJsonStructure([
                'error',
                'error_description',
                'details' => [
                    'avatar',
                ],
            ]);
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function it_validates_avatar_size_limit(): void
    {
        // ARRANGE
        Passport::actingAs($this->user);

        // Create file larger than allowed (max 2MB per controller)
        $largeFile = UploadedFile::fake()->image('avatar.jpg')->size(3000); // 3MB (exceeds 2MB limit)

        // ACT
        $response = $this->postJson('/api/v1/profile/avatar', [
            'avatar' => $largeFile,
        ]);

        // ASSERT
        $response->assertStatus(422)
            ->assertJson([
                'error' => 'validation_failed',
                'error_description' => 'The given data was invalid.',
            ])
            ->assertJsonStructure([
                'error',
                'error_description',
                'details' => [
                    'avatar',
                ],
            ]);
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
            ->assertJson([
                'error' => 'validation_failed',
                'error_description' => 'The given data was invalid.',
            ])
            ->assertJsonStructure([
                'error',
                'error_description',
                'details' => [
                    'name',
                    'email',
                    'profile',
                ],
            ]);
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
            ->assertJson([
                'error' => 'validation_failed',
                'error_description' => 'The given data was invalid.',
            ])
            ->assertJsonStructure([
                'error',
                'error_description',
                'details' => [
                    'email',
                ],
            ]);

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
                'data',
            ]);

        // Should return default preferences
        $data = $response->json('data');
        $this->assertIsArray($data);
        $this->assertEquals('UTC', $data['timezone']);
        $this->assertEquals('en', $data['language']);
        $this->assertEquals('light', $data['theme']);
        $this->assertEquals('Y-m-d', $data['date_format']);
        $this->assertEquals('H:i', $data['time_format']);
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
