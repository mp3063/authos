<?php

namespace Tests\Unit\Services\Migration;

use App\Models\Organization;
use App\Models\User;
use App\Services\Migration\UserImporter;
use Tests\TestCase;

class UserImporterTest extends TestCase
{
    private UserImporter $importer;

    private Organization $organization;

    protected function setUp(): void
    {
        parent::setUp();

        $this->importer = new UserImporter;
        $this->organization = Organization::factory()->create();
    }

    public function test_imports_user_with_password_reset(): void
    {
        $auth0User = [
            'email' => 'user@example.com',
            'name' => 'Test User',
            'user_id' => 'auth0|123456',
            'email_verified' => true,
        ];

        $user = $this->importer->importUser($auth0User, $this->organization, [
            'migration_strategy' => 'password_reset',
        ]);

        $this->assertInstanceOf(User::class, $user);
        $this->assertEquals('user@example.com', $user->email);
        $this->assertNotNull($user->password);
        $this->assertDatabaseHas('password_reset_tokens', [
            'email' => 'user@example.com',
        ]);
    }

    public function test_imports_user_with_lazy_migration(): void
    {
        $auth0User = [
            'email' => 'user@example.com',
            'name' => 'Test User',
            'user_id' => 'auth0|123456',
        ];

        $user = $this->importer->importUser($auth0User, $this->organization, [
            'migration_strategy' => 'lazy',
        ]);

        $this->assertDatabaseHas('users', [
            'email' => 'user@example.com',
            'migration_pending' => true,
        ]);
    }

    public function test_migrates_password_hash(): void
    {
        $auth0User = [
            'email' => 'user@example.com',
            'name' => 'Test User',
            'user_id' => 'auth0|123456',
        ];

        $auth0Hash = bcrypt('password123');

        $user = $this->importer->importUser($auth0User, $this->organization, [
            'migration_strategy' => 'hash',
            'password_hash' => $auth0Hash,
        ]);

        $this->assertEquals($auth0Hash, $user->password);
    }

    public function test_imports_social_accounts(): void
    {
        $auth0User = [
            'email' => 'user@example.com',
            'name' => 'Test User',
            'user_id' => 'auth0|123456',
            'identities' => [
                [
                    'provider' => 'google-oauth2',
                    'user_id' => 'google-123456',
                    'connection' => 'google-oauth2',
                ],
            ],
        ];

        $user = $this->importer->importUser($auth0User, $this->organization);

        $this->assertDatabaseHas('social_accounts', [
            'user_id' => $user->id,
            'provider' => 'google',
            'provider_user_id' => 'google-123456',
        ]);
    }

    public function test_migrates_mfa_settings(): void
    {
        $auth0User = [
            'email' => 'user@example.com',
            'name' => 'Test User',
            'user_id' => 'auth0|123456',
            'multifactor' => ['google-authenticator'],
        ];

        $user = $this->importer->importUser($auth0User, $this->organization);

        $this->assertTrue($user->two_factor_enabled);
        $this->assertNotNull($user->two_factor_secret);
    }

    public function test_preserves_email_verification_status(): void
    {
        $verifiedUser = [
            'email' => 'verified@example.com',
            'name' => 'Verified User',
            'email_verified' => true,
        ];

        $unverifiedUser = [
            'email' => 'unverified@example.com',
            'name' => 'Unverified User',
            'email_verified' => false,
        ];

        $verified = $this->importer->importUser($verifiedUser, $this->organization);
        $unverified = $this->importer->importUser($unverifiedUser, $this->organization);

        $this->assertNotNull($verified->email_verified_at);
        $this->assertNull($unverified->email_verified_at);
    }

    public function test_imports_user_metadata(): void
    {
        $auth0User = [
            'email' => 'user@example.com',
            'name' => 'Test User',
            'user_metadata' => [
                'phone' => '+1234567890',
                'job_title' => 'Developer',
            ],
            'app_metadata' => [
                'plan' => 'premium',
            ],
        ];

        $user = $this->importer->importUser($auth0User, $this->organization);

        $metadata = $user->metadata;
        $this->assertEquals('+1234567890', $metadata['phone'] ?? null);
        $this->assertEquals('premium', $metadata['plan'] ?? null);
    }

    public function test_handles_duplicate_users(): void
    {
        User::factory()->for($this->organization)->create([
            'email' => 'existing@example.com',
        ]);

        $auth0User = [
            'email' => 'existing@example.com',
            'name' => 'Updated Name',
        ];

        $user = $this->importer->importUser($auth0User, $this->organization, [
            'duplicate_strategy' => 'update',
        ]);

        $this->assertEquals('Updated Name', $user->name);
        $this->assertEquals(1, User::where('email', 'existing@example.com')->count());
    }

    public function test_skips_duplicate_users_when_configured(): void
    {
        $existing = User::factory()->for($this->organization)->create([
            'email' => 'existing@example.com',
            'name' => 'Original Name',
        ]);

        $auth0User = [
            'email' => 'existing@example.com',
            'name' => 'Updated Name',
        ];

        $user = $this->importer->importUser($auth0User, $this->organization, [
            'duplicate_strategy' => 'skip',
        ]);

        $this->assertEquals('Original Name', $user->name);
    }

    public function test_assigns_default_role(): void
    {
        $auth0User = [
            'email' => 'user@example.com',
            'name' => 'Test User',
        ];

        $user = $this->importer->importUser($auth0User, $this->organization, [
            'default_role' => 'user',
        ]);

        $this->assertTrue($user->hasRole('User'));
    }

    public function test_maps_auth0_roles_to_local_roles(): void
    {
        $auth0User = [
            'email' => 'admin@example.com',
            'name' => 'Admin User',
            'app_metadata' => [
                'roles' => ['admin'],
            ],
        ];

        $user = $this->importer->importUser($auth0User, $this->organization, [
            'role_mapping' => [
                'admin' => 'Organization Admin',
            ],
        ]);

        $this->assertTrue($user->hasRole('Organization Admin'));
    }
}
