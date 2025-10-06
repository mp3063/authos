<?php

declare(strict_types=1);

namespace Tests\Feature\Services\Auth0;

use App\Models\Organization;
use App\Models\User;
use App\Services\Auth0\DTOs\Auth0UserDTO;
use App\Services\Auth0\Migration\Importers\UserImporter;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Tests\TestCase;

class UserImporterTest extends TestCase
{
    use RefreshDatabase;

    private Organization $organization;

    private UserImporter $importer;

    protected function setUp(): void
    {
        parent::setUp();

        $this->organization = Organization::factory()->create();
        $this->importer = new UserImporter(UserImporter::STRATEGY_LAZY, $this->organization);
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function it_imports_basic_user(): void
    {
        $auth0User = new Auth0UserDTO(
            userId: 'auth0|123',
            email: 'test@example.com',
            name: 'Test User',
            emailVerified: true,
            appMetadata: [],
            userMetadata: [],
            identities: [
                ['provider' => 'auth0', 'user_id' => '123', 'isSocial' => false],
            ],
        );

        $result = $this->importer->import([$auth0User], false);

        $this->assertEquals(1, $result->getSuccessCount());
        $this->assertEquals(0, $result->getFailureCount());

        $this->assertDatabaseHas('users', [
            'email' => 'test@example.com',
            'name' => 'Test User',
            'organization_id' => $this->organization->id,
        ]);

        $user = User::where('email', 'test@example.com')->first();
        $this->assertTrue($user->email_verified_at !== null);
        $this->assertEquals('auth0|123', $user->metadata['auth0_user_id'] ?? null);
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function it_skips_users_without_email(): void
    {
        $auth0User = new Auth0UserDTO(
            userId: 'auth0|123',
            email: '',
            name: 'Test User',
            emailVerified: false,
            appMetadata: [],
            userMetadata: [],
            identities: [],
        );

        $result = $this->importer->import([$auth0User], false);

        $this->assertEquals(0, $result->getSuccessCount());
        $this->assertEquals(1, $result->getSkippedCount());
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function it_skips_duplicate_users(): void
    {
        User::factory()->create([
            'email' => 'test@example.com',
            'organization_id' => $this->organization->id,
        ]);

        $auth0User = new Auth0UserDTO(
            userId: 'auth0|123',
            email: 'test@example.com',
            name: 'Test User',
            emailVerified: true,
            appMetadata: [],
            userMetadata: [],
            identities: [],
        );

        $result = $this->importer->import([$auth0User], false);

        $this->assertEquals(0, $result->getSuccessCount());
        $this->assertEquals(1, $result->getSkippedCount());
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function it_performs_dry_run(): void
    {
        $auth0User = new Auth0UserDTO(
            userId: 'auth0|123',
            email: 'test@example.com',
            name: 'Test User',
            emailVerified: true,
            appMetadata: [],
            userMetadata: [],
            identities: [],
        );

        $result = $this->importer->import([$auth0User], true);

        $this->assertEquals(1, $result->getSuccessCount());
        $this->assertDatabaseMissing('users', ['email' => 'test@example.com']);
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function it_imports_social_accounts(): void
    {
        $auth0User = new Auth0UserDTO(
            userId: 'auth0|123',
            email: 'test@example.com',
            name: 'Test User',
            emailVerified: true,
            appMetadata: [],
            userMetadata: [],
            identities: [
                ['provider' => 'google-oauth2', 'user_id' => 'google123', 'isSocial' => true, 'connection' => 'google'],
                ['provider' => 'github', 'user_id' => 'github123', 'isSocial' => true, 'connection' => 'github'],
            ],
        );

        $result = $this->importer->import([$auth0User], false);

        $this->assertEquals(1, $result->getSuccessCount());

        $user = User::where('email', 'test@example.com')->first();
        $this->assertCount(2, $user->socialAccounts);

        $this->assertDatabaseHas('social_accounts', [
            'user_id' => $user->id,
            'provider' => 'google',
            'provider_id' => 'google123',
        ]);

        $this->assertDatabaseHas('social_accounts', [
            'user_id' => $user->id,
            'provider' => 'github',
            'provider_id' => 'github123',
        ]);
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function it_enables_mfa_for_users_with_mfa(): void
    {
        $auth0User = new Auth0UserDTO(
            userId: 'auth0|123',
            email: 'test@example.com',
            name: 'Test User',
            emailVerified: true,
            appMetadata: ['mfa_enabled' => true],
            userMetadata: [],
            identities: [],
        );

        $result = $this->importer->import([$auth0User], false);

        $this->assertEquals(1, $result->getSuccessCount());

        $user = User::where('email', 'test@example.com')->first();
        $this->assertTrue($user->mfa_enabled);
        $this->assertNotNull($user->mfa_secret);
        $this->assertNotNull($user->mfa_recovery_codes);
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function it_imports_user_metadata(): void
    {
        $auth0User = new Auth0UserDTO(
            userId: 'auth0|123',
            email: 'test@example.com',
            name: 'Test User',
            emailVerified: true,
            appMetadata: ['custom_key' => 'custom_value'],
            userMetadata: ['preferences' => ['theme' => 'dark']],
            identities: [],
            loginsCount: 10,
            lastLogin: new \DateTimeImmutable('2024-01-01'),
        );

        $result = $this->importer->import([$auth0User], false);

        $this->assertEquals(1, $result->getSuccessCount());

        $user = User::where('email', 'test@example.com')->first();
        $this->assertEquals('custom_value', $user->metadata['auth0_app_metadata']['custom_key'] ?? null);
        $this->assertEquals(['theme' => 'dark'], $user->metadata['auth0_user_metadata']['preferences'] ?? null);
        $this->assertEquals(10, $user->metadata['auth0_logins_count'] ?? null);
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function it_uses_reset_password_strategy(): void
    {
        $importer = new UserImporter(UserImporter::STRATEGY_RESET, $this->organization);

        $auth0User = new Auth0UserDTO(
            userId: 'auth0|123',
            email: 'test@example.com',
            name: 'Test User',
            emailVerified: true,
            appMetadata: [],
            userMetadata: [],
            identities: [],
        );

        $result = $importer->import([$auth0User], false);

        $this->assertEquals(1, $result->getSuccessCount());

        $user = User::where('email', 'test@example.com')->first();
        $this->assertTrue($user->metadata['requires_password_reset'] ?? false);
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function it_uses_lazy_migration_strategy(): void
    {
        $importer = new UserImporter(UserImporter::STRATEGY_LAZY, $this->organization);

        $auth0User = new Auth0UserDTO(
            userId: 'auth0|123',
            email: 'test@example.com',
            name: 'Test User',
            emailVerified: true,
            appMetadata: [],
            userMetadata: [],
            identities: [],
        );

        $result = $importer->import([$auth0User], false);

        $this->assertEquals(1, $result->getSuccessCount());

        $user = User::where('email', 'test@example.com')->first();
        $this->assertTrue($user->metadata['lazy_migration_enabled'] ?? false);
        $this->assertEquals('auth0|123', $user->metadata['auth0_user_id'] ?? null);
    }
}
