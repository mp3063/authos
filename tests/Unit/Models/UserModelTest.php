<?php

namespace Tests\Unit\Models;

use App\Models\Application;
use App\Models\CustomRole;
use App\Models\Organization;
use App\Models\SSOSession;
use App\Models\User;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Spatie\Permission\Models\Permission;
use Spatie\Permission\Models\Role;
use Tests\TestCase;

class UserModelTest extends TestCase
{
    use RefreshDatabase;

    private Organization $organization;

    protected function setUp(): void
    {
        parent::setUp();

        $this->organization = Organization::factory()->create();
    }

    public function test_user_belongs_to_organization(): void
    {
        $user = User::factory()->forOrganization($this->organization)->create();

        $this->assertInstanceOf(Organization::class, $user->organization);
        $this->assertEquals($this->organization->id, $user->organization->id);
    }

    public function test_user_has_many_applications(): void
    {
        $user = User::factory()->forOrganization($this->organization)->create();
        $app1 = Application::factory()->forOrganization($this->organization)->create();
        $app2 = Application::factory()->forOrganization($this->organization)->create();

        $user->applications()->attach($app1->id, [
            'permissions' => ['read', 'write'],
            'metadata' => ['role' => 'admin'],
            'granted_at' => now(),
            'granted_by' => $user->id,
        ]);

        $user->applications()->attach($app2->id, [
            'permissions' => ['read'],
            'metadata' => ['role' => 'user'],
            'granted_at' => now(),
            'granted_by' => $user->id,
        ]);

        $this->assertCount(2, $user->applications);
        $this->assertTrue($user->applications->contains($app1));
        $this->assertTrue($user->applications->contains($app2));
    }

    public function test_user_has_many_sso_sessions(): void
    {
        $user = User::factory()->forOrganization($this->organization)->create();
        $app = Application::factory()->forOrganization($this->organization)->create();

        $session1 = SSOSession::factory()->create([
            'user_id' => $user->id,
            'application_id' => $app->id,
        ]);

        $session2 = SSOSession::factory()->create([
            'user_id' => $user->id,
            'application_id' => $app->id,
        ]);

        $this->assertCount(2, $user->ssoSessions);
        $this->assertTrue($user->ssoSessions->contains($session1));
        $this->assertTrue($user->ssoSessions->contains($session2));
    }

    public function test_user_has_many_custom_roles(): void
    {
        $user = User::factory()->forOrganization($this->organization)->create();
        $role1 = CustomRole::factory()->forOrganization($this->organization)->create();
        $role2 = CustomRole::factory()->forOrganization($this->organization)->create();

        $user->customRoles()->attach($role1->id, [
            'granted_at' => now(),
            'granted_by' => $user->id,
        ]);

        $user->customRoles()->attach($role2->id, [
            'granted_at' => now(),
            'granted_by' => $user->id,
        ]);

        $this->assertCount(2, $user->customRoles);
        $this->assertTrue($user->customRoles->contains($role1));
        $this->assertTrue($user->customRoles->contains($role2));
    }

    public function test_has_mfa_enabled_returns_true_when_methods_exist(): void
    {
        $user = User::factory()->create(['mfa_methods' => ['totp', 'recovery_codes']]);

        $this->assertTrue($user->hasMfaEnabled());
    }

    public function test_has_mfa_enabled_returns_false_when_no_methods(): void
    {
        $user = User::factory()->create(['mfa_methods' => null]);

        $this->assertFalse($user->hasMfaEnabled());
    }

    public function test_has_mfa_enabled_returns_false_when_empty_methods(): void
    {
        $user = User::factory()->create(['mfa_methods' => []]);

        $this->assertFalse($user->hasMfaEnabled());
    }

    public function test_get_mfa_methods_returns_array(): void
    {
        $methods = ['totp', 'recovery_codes'];
        $user = User::factory()->create(['mfa_methods' => $methods]);

        $this->assertEquals($methods, $user->getMfaMethods());
    }

    public function test_get_mfa_methods_returns_empty_array_when_null(): void
    {
        $user = User::factory()->create(['mfa_methods' => null]);

        $this->assertEquals([], $user->getMfaMethods());
    }

    public function test_set_permissions_team_id_uses_provided_id(): void
    {
        $user = User::factory()->forOrganization($this->organization)->create();
        $otherOrgId = 999;

        $user->setPermissionsTeamId($otherOrgId);

        $this->assertEquals($otherOrgId, $user->permissionsTeamId);
    }

    public function test_set_permissions_team_id_defaults_to_user_organization(): void
    {
        $user = User::factory()->forOrganization($this->organization)->create();

        $user->setPermissionsTeamId();

        $this->assertEquals($this->organization->id, $user->permissionsTeamId);
    }

    public function test_get_organization_roles_returns_organization_specific_roles(): void
    {
        $user = User::factory()->forOrganization($this->organization)->create();

        // Set up permission context
        app(\Spatie\Permission\PermissionRegistrar::class)->setPermissionsTeamId($this->organization->id);
        $user->setPermissionsTeamId($this->organization->id);

        // Create organization-specific role
        $orgRole = Role::create([
            'name' => 'org_admin',
            'guard_name' => 'web',
            'organization_id' => $this->organization->id,
        ]);

        // Create global role
        $globalRole = Role::create([
            'name' => 'global_admin',
            'guard_name' => 'web',
            'organization_id' => null,
        ]);

        // Use assignRole for proper Spatie integration
        $user->assignRole($orgRole);
        $user->assignRole($globalRole);
        $user->refresh();

        $orgRoles = $user->getOrganizationRoles();

        $this->assertTrue($orgRoles->contains($orgRole));
        $this->assertTrue($orgRoles->contains($globalRole)); // Global roles should be included
    }

    public function test_has_organization_role_checks_role_within_context(): void
    {
        $user = User::factory()->forOrganization($this->organization)->create();

        // Set up permission context
        app(\Spatie\Permission\PermissionRegistrar::class)->setPermissionsTeamId($this->organization->id);
        $user->setPermissionsTeamId($this->organization->id);

        $role = Role::create([
            'name' => 'test_role',
            'guard_name' => 'web',
            'organization_id' => $this->organization->id,
        ]);

        $user->assignRole($role);
        $user->refresh();

        $this->assertTrue($user->hasOrganizationRole('test_role'));
        $this->assertFalse($user->hasOrganizationRole('nonexistent_role'));
    }

    public function test_is_organization_owner_checks_owner_role(): void
    {
        $user = User::factory()->forOrganization($this->organization)->create();

        // Set up permission context
        app(\Spatie\Permission\PermissionRegistrar::class)->setPermissionsTeamId($this->organization->id);
        $user->setPermissionsTeamId($this->organization->id);

        $ownerRole = Role::create([
            'name' => 'Organization Owner',
            'guard_name' => 'web',
            'organization_id' => $this->organization->id,
        ]);

        $user->assignRole($ownerRole);
        $user->refresh();

        $this->assertTrue($user->isOrganizationOwner());
    }

    public function test_is_organization_admin_checks_admin_roles(): void
    {
        $user = User::factory()->forOrganization($this->organization)->create();

        // Set up permission context
        app(\Spatie\Permission\PermissionRegistrar::class)->setPermissionsTeamId($this->organization->id);
        $user->setPermissionsTeamId($this->organization->id);

        $adminRole = Role::create([
            'name' => 'Organization Admin',
            'guard_name' => 'web',
            'organization_id' => $this->organization->id,
        ]);

        $user->assignRole($adminRole);
        $user->refresh();

        $this->assertTrue($user->isOrganizationAdmin());
    }

    public function test_is_organization_admin_returns_true_for_owner(): void
    {
        $user = User::factory()->forOrganization($this->organization)->create();

        // Set up permission context
        app(\Spatie\Permission\PermissionRegistrar::class)->setPermissionsTeamId($this->organization->id);
        $user->setPermissionsTeamId($this->organization->id);

        $ownerRole = Role::create([
            'name' => 'Organization Owner',
            'guard_name' => 'web',
            'organization_id' => $this->organization->id,
        ]);

        $user->assignRole($ownerRole);
        $user->refresh();

        $this->assertTrue($user->isOrganizationAdmin()); // Owner should also be admin
    }

    public function test_is_super_admin_checks_global_super_admin_role(): void
    {
        $user = User::factory()->create();

        $superAdminRole = Role::create([
            'name' => 'Super Admin',
            'guard_name' => 'web',
            'organization_id' => null, // Global role
        ]);

        $user->roles()->attach($superAdminRole->id);

        $this->assertTrue($user->isSuperAdmin());
    }

    public function test_is_social_user_returns_true_when_provider_exists(): void
    {
        $user = User::factory()->create([
            'provider' => 'google',
            'provider_id' => '123456789',
        ]);

        $this->assertTrue($user->isSocialUser());
    }

    public function test_is_social_user_returns_false_when_no_provider(): void
    {
        $user = User::factory()->create([
            'provider' => null,
            'provider_id' => null,
        ]);

        $this->assertFalse($user->isSocialUser());
    }

    public function test_has_password_returns_true_when_password_exists(): void
    {
        $user = User::factory()->create(['password' => 'hashed_password']);

        $this->assertTrue($user->hasPassword());
    }

    public function test_has_password_returns_false_when_no_password(): void
    {
        $user = User::factory()->create(['password' => null]);

        $this->assertFalse($user->hasPassword());
    }

    public function test_get_provider_display_name_returns_formatted_names(): void
    {
        $providerMappings = [
            'google' => 'Google',
            'github' => 'GitHub',
            'facebook' => 'Facebook',
            'twitter' => 'Twitter',
            'linkedin' => 'LinkedIn',
            'custom' => 'Custom', // Test default case
            null => 'Local',
        ];

        foreach ($providerMappings as $provider => $expected) {
            $user = User::factory()->create(['provider' => $provider]);
            $this->assertEquals($expected, $user->getProviderDisplayName());
        }
    }

    public function test_find_by_social_provider_finds_correct_user(): void
    {
        $user1 = User::factory()->create([
            'provider' => 'google',
            'provider_id' => '123456789',
        ]);

        $user2 = User::factory()->create([
            'provider' => 'github',
            'provider_id' => '987654321',
        ]);

        $foundUser = User::findBySocialProvider('google', '123456789');
        $this->assertEquals($user1->id, $foundUser->id);

        $notFoundUser = User::findBySocialProvider('google', 'nonexistent');
        $this->assertNull($notFoundUser);
    }

    public function test_create_or_update_from_social_creates_new_user(): void
    {
        $userData = [
            'name' => 'John Doe',
            'email' => 'john@example.com',
            'avatar' => 'https://example.com/avatar.jpg',
        ];

        $user = User::createOrUpdateFromSocial(
            'google',
            '123456789',
            $userData,
            'access_token',
            'refresh_token'
        );

        $this->assertInstanceOf(User::class, $user);
        $this->assertEquals('google', $user->provider);
        $this->assertEquals('123456789', $user->provider_id);
        $this->assertEquals('John Doe', $user->name);
        $this->assertEquals('john@example.com', $user->email);
        $this->assertEquals('access_token', $user->provider_token);
        $this->assertEquals('refresh_token', $user->provider_refresh_token);
        $this->assertNotNull($user->email_verified_at);
    }

    public function test_create_or_update_from_social_updates_existing_user(): void
    {
        $existingUser = User::factory()->create([
            'provider' => 'google',
            'provider_id' => '123456789',
            'name' => 'Old Name',
            'email' => 'old@example.com',
        ]);

        $userData = [
            'name' => 'New Name',
            'email' => 'new@example.com',
            'avatar' => 'https://example.com/new-avatar.jpg',
        ];

        $user = User::createOrUpdateFromSocial(
            'google',
            '123456789',
            $userData,
            'new_access_token'
        );

        $this->assertEquals($existingUser->id, $user->id);
        $this->assertEquals('New Name', $user->name);
        $this->assertEquals('new@example.com', $user->email);
        $this->assertEquals('new_access_token', $user->provider_token);
    }
}
