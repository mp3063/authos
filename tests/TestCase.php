<?php

namespace Tests;

use App\Models\Organization;
use App\Models\User;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Foundation\Testing\TestCase as BaseTestCase;
use Illuminate\Support\Facades\Artisan;
use Laravel\Passport\Passport;
use Spatie\Permission\Models\Role;

abstract class TestCase extends BaseTestCase
{
    // Keep original RefreshDatabase but add memory optimizations
    use RefreshDatabase;

    // Memory optimization: Cache expensive operations
    protected static bool $passportInitialized = false;

    protected static array $rolesAndPermissionsSeeded = [];

    protected function setUp(): void
    {
        parent::setUp();

        // Set up Passport for testing (cached)
        $this->setupPassport();
    }

    /**
     * Set up Passport OAuth for testing (optimized with caching)
     */
    protected function setupPassport(): void
    {
        // Only initialize Passport once per test suite
        if (! static::$passportInitialized) {
            // Use proper Passport setup for v13.x testing
            if (file_exists(storage_path('oauth-keys'))) {
                Passport::loadKeysFrom(storage_path('oauth-keys'));
            } else {
                // Generate keys only once
                Artisan::call('passport:keys', ['--force' => true]);
            }

            // Create personal access client only once
            Artisan::call('passport:client', [
                '--personal' => true,
                '--no-interaction' => true,
                '--name' => 'Test Personal Access Client',
            ]);

            static::$passportInitialized = true;
        }
    }

    protected function createUser(array $attributes = [], string $role = 'user', string $guard = 'web'): User
    {
        // Only create organization if not provided in attributes
        if (! isset($attributes['organization_id'])) {
            $organization = Organization::factory()->create();
            $attributes['organization_id'] = $organization->id;
        } else {
            $organization = Organization::find($attributes['organization_id']);
        }

        $user = User::factory()->create($attributes);

        if ($role) {
            // Memory optimization: Cache basic role/permission setup
            $orgId = $role === 'Super Admin' ? 'global' : $user->organization_id;
            $basicCacheKey = "basic_roles_{$guard}";

            // Only setup basic roles once per guard (avoid memory optimization conflicts)
            if (! isset(static::$rolesAndPermissionsSeeded[$basicCacheKey])) {
                $this->seedRolesAndPermissions(); // Ensure base permissions exist
                static::$rolesAndPermissionsSeeded[$basicCacheKey] = true;
            }

            // Always setup roles and permissions (but cache the expensive seeding)
            $this->setupRoleWithPermissions($role, $guard, $user->organization_id);

            // CRITICAL FIX: Set the team context BEFORE role operations
            app(\Spatie\Permission\PermissionRegistrar::class)->setPermissionsTeamId($user->organization_id);

            // Find the role (should exist after setup)
            $roleModel = Role::where('name', $role)
                ->where('guard_name', $guard)
                ->where('organization_id', $role === 'Super Admin' ? null : $user->organization_id)
                ->first();

            if ($roleModel) {
                // CRITICAL FIX: Set team context on user before role assignment
                $user->setPermissionsTeamId($user->organization_id);

                // Assign role with proper team context
                $user->assignRole($roleModel);

                // Refresh the user model to ensure the role is properly loaded
                $user->refresh();
                $user->load('roles', 'permissions');
            }
        }

        return $user;
    }

    protected function createOrganization(array $attributes = []): Organization
    {
        return Organization::factory()->create($attributes);
    }

    protected function createSuperAdmin(array $attributes = []): User
    {
        return $this->createUser($attributes, 'Super Admin');
    }

    protected function createOrganizationAdmin(array $attributes = []): User
    {
        return $this->createUser($attributes, 'Organization Admin');
    }

    protected function createApiSuperAdmin(array $attributes = []): User
    {
        return $this->createUser($attributes, 'Super Admin', 'api');
    }

    protected function createApiOrganizationAdmin(array $attributes = []): User
    {
        return $this->createUser($attributes, 'Organization Admin', 'api');
    }

    protected function createApiUser(array $attributes = []): User
    {
        return $this->createUser($attributes, 'user', 'api');
    }

    protected function actingAsUser(?User $user = null): User
    {
        $user = $user ?: $this->createUser();
        $this->actingAs($user);

        return $user;
    }

    protected function actingAsAdmin(?User $admin = null): User
    {
        $admin = $admin ?: $this->createSuperAdmin();
        $this->actingAs($admin);

        return $admin;
    }

    protected function actingAsApiUser(?User $user = null): User
    {
        $user = $user ?: $this->createUser();
        Passport::actingAs($user);

        return $user;
    }

    protected function createAccessToken(User $user, array $scopes = ['*']): string
    {
        $token = $user->createToken('TestToken', $scopes);

        return $token->accessToken;
    }

    protected function seedRolesAndPermissions(): void
    {
        // Memory optimization: Only seed roles and permissions once per organization
        $organizationId = request()->get('organization_id', 'global');
        $cacheKey = "roles_permissions_{$organizationId}";

        if (! isset(static::$rolesAndPermissionsSeeded[$cacheKey])) {
            Artisan::call('db:seed', ['--class' => 'RolePermissionSeeder']);
            static::$rolesAndPermissionsSeeded[$cacheKey] = true;
        }
    }

    /**
     * Setup role with permissions (memory optimized)
     */
    protected function setupRoleWithPermissions(string $role, string $guard, int $organizationId): void
    {
        $roleModel = Role::firstOrCreate([
            'name' => $role,
            'guard_name' => $guard,
            'organization_id' => $role === 'Super Admin' ? null : $organizationId,
        ]);

        // Get permissions for role
        $permissions = $this->getPermissionsForRole($role);

        if (! empty($permissions)) {
            // Create permissions with organization context (global for Super Admin)
            foreach ($permissions as $permissionName) {
                \Spatie\Permission\Models\Permission::firstOrCreate([
                    'name' => $permissionName,
                    'guard_name' => $guard,
                    'organization_id' => $role === 'Super Admin' ? null : $organizationId,
                ]);
            }

            // Sync permissions to role
            $query = \Spatie\Permission\Models\Permission::whereIn('name', $permissions)
                ->where('guard_name', $guard);

            if ($role === 'Super Admin') {
                $query->whereNull('organization_id');
            } else {
                $query->where('organization_id', $organizationId);
            }

            $permissionModels = $query->get();
            $roleModel->syncPermissions($permissionModels);
        }
    }

    /**
     * Get permissions for a given role (centralized definition)
     */
    protected function getPermissionsForRole(string $role): array
    {
        $permissions = [
            'Super Admin' => [
                'users.create', 'users.read', 'users.update', 'users.delete',
                'applications.create', 'applications.read', 'applications.update', 'applications.delete',
                'applications.regenerate_credentials',
                'organizations.read', 'organizations.update', 'organizations.create', 'organizations.delete', 'organizations.manage_users',
                'roles.create', 'roles.read', 'roles.update', 'roles.delete', 'roles.assign',
                'permissions.create', 'permissions.read', 'permissions.update', 'permissions.delete',
                'auth_logs.read', 'auth_logs.export',
                'system.settings.read', 'system.settings.update', 'system.analytics.read',
                'oauth.manage', 'admin.access',
            ],
            'Organization Owner' => [
                'users.create', 'users.read', 'users.update', 'users.delete',
                'applications.create', 'applications.read', 'applications.update', 'applications.delete',
                'applications.regenerate_credentials',
                'organizations.read', 'organizations.update', 'organizations.manage_users',
                'roles.create', 'roles.read', 'roles.update', 'roles.delete', 'roles.assign',
                'permissions.create', 'permissions.read', 'permissions.update', 'permissions.delete',
                'auth_logs.read', 'auth_logs.export',
            ],
            'Organization Admin' => [
                'users.create', 'users.read', 'users.update',
                'applications.create', 'applications.read', 'applications.update', 'applications.delete',
                'organizations.read', 'organizations.update', 'organizations.manage_users',
                'roles.create', 'roles.read', 'roles.update', 'roles.delete', 'roles.assign',
                'permissions.read',
                'auth_logs.read',
            ],
        ];

        return $permissions[$role] ?? [];
    }

    protected function assertJsonStructureExact(array $structure, $json = null): void
    {
        if (is_null($json)) {
            $json = $this->response->json();
        }

        foreach ($structure as $key => $value) {
            if (is_array($value)) {
                $this->assertArrayHasKey($key, $json);
                $this->assertJsonStructureExact($value, $json[$key]);
            } else {
                $this->assertArrayHasKey($value, $json);
            }
        }
    }

    protected function assertDatabaseHasModel($model, array $attributes = []): void
    {
        $this->assertDatabaseHas($model->getTable(), array_merge([
            $model->getKeyName() => $model->getKey(),
        ], $attributes));
    }

    protected function assertDatabaseMissingModel($model): void
    {
        $this->assertDatabaseMissing($model->getTable(), [
            $model->getKeyName() => $model->getKey(),
        ]);
    }
}
