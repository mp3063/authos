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
    use RefreshDatabase;

    protected function setUp(): void
    {
        parent::setUp();
        
        // Set up Passport for testing
        $this->setupPassport();
    }

    /**
     * Set up Passport OAuth for testing
     */
    protected function setupPassport(): void
    {
        // Use proper Passport setup for v13.x testing
        if (file_exists(storage_path('oauth-keys'))) {
            Passport::loadKeysFrom(storage_path('oauth-keys'));
        }
        
        // Create personal access client if it doesn't exist
        Artisan::call('passport:client', [
            '--personal' => true,
            '--no-interaction' => true,
            '--name' => 'Test Personal Access Client'
        ]);
    }

    protected function createUser(array $attributes = [], string $role = 'user', string $guard = 'web'): User
    {
        // Only create organization if not provided in attributes
        if (!isset($attributes['organization_id'])) {
            $organization = Organization::factory()->create();
            $attributes['organization_id'] = $organization->id;
        } else {
            $organization = Organization::find($attributes['organization_id']);
        }
        
        $user = User::factory()->create($attributes);

        if ($role) {
            // For testing, create a global role with the required permissions
            $this->seedRolesAndPermissions(); // Ensure permissions exist
            
            // CRITICAL FIX: Set the team context BEFORE role operations
            app(\Spatie\Permission\PermissionRegistrar::class)->setPermissionsTeamId($user->organization_id);
            
            $roleModel = Role::firstOrCreate([
                'name' => $role, 
                'guard_name' => $guard,
                'organization_id' => $user->organization_id
            ]);
            
            // Create permissions with the same organization context if they don't exist
            $permissions = [];
            if ($role === 'Super Admin') {
                $permissions = [
                    'users.create', 'users.read', 'users.update', 'users.delete',
                    'applications.create', 'applications.read', 'applications.update', 'applications.delete',
                    'applications.regenerate_credentials',
                    'organizations.read', 'organizations.update', 'organizations.create', 'organizations.delete', 'organizations.manage_users',
                    'roles.create', 'roles.read', 'roles.update', 'roles.delete', 'roles.assign',
                    'permissions.create', 'permissions.read', 'permissions.update', 'permissions.delete',
                    'auth_logs.read', 'auth_logs.export',
                    'system.settings.read', 'system.settings.update', 'system.analytics.read',
                    'oauth.manage', 'admin.access',
                ];
            } elseif ($role === 'Organization Owner') {
                $permissions = [
                    'users.create', 'users.read', 'users.update', 'users.delete',
                    'applications.create', 'applications.read', 'applications.update', 'applications.delete',
                    'applications.regenerate_credentials',
                    'organizations.read', 'organizations.update', 'organizations.manage_users',
                    'roles.create', 'roles.read', 'roles.update', 'roles.delete', 'roles.assign',
                    'permissions.create', 'permissions.read', 'permissions.update', 'permissions.delete',
                    'auth_logs.read', 'auth_logs.export',
                ];
            } elseif ($role === 'Organization Admin') {
                $permissions = [
                    'users.create', 'users.read', 'users.update',
                    'applications.create', 'applications.read', 'applications.update',
                    'organizations.read', 'organizations.update', 'organizations.manage_users',
                    'roles.read', 'roles.assign',
                    'permissions.read',
                    'auth_logs.read',
                ];
            }
            
            // Create permissions with organization context
            foreach ($permissions as $permissionName) {
                $permission = \Spatie\Permission\Models\Permission::firstOrCreate([
                    'name' => $permissionName,
                    'guard_name' => $guard,
                    'organization_id' => $user->organization_id
                ]);
            }
            
            // Sync permissions to role
            if (!empty($permissions)) {
                $permissionModels = \Spatie\Permission\Models\Permission::whereIn('name', $permissions)
                    ->where('guard_name', $guard)
                    ->where('organization_id', $user->organization_id)
                    ->get();
                $roleModel->syncPermissions($permissionModels);
            }
            
            
            // CRITICAL FIX: Set team context on user before role assignment
            $user->setPermissionsTeamId($user->organization_id);
            
            // Assign role with proper team context
            $user->assignRole($roleModel);
            
            
            // Refresh the user model to ensure the role is properly loaded
            $user->refresh();
            $user->load('roles', 'permissions');
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

    protected function actingAsUser(User $user = null): User
    {
        $user = $user ?: $this->createUser();
        $this->actingAs($user);
        return $user;
    }

    protected function actingAsAdmin(User $admin = null): User
    {
        $admin = $admin ?: $this->createSuperAdmin();
        $this->actingAs($admin);
        return $admin;
    }

    protected function actingAsApiUser(User $user = null): User
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
        Artisan::call('db:seed', ['--class' => 'RolePermissionSeeder']);
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
