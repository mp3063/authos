<?php

namespace Tests;

use App\Models\Organization;
use App\Models\User;
use Illuminate\Foundation\Testing\TestCase as BaseTestCase;
use Illuminate\Support\Facades\Artisan;
use Laravel\Passport\Passport;
use Spatie\Permission\Models\Role;

abstract class TestCase extends BaseTestCase
{
    // Use RefreshDatabase for much better performance (migrates once, uses transactions)
    // This is safe with PHP 8.4 and SQLite :memory: database
    use \Illuminate\Foundation\Testing\RefreshDatabase;

    // Memory optimization: Cache expensive operations (parallel-safe with static state)
    protected static bool $passportInitialized = false;

    protected static array $rolesAndPermissionsSeeded = [];

    // Parallel execution support: Each process gets its own database
    protected static bool $databaseInitialized = false;

    protected function setUp(): void
    {
        parent::setUp();

        // CRITICAL: Clear Spatie Permission cache aggressively for parallel test isolation
        if (class_exists(\Spatie\Permission\PermissionRegistrar::class)) {
            $registrar = app(\Spatie\Permission\PermissionRegistrar::class);

            // Clear all permission caches
            $registrar->forgetCachedPermissions();

            // Reset team context to null (important for multi-tenant tests)
            $registrar->setPermissionsTeamId(null);

            // Clear any Laravel cache that might store permissions
            if (app()->bound('cache')) {
                try {
                    \Illuminate\Support\Facades\Cache::tags(['spatie.permission.cache'])->flush();
                } catch (\Exception $e) {
                    // Some cache drivers don't support tags, that's okay
                }
            }
        }

        // Set up Passport for testing (cached, parallel-safe)
        $this->setupPassport();

        // Memory optimization: Reduce GC frequency for better performance
        // Only run GC every 10th test to reduce overhead
        if (function_exists('gc_collect_cycles') && rand(1, 10) === 1) {
            gc_collect_cycles();
        }
    }

    protected function tearDown(): void
    {
        // Clear authentication state BEFORE other cleanup to prevent issues
        if (auth()->hasUser()) {
            $user = auth()->user();
            if ($user && method_exists($user, 'setPermissionsTeamId')) {
                $user->setPermissionsTeamId(null);
            }
        }
        auth()->forgetGuards();

        // Explicitly close Mockery to prevent hanging
        if (class_exists(\Mockery::class)) {
            \Mockery::close();
        }

        // CRITICAL: Aggressively clear Spatie Permission cache to prevent test pollution
        if (class_exists(\Spatie\Permission\PermissionRegistrar::class)) {
            $registrar = app(\Spatie\Permission\PermissionRegistrar::class);

            // Clear all permission caches
            $registrar->forgetCachedPermissions();

            // Reset team context
            $registrar->setPermissionsTeamId(null);

            // Clear Laravel cache for permissions
            if (app()->bound('cache')) {
                try {
                    \Illuminate\Support\Facades\Cache::tags(['spatie.permission.cache'])->flush();
                } catch (\Exception $e) {
                    // Some cache drivers don't support tags
                }
            }
        }

        parent::tearDown();

        // Memory optimization: Reduce GC frequency in tearDown too
        // Transactions handle cleanup, so aggressive GC is unnecessary
    }

    /**
     * Set up Passport OAuth for testing (parallel-safe with optimized caching)
     */
    protected function setupPassport(): void
    {
        // Parallel-safe: Generate keys only once per process
        if (! static::$passportInitialized) {
            // Use proper Passport setup for v13.x testing
            // Keys are stored directly in storage/ not in a subdirectory
            $privateKeyPath = storage_path('oauth-private.key');
            $publicKeyPath = storage_path('oauth-public.key');

            if (file_exists($privateKeyPath) && file_exists($publicKeyPath)) {
                // Keys exist, ensure correct permissions (600 or 660)
                @chmod($privateKeyPath, 0600);
                @chmod($publicKeyPath, 0600);
            } else {
                // Generate keys only once (parallel-safe with file locking)
                $lockFile = storage_path('.generating_passport_keys.lock');

                $fp = fopen($lockFile, 'c+');
                if (flock($fp, LOCK_EX)) {
                    // Double-check after acquiring lock
                    if (! file_exists($privateKeyPath)) {
                        Artisan::call('passport:keys', ['--force' => true]);
                        // Ensure correct permissions after generation
                        if (file_exists($privateKeyPath)) {
                            @chmod($privateKeyPath, 0600);
                        }
                        if (file_exists($publicKeyPath)) {
                            @chmod($publicKeyPath, 0600);
                        }
                    }
                    flock($fp, LOCK_UN);
                }
                fclose($fp);
                @unlink($lockFile);
            }
            static::$passportInitialized = true;
        }

        // Parallel-safe: Each process/transaction gets its own clients
        // RefreshDatabase trait ensures each test starts fresh via transactions
        try {
            if (\Illuminate\Support\Facades\Schema::hasTable('oauth_clients')) {
                $existingClient = \Laravel\Passport\Client::where('personal_access_client', true)
                    ->where('provider', 'users')
                    ->first();

                if (! $existingClient) {
                    $clientRepository = app(\Laravel\Passport\ClientRepository::class);
                    $clientRepository->createPersonalAccessGrantClient(
                        'Test Personal Access Client',
                        'users'
                    );
                }
            }
        } catch (\Exception $e) {
            // Silently ignore errors during setup (migrations may not be complete)
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
                // CRITICAL FIX: Set team context based on role type
                $teamId = $role === 'Super Admin' ? null : $user->organization_id;
                $user->setPermissionsTeamId($teamId);
                app(\Spatie\Permission\PermissionRegistrar::class)->setPermissionsTeamId($teamId);

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
        $organization = Organization::factory()->create($attributes);

        // Automatically set up default roles for the organization in tests
        $organization->setupDefaultRoles();

        return $organization;
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
        return $this->createUser($attributes, 'User', 'api');
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

    protected function createAccessToken(User $user, array $scopes = ['*'], int|string|null $clientId = null): string
    {
        if ($clientId !== null) {
            // Create token with specific client ID for integration tests
            $tokenId = \Illuminate\Support\Str::random(80);
            \Laravel\Passport\Token::create([
                'id' => $tokenId,
                'user_id' => $user->id,
                'client_id' => $clientId,
                'name' => 'TestToken',
                'scopes' => $scopes,
                'revoked' => false,
                'expires_at' => now()->addHours(1),
            ]);

            return $tokenId;
        }

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
    protected function setupRoleWithPermissions(string $role, string $guard, ?int $organizationId): void
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

            // Clear cached permissions before syncing
            $roleModel->forgetCachedPermissions();

            $roleModel->syncPermissions($permissionModels);

            // Force refresh role permissions
            $roleModel->unsetRelation('permissions');
            $roleModel->load('permissions');
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
                'webhooks.create', 'webhooks.read', 'webhooks.update', 'webhooks.delete',
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
                'webhooks.create', 'webhooks.read', 'webhooks.update', 'webhooks.delete',
            ],
            'Organization Admin' => [
                'users.create', 'users.read', 'users.update',
                'applications.create', 'applications.read', 'applications.update', 'applications.delete',
                'organizations.read', 'organizations.update', 'organizations.manage_users',
                'roles.create', 'roles.read', 'roles.update', 'roles.delete', 'roles.assign',
                'permissions.read',
                'auth_logs.read',
                'webhooks.create', 'webhooks.read', 'webhooks.update', 'webhooks.delete',
            ],
            'User' => [
                'users.read',
                'applications.read',
                'organizations.read',
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
