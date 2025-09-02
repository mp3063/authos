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
        
        // Install Passport for API testing
        if (!$this->app->runningInConsole()) {
            Artisan::call('passport:keys', ['--force' => true]);
            Artisan::call('passport:install', ['--force' => true]);
        }
    }

    protected function createUser(array $attributes = [], string $role = 'user'): User
    {
        $organization = Organization::factory()->create();
        
        $user = User::factory()->create(array_merge([
            'organization_id' => $organization->id,
        ], $attributes));

        if ($role) {
            $roleModel = Role::firstOrCreate(['name' => $role, 'guard_name' => 'web']);
            $user->assignRole($roleModel);
        }

        return $user;
    }

    protected function createOrganization(array $attributes = []): Organization
    {
        return Organization::factory()->create($attributes);
    }

    protected function createSuperAdmin(array $attributes = []): User
    {
        return $this->createUser($attributes, 'super admin');
    }

    protected function createOrganizationAdmin(array $attributes = []): User
    {
        return $this->createUser($attributes, 'organization admin');
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
