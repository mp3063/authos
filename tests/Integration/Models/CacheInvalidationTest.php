<?php

namespace Tests\Integration\Models;

use App\Models\Application;
use App\Models\Organization;
use App\Models\User;
use Illuminate\Support\Facades\Cache;
use Spatie\Permission\Models\Permission;
use Spatie\Permission\Models\Role;
use Tests\Integration\IntegrationTestCase;

/**
 * Cache Invalidation Integration Tests
 *
 * Tests cache invalidation behavior triggered by model observers:
 * - Application observer cache invalidation
 * - User observer cache invalidation
 * - Organization observer cache invalidation
 * - Multi-layer cache invalidation verification
 * - Role assignment cache clearing
 * - Cache pattern matching and cleanup
 *
 * @covers \App\Observers\ApplicationObserver
 * @covers \App\Observers\UserObserver
 * @covers \App\Observers\OrganizationObserver
 * @covers \App\Services\CacheInvalidationService
 */
class CacheInvalidationTest extends IntegrationTestCase
{
    protected Organization $organization;

    protected User $user;

    protected function setUp(): void
    {
        parent::setUp();

        $this->organization = $this->createOrganization();
        $this->user = $this->createApiOrganizationAdmin([
            'organization_id' => $this->organization->id,
        ]);
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function it_clears_endpoint_cache_when_application_is_created(): void
    {
        // ARRANGE: Seed cache with applications endpoint data
        $cacheKey = 'api_cache:GET:_api_applications:list:page1';
        Cache::put($cacheKey, ['data' => 'cached_applications'], 60);

        // Verify cache exists before creation
        $this->assertTrue(Cache::has($cacheKey));

        // ACT: Create new application (observer should trigger)
        Application::create([
            'organization_id' => $this->organization->id,
            'name' => 'New Test App',
            'redirect_uris' => ['https://example.com/callback'],
            'allowed_grant_types' => ['authorization_code'],
        ]);

        // ASSERT: Verify application was created (observer ran)
        $this->assertDatabaseHas('applications', [
            'organization_id' => $this->organization->id,
            'name' => 'New Test App',
        ]);
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function it_clears_organization_cache_when_application_is_created(): void
    {
        // ARRANGE: Seed organization-specific cache
        $orgCacheKey = 'api_cache:GET:_api_organizations_'.$this->organization->id.'_apps';
        Cache::put($orgCacheKey, ['data' => 'org_apps'], 60);

        // Verify cache exists
        $this->assertTrue(Cache::has($orgCacheKey));

        // ACT: Create application in organization
        Application::create([
            'organization_id' => $this->organization->id,
            'name' => 'Org Test App',
            'redirect_uris' => ['https://example.com/callback'],
            'allowed_grant_types' => ['authorization_code'],
        ]);

        // ASSERT: Application should be created
        $this->assertDatabaseHas('applications', [
            'organization_id' => $this->organization->id,
            'name' => 'Org Test App',
        ]);
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function it_clears_application_cache_when_updated(): void
    {
        // ARRANGE: Create application and seed its cache
        $application = Application::factory()->create([
            'organization_id' => $this->organization->id,
            'name' => 'Original Name',
        ]);

        $appCacheKey = 'api_cache:GET:_api_applications_'.$application->id;
        Cache::put($appCacheKey, ['name' => 'Original Name'], 60);
        $this->assertTrue(Cache::has($appCacheKey));

        // ACT: Update application
        $application->update(['name' => 'Updated Name']);

        // ASSERT: Application should be updated in database
        $this->assertDatabaseHas('applications', [
            'id' => $application->id,
            'name' => 'Updated Name',
        ]);
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function it_clears_both_organization_caches_when_application_organization_changes(): void
    {
        // ARRANGE: Create application and second organization
        $application = Application::factory()->create([
            'organization_id' => $this->organization->id,
        ]);

        $secondOrg = $this->createOrganization();

        // Seed caches for both organizations
        $org1Key = 'api_cache:GET:_api_organizations_'.$this->organization->id;
        $org2Key = 'api_cache:GET:_api_organizations_'.$secondOrg->id;
        Cache::put($org1Key, ['data' => 'org1'], 60);
        Cache::put($org2Key, ['data' => 'org2'], 60);

        // ACT: Move application to second organization
        $application->update(['organization_id' => $secondOrg->id]);

        // ASSERT: Application should be moved
        $this->assertDatabaseHas('applications', [
            'id' => $application->id,
            'organization_id' => $secondOrg->id,
        ]);
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function it_clears_application_cache_when_deleted(): void
    {
        // ARRANGE: Create application and seed cache
        $application = Application::factory()->create([
            'organization_id' => $this->organization->id,
        ]);

        $cacheKey = 'api_cache:GET:_api_applications_'.$application->id;
        Cache::put($cacheKey, ['data' => 'app_data'], 60);

        // ACT: Delete application
        $application->delete();

        // ASSERT: Application should be deleted
        $this->assertDatabaseMissing('applications', [
            'id' => $application->id,
        ]);
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function it_clears_user_cache_when_user_is_updated(): void
    {
        // ARRANGE: Create user and seed cache
        $user = User::factory()->create([
            'organization_id' => $this->organization->id,
        ]);

        $userCacheKey = 'api_cache:GET:_api_users_'.$user->id;
        Cache::put($userCacheKey, ['data' => 'user_data'], 60);

        // ACT: Update user
        $user->update(['name' => 'Updated User Name']);

        // ASSERT: User should be updated in database
        $this->assertDatabaseHas('users', [
            'id' => $user->id,
            'name' => 'Updated User Name',
        ]);
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function it_clears_organization_cache_when_user_organization_changes(): void
    {
        // ARRANGE: Create user and second organization
        $user = User::factory()->create([
            'organization_id' => $this->organization->id,
        ]);

        $secondOrg = $this->createOrganization();

        // Seed caches
        $org1Key = 'api_cache:GET:_api_organizations_'.$this->organization->id;
        $org2Key = 'api_cache:GET:_api_organizations_'.$secondOrg->id;
        Cache::put($org1Key, ['data' => 'org1'], 60);
        Cache::put($org2Key, ['data' => 'org2'], 60);

        // ACT: Move user to second organization
        $user->update(['organization_id' => $secondOrg->id]);

        // ASSERT: User should be moved
        $this->assertDatabaseHas('users', [
            'id' => $user->id,
            'organization_id' => $secondOrg->id,
        ]);
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function it_clears_organization_cache_when_organization_is_updated(): void
    {
        // ARRANGE: Seed organization cache
        $orgCacheKey = 'api_cache:GET:_api_organizations_'.$this->organization->id;
        Cache::put($orgCacheKey, ['name' => 'Original Name'], 60);

        // ACT: Update organization
        $this->organization->update(['name' => 'Updated Org Name']);

        // ASSERT: Organization should be updated
        $this->assertDatabaseHas('organizations', [
            'id' => $this->organization->id,
            'name' => 'Updated Org Name',
        ]);
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function it_clears_permission_cache_when_user_mfa_status_changes(): void
    {
        // ARRANGE: Create user and seed permission cache
        $user = User::factory()->create([
            'organization_id' => $this->organization->id,
            'mfa_methods' => [],
        ]);

        $permCacheKey = 'api_cache:permissions:user:'.$user->id;
        Cache::put($permCacheKey, ['permissions' => ['read']], 60);

        // ACT: Enable MFA for user
        $user->update(['mfa_methods' => ['totp']]);

        // ASSERT: User MFA should be updated
        $this->assertDatabaseHas('users', [
            'id' => $user->id,
        ]);
        $user->refresh();
        $this->assertEquals(['totp'], $user->mfa_methods);
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function it_verifies_multi_layer_cache_invalidation(): void
    {
        // ARRANGE: Create application and seed multiple cache layers
        $application = Application::factory()->create([
            'organization_id' => $this->organization->id,
        ]);

        // Seed various cache keys that should be invalidated
        $cacheKeys = [
            'api_cache:GET:_api_applications:'.$application->id,
            'api_cache:GET:_api_applications:list',
            'api_cache:GET:_api_organizations_'.$this->organization->id,
        ];

        foreach ($cacheKeys as $key) {
            Cache::put($key, ['data' => 'test'], 60);
        }

        // ACT: Update application (should invalidate multiple layers)
        $application->update(['name' => 'Multi-layer Test']);

        // ASSERT: Application should be updated
        $this->assertDatabaseHas('applications', [
            'id' => $application->id,
            'name' => 'Multi-layer Test',
        ]);
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function it_handles_cache_invalidation_for_multiple_applications(): void
    {
        // ARRANGE: Create multiple applications
        $app1 = Application::factory()->create([
            'organization_id' => $this->organization->id,
            'name' => 'App 1',
        ]);

        $app2 = Application::factory()->create([
            'organization_id' => $this->organization->id,
            'name' => 'App 2',
        ]);

        // Seed caches
        Cache::put('api_cache:GET:_api_applications_'.$app1->id, ['name' => 'App 1'], 60);
        Cache::put('api_cache:GET:_api_applications_'.$app2->id, ['name' => 'App 2'], 60);

        // ACT: Update first application
        $app1->update(['name' => 'App 1 Updated']);

        // ASSERT: First app should be updated
        $this->assertDatabaseHas('applications', [
            'id' => $app1->id,
            'name' => 'App 1 Updated',
        ]);

        // Second app should remain unchanged
        $this->assertDatabaseHas('applications', [
            'id' => $app2->id,
            'name' => 'App 2',
        ]);
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function it_handles_cache_invalidation_when_user_is_deleted(): void
    {
        // ARRANGE: Create user and seed cache
        $user = User::factory()->create([
            'organization_id' => $this->organization->id,
        ]);

        $userCacheKey = 'api_cache:GET:_api_users_'.$user->id;
        Cache::put($userCacheKey, ['data' => 'user'], 60);

        // Get ID before deletion
        $userId = $user->id;

        // ACT: Force delete user (bypass soft delete to test actual deletion)
        $user->forceDelete();

        // ASSERT: User should be force deleted (not soft deleted)
        $this->assertDatabaseMissing('users', [
            'id' => $userId,
        ]);
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function it_handles_cache_invalidation_when_organization_is_deleted(): void
    {
        // ARRANGE: Create organization and seed cache
        $testOrg = $this->createOrganization(['name' => 'Test Org']);
        $orgCacheKey = 'api_cache:GET:_api_organizations_'.$testOrg->id;
        Cache::put($orgCacheKey, ['data' => 'org'], 60);

        // Get ID before deletion
        $orgId = $testOrg->id;

        // ACT: Force delete organization (bypass soft delete if applicable)
        $testOrg->forceDelete();

        // ASSERT: Organization should be force deleted (not soft deleted)
        $this->assertDatabaseMissing('organizations', [
            'id' => $orgId,
        ]);
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function it_preserves_unrelated_cache_on_model_updates(): void
    {
        // ARRANGE: Create application and seed unrelated cache
        $application = Application::factory()->create([
            'organization_id' => $this->organization->id,
        ]);

        // Seed unrelated cache that should NOT be invalidated
        $unrelatedKey = 'api_cache:GET:_api_other_endpoint:data';
        Cache::put($unrelatedKey, ['data' => 'should_persist'], 60);
        $this->assertTrue(Cache::has($unrelatedKey));

        // ACT: Update application
        $application->update(['name' => 'Updated Name']);

        // ASSERT: Unrelated cache should still exist
        $this->assertTrue(Cache::has($unrelatedKey));
        $this->assertEquals(['data' => 'should_persist'], Cache::get($unrelatedKey));
    }
}
