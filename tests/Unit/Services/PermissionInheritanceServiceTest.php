<?php

namespace Tests\Unit\Services;

use App\Models\Application;
use App\Models\ApplicationGroup;
use App\Models\Organization;
use App\Models\User;
use App\Services\PermissionInheritanceService;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Tests\TestCase;

class PermissionInheritanceServiceTest extends TestCase
{
    use RefreshDatabase;

    private PermissionInheritanceService $permissionService;

    private Organization $organization;

    private User $user;

    private ApplicationGroup $parentGroup;

    private ApplicationGroup $childGroup;

    private Application $parentApp;

    private Application $childApp;

    protected function setUp(): void
    {
        parent::setUp();

        $this->permissionService = app(PermissionInheritanceService::class);
        $this->organization = Organization::factory()->create();
        $this->user = User::factory()->forOrganization($this->organization)->create();

        // Create application groups with parent-child relationship
        $this->parentGroup = ApplicationGroup::factory()
            ->forOrganization($this->organization)
            ->create();

        $this->childGroup = ApplicationGroup::factory()
            ->childOf($this->parentGroup)
            ->create([
                'settings' => [
                    'inheritance_enabled' => true,
                    'auto_assign_users' => false,
                    'default_permissions' => ['read'],
                ],
            ]);

        // Create applications in each group
        $this->parentApp = Application::factory()
            ->forOrganization($this->organization)
            ->create();

        $this->childApp = Application::factory()
            ->forOrganization($this->organization)
            ->create();

        // Associate applications with groups
        $this->parentGroup->applications()->attach($this->parentApp->id);
        $this->childGroup->applications()->attach($this->childApp->id);
    }

    public function test_calculate_inherited_permissions_returns_parent_permissions(): void
    {
        // Grant user access to parent group
        $this->user->applications()->attach($this->parentApp->id, [
            'permissions' => ['read', 'write'],
            'granted_at' => now(),
        ]);

        $inheritedPermissions = $this->permissionService->calculateInheritedPermissions(
            $this->user->id,
            $this->childApp->id
        );

        $this->assertCount(2, $inheritedPermissions);
        $this->assertContains('read', $inheritedPermissions);
        $this->assertContains('write', $inheritedPermissions);
    }

    public function test_calculate_inherited_permissions_combines_direct_and_inherited(): void
    {
        // Grant user direct access to child app
        $this->user->applications()->attach($this->childApp->id, [
            'permissions' => ['read'],
            'granted_at' => now(),
            'granted_by' => $this->user->id, // Direct access - granted by self or admin
        ]);

        // Grant user access to parent app
        $this->user->applications()->attach($this->parentApp->id, [
            'permissions' => ['write', 'admin'],
            'granted_at' => now(),
            'granted_by' => $this->user->id, // Direct access - granted by self or admin
        ]);

        $allPermissions = $this->permissionService->calculateInheritedPermissions(
            $this->user->id,
            $this->childApp->id
        );

        $this->assertCount(3, $allPermissions);
        $this->assertContains('read', $allPermissions);
        $this->assertContains('write', $allPermissions);
        $this->assertContains('admin', $allPermissions);
    }

    public function test_calculate_inherited_permissions_respects_inheritance_disabled(): void
    {
        // Disable inheritance on child group
        $this->childGroup->update([
            'settings' => array_merge($this->childGroup->settings, [
                'inheritance_enabled' => false,
            ]),
        ]);

        // Grant user access to parent app
        $this->user->applications()->attach($this->parentApp->id, [
            'permissions' => ['admin'],
            'granted_at' => now(),
        ]);

        $inheritedPermissions = $this->permissionService->calculateInheritedPermissions(
            $this->user->id,
            $this->childApp->id
        );

        $this->assertEmpty($inheritedPermissions);
    }

    public function test_cascade_permissions_to_children_applies_permissions_down_hierarchy(): void
    {
        // Create multiple levels of hierarchy
        $grandchildGroup = ApplicationGroup::factory()
            ->childOf($this->childGroup)
            ->create([
                'settings' => [
                    'inheritance_enabled' => true,
                    'auto_assign_users' => false,
                    'default_permissions' => ['read'],
                ],
            ]);

        $grandchildApp = Application::factory()
            ->forOrganization($this->organization)
            ->create();

        $grandchildGroup->applications()->attach($grandchildApp->id);

        // Grant permissions at parent level
        $this->user->applications()->attach($this->parentApp->id, [
            'permissions' => ['read', 'write'],
            'granted_at' => now(),
        ]);

        $cascadedCount = $this->permissionService->cascadePermissionsToChildren(
            $this->user->id,
            $this->parentApp->id
        );

        // Should cascade to child and grandchild
        $this->assertEquals(2, $cascadedCount);

        // Verify permissions were cascaded
        $childPermissions = $this->permissionService->getEffectivePermissions(
            $this->user->id,
            $this->childApp->id
        );
        $this->assertContains('read', $childPermissions);
        $this->assertContains('write', $childPermissions);

        $grandchildPermissions = $this->permissionService->getEffectivePermissions(
            $this->user->id,
            $grandchildApp->id
        );
        $this->assertContains('read', $grandchildPermissions);
        $this->assertContains('write', $grandchildPermissions);
    }

    public function test_get_permission_inheritance_chain_returns_complete_hierarchy(): void
    {
        $chain = $this->permissionService->getPermissionInheritanceChain($this->childApp->id);

        $this->assertCount(2, $chain);
        $this->assertEquals($this->childGroup->id, $chain[0]['group_id']);
        $this->assertEquals($this->parentGroup->id, $chain[1]['group_id']);
        $this->assertEquals('parent', $chain[1]['relationship']);
    }

    public function test_get_effective_permissions_combines_all_sources(): void
    {
        // Direct permissions
        $this->user->applications()->attach($this->childApp->id, [
            'permissions' => ['read'],
            'granted_at' => now(),
            'granted_by' => $this->user->id, // Direct access
        ]);

        // Inherited permissions
        $this->user->applications()->attach($this->parentApp->id, [
            'permissions' => ['write', 'admin'],
            'granted_at' => now(),
            'granted_by' => $this->user->id, // Direct access
        ]);

        $effectivePermissions = $this->permissionService->getEffectivePermissions(
            $this->user->id,
            $this->childApp->id
        );

        $this->assertCount(3, $effectivePermissions);
        $this->assertContains('read', $effectivePermissions);
        $this->assertContains('write', $effectivePermissions);
        $this->assertContains('admin', $effectivePermissions);
    }

    public function test_get_permission_source_identifies_inheritance_origin(): void
    {
        // Grant permission through parent
        $this->user->applications()->attach($this->parentApp->id, [
            'permissions' => ['admin'],
            'granted_at' => now(),
        ]);

        $source = $this->permissionService->getPermissionSource(
            $this->user->id,
            $this->childApp->id,
            'admin'
        );

        $this->assertEquals('inherited', $source['type']);
        $this->assertEquals($this->parentApp->id, $source['source_application_id']);
        $this->assertEquals($this->parentGroup->id, $source['source_group_id']);
    }

    public function test_revoke_cascaded_permissions_removes_inherited_permissions(): void
    {
        // Grant and cascade permissions
        $this->user->applications()->attach($this->parentApp->id, [
            'permissions' => ['read', 'write'],
            'granted_at' => now(),
        ]);

        $cascadedCount = $this->permissionService->cascadePermissionsToChildren(
            $this->user->id,
            $this->parentApp->id
        );

        // Verify cascade worked
        $this->assertGreaterThan(0, $cascadedCount, 'Cascade should create at least one relationship');

        // Verify child app has cascaded access
        $childRelation = $this->user->applications()->where('application_id', $this->childApp->id)->first();
        $this->assertNotNull($childRelation, 'Child app should have cascaded access');
        $this->assertNull($childRelation->pivot->granted_by, 'Should be inherited access (granted_by = null)');
        $this->assertEquals(['read', 'write'], $childRelation->pivot->permissions, 'Should have cascaded permissions');

        // Revoke cascaded permissions
        $revokedCount = $this->permissionService->revokeCascadedPermissions(
            $this->user->id,
            $this->parentApp->id,
            ['write']
        );

        $this->assertEquals(1, $revokedCount);

        // Verify write permission was removed but read remains
        $remainingPermissions = $this->permissionService->getEffectivePermissions(
            $this->user->id,
            $this->childApp->id
        );

        $this->assertContains('read', $remainingPermissions);
        $this->assertNotContains('write', $remainingPermissions);
    }

    public function test_detect_circular_dependencies_prevents_infinite_loops(): void
    {
        // Create circular dependency: parent -> child -> parent
        $this->parentGroup->update(['parent_id' => $this->childGroup->id]);

        $hasCircularDependency = $this->permissionService->detectCircularDependencies(
            $this->parentGroup->id
        );

        $this->assertTrue($hasCircularDependency);
    }

    public function test_get_permission_audit_trail_tracks_inheritance_history(): void
    {
        // Grant permission
        $this->user->applications()->attach($this->parentApp->id, [
            'permissions' => ['admin'],
            'granted_at' => now(),
        ]);

        // Cascade to children
        $this->permissionService->cascadePermissionsToChildren(
            $this->user->id,
            $this->parentApp->id
        );

        $auditTrail = $this->permissionService->getPermissionAuditTrail(
            $this->user->id,
            $this->childApp->id
        );

        $this->assertNotEmpty($auditTrail);
        $this->assertArrayHasKey('inherited_permissions', $auditTrail);
        $this->assertArrayHasKey('inheritance_chain', $auditTrail);
        $this->assertArrayHasKey('cascade_history', $auditTrail);
    }

    public function test_bulk_update_inheritance_settings_updates_multiple_groups(): void
    {
        $groups = [$this->parentGroup->id, $this->childGroup->id];
        $settings = ['inheritance_enabled' => false];

        $updatedCount = $this->permissionService->bulkUpdateInheritanceSettings($groups, $settings);

        $this->assertEquals(2, $updatedCount);

        // Verify settings were updated
        $this->parentGroup->refresh();
        $this->childGroup->refresh();

        $this->assertFalse($this->parentGroup->settings['inheritance_enabled']);
        $this->assertFalse($this->childGroup->settings['inheritance_enabled']);
    }

    public function test_validate_inheritance_hierarchy_detects_issues(): void
    {
        // Create a group with missing inheritance settings to test inconsistent settings detection
        $inconsistentGroup = ApplicationGroup::factory()
            ->forOrganization($this->organization)
            ->create([
                'name' => 'Inconsistent Group',
                'settings' => [], // Missing inheritance_enabled setting
            ]);

        // Test validation when there are no issues (should pass)
        $validationResults = $this->permissionService->validateInheritanceHierarchy(
            $this->organization->id
        );

        $this->assertArrayHasKey('orphaned_groups', $validationResults);
        $this->assertArrayHasKey('circular_dependencies', $validationResults);
        $this->assertArrayHasKey('inconsistent_settings', $validationResults);
        $this->assertArrayHasKey('validation_passed', $validationResults);
        $this->assertArrayHasKey('validated_at', $validationResults);

        // Should have no orphaned groups (database constraints prevent them)
        $this->assertEmpty($validationResults['orphaned_groups']);

        // Should have no circular dependencies (our test data is clean)
        $this->assertEmpty($validationResults['circular_dependencies']);

        // Should have found inconsistent settings
        $this->assertNotEmpty($validationResults['inconsistent_settings']);
        $inconsistentGroupIds = array_column($validationResults['inconsistent_settings'], 'group_id');
        $this->assertContains($inconsistentGroup->id, $inconsistentGroupIds);

        // Check the specific inconsistent group details
        $inconsistentGroup = $validationResults['inconsistent_settings'][0];
        $this->assertEquals('Inconsistent Group', $inconsistentGroup['group_name']);
        $this->assertEquals('inheritance_enabled', $inconsistentGroup['missing_setting']);

        // Validation should fail due to inconsistent settings
        $this->assertFalse($validationResults['validation_passed']);
    }

    public function test_get_users_with_inherited_access_finds_users_with_cascaded_permissions(): void
    {
        // Grant user access to parent
        $this->user->applications()->attach($this->parentApp->id, [
            'permissions' => ['read'],
            'granted_at' => now(),
        ]);

        // Create another user without access
        $otherUser = User::factory()->forOrganization($this->organization)->create();

        $usersWithAccess = $this->permissionService->getUsersWithInheritedAccess(
            $this->childApp->id
        );

        $this->assertCount(1, $usersWithAccess);
        $this->assertEquals($this->user->id, $usersWithAccess[0]['user_id']);
        $this->assertContains('read', $usersWithAccess[0]['inherited_permissions']);
    }
}
