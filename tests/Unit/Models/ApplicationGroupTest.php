<?php

namespace Tests\Unit\Models;

use App\Models\Application;
use App\Models\ApplicationGroup;
use App\Models\Organization;
use Tests\TestCase;

class ApplicationGroupTest extends TestCase
{
    private Organization $organization;

    private ApplicationGroup $parentGroup;

    protected function setUp(): void
    {
        parent::setUp();

        $this->organization = Organization::factory()->create();
        $this->parentGroup = ApplicationGroup::factory()
            ->forOrganization($this->organization)
            ->create();
    }

    public function test_application_group_belongs_to_organization(): void
    {
        $group = ApplicationGroup::factory()
            ->forOrganization($this->organization)
            ->create();

        $this->assertInstanceOf(Organization::class, $group->organization);
        $this->assertEquals($this->organization->id, $group->organization->id);
    }

    public function test_application_group_belongs_to_parent(): void
    {
        $childGroup = ApplicationGroup::factory()
            ->childOf($this->parentGroup)
            ->create();

        $this->assertInstanceOf(ApplicationGroup::class, $childGroup->parent);
        $this->assertEquals($this->parentGroup->id, $childGroup->parent->id);
    }

    public function test_application_group_has_many_children(): void
    {
        $child1 = ApplicationGroup::factory()
            ->childOf($this->parentGroup)
            ->create();

        $child2 = ApplicationGroup::factory()
            ->childOf($this->parentGroup)
            ->create();

        $this->assertCount(2, $this->parentGroup->children);
        $this->assertTrue($this->parentGroup->children->contains($child1));
        $this->assertTrue($this->parentGroup->children->contains($child2));
    }

    public function test_application_group_has_many_applications(): void
    {
        $app1 = Application::factory()->forOrganization($this->organization)->create();
        $app2 = Application::factory()->forOrganization($this->organization)->create();

        $this->parentGroup->applications()->attach([$app1->id, $app2->id]);

        $this->assertCount(2, $this->parentGroup->applications);
        $this->assertTrue($this->parentGroup->applications->contains($app1));
        $this->assertTrue($this->parentGroup->applications->contains($app2));
    }

    public function test_active_scope_filters_active_groups(): void
    {
        // Create active group
        $activeGroup = ApplicationGroup::factory()
            ->forOrganization($this->organization)
            ->create(['is_active' => true]);

        // Create inactive group
        $inactiveGroup = ApplicationGroup::factory()
            ->forOrganization($this->organization)
            ->inactive()
            ->create();

        $activeGroups = ApplicationGroup::active()->get();

        $this->assertTrue($activeGroups->contains($activeGroup));
        $this->assertFalse($activeGroups->contains($inactiveGroup));
    }

    public function test_for_organization_scope_filters_by_organization(): void
    {
        $otherOrganization = Organization::factory()->create();

        // Create group for our organization
        $ourGroup = ApplicationGroup::factory()
            ->forOrganization($this->organization)
            ->create();

        // Create group for other organization
        $otherGroup = ApplicationGroup::factory()
            ->forOrganization($otherOrganization)
            ->create();

        $organizationGroups = ApplicationGroup::forOrganization($this->organization->id)->get();

        $this->assertTrue($organizationGroups->contains($ourGroup));
        $this->assertFalse($organizationGroups->contains($otherGroup));
    }

    public function test_root_groups_scope_filters_root_level_groups(): void
    {
        // Create root group
        $rootGroup = ApplicationGroup::factory()
            ->forOrganization($this->organization)
            ->create(['parent_id' => null]);

        // Create child group
        $childGroup = ApplicationGroup::factory()
            ->childOf($rootGroup)
            ->create();

        $rootGroups = ApplicationGroup::rootGroups()->get();

        $this->assertTrue($rootGroups->contains($rootGroup));
        $this->assertFalse($rootGroups->contains($childGroup));
    }

    public function test_is_root_returns_true_for_root_group(): void
    {
        $rootGroup = ApplicationGroup::factory()
            ->forOrganization($this->organization)
            ->create(['parent_id' => null]);

        $this->assertTrue($rootGroup->isRoot());
    }

    public function test_is_root_returns_false_for_child_group(): void
    {
        $childGroup = ApplicationGroup::factory()
            ->childOf($this->parentGroup)
            ->create();

        $this->assertFalse($childGroup->isRoot());
    }

    public function test_has_children_returns_true_when_group_has_children(): void
    {
        ApplicationGroup::factory()
            ->childOf($this->parentGroup)
            ->create();

        $this->assertTrue($this->parentGroup->hasChildren());
    }

    public function test_has_children_returns_false_when_group_has_no_children(): void
    {
        $leafGroup = ApplicationGroup::factory()
            ->forOrganization($this->organization)
            ->create();

        $this->assertFalse($leafGroup->hasChildren());
    }

    public function test_get_depth_calculates_correct_depth(): void
    {
        // Root group (depth 0)
        $rootGroup = ApplicationGroup::factory()
            ->forOrganization($this->organization)
            ->create(['parent_id' => null]);

        // Child group (depth 1)
        $childGroup = ApplicationGroup::factory()
            ->childOf($rootGroup)
            ->create();

        // Grandchild group (depth 2)
        $grandchildGroup = ApplicationGroup::factory()
            ->childOf($childGroup)
            ->create();

        $this->assertEquals(0, $rootGroup->getDepth());
        $this->assertEquals(1, $childGroup->getDepth());
        $this->assertEquals(2, $grandchildGroup->getDepth());
    }

    public function test_get_ancestors_returns_parent_hierarchy(): void
    {
        // Create hierarchy: root -> child -> grandchild
        $rootGroup = ApplicationGroup::factory()
            ->forOrganization($this->organization)
            ->create(['parent_id' => null]);

        $childGroup = ApplicationGroup::factory()
            ->childOf($rootGroup)
            ->create();

        $grandchildGroup = ApplicationGroup::factory()
            ->childOf($childGroup)
            ->create();

        $ancestors = $grandchildGroup->getAncestors();

        $this->assertCount(2, $ancestors);
        $this->assertEquals($childGroup->id, $ancestors[0]->id);
        $this->assertEquals($rootGroup->id, $ancestors[1]->id);
    }

    public function test_get_descendants_returns_child_hierarchy(): void
    {
        // Create child groups
        $child1 = ApplicationGroup::factory()
            ->childOf($this->parentGroup)
            ->create();

        $child2 = ApplicationGroup::factory()
            ->childOf($this->parentGroup)
            ->create();

        // Create grandchild
        $grandchild = ApplicationGroup::factory()
            ->childOf($child1)
            ->create();

        $descendants = $this->parentGroup->getDescendants();

        $this->assertCount(3, $descendants);
        $this->assertTrue($descendants->contains('id', $child1->id));
        $this->assertTrue($descendants->contains('id', $child2->id));
        $this->assertTrue($descendants->contains('id', $grandchild->id));
    }

    public function test_has_inheritance_enabled_checks_settings(): void
    {
        $groupWithInheritance = ApplicationGroup::factory()
            ->forOrganization($this->organization)
            ->create([
                'settings' => ['inheritance_enabled' => true],
            ]);

        $groupWithoutInheritance = ApplicationGroup::factory()
            ->forOrganization($this->organization)
            ->noInheritance()
            ->create();

        $this->assertTrue($groupWithInheritance->hasInheritanceEnabled());
        $this->assertFalse($groupWithoutInheritance->hasInheritanceEnabled());
    }

    public function test_has_auto_assign_enabled_checks_settings(): void
    {
        $groupWithAutoAssign = ApplicationGroup::factory()
            ->forOrganization($this->organization)
            ->autoAssign()
            ->create();

        $groupWithoutAutoAssign = ApplicationGroup::factory()
            ->forOrganization($this->organization)
            ->create([
                'settings' => ['auto_assign_users' => false],
            ]);

        $this->assertTrue($groupWithAutoAssign->hasAutoAssignEnabled());
        $this->assertFalse($groupWithoutAutoAssign->hasAutoAssignEnabled());
    }

    public function test_get_default_permissions_returns_permissions_from_settings(): void
    {
        $permissions = ['read', 'write'];
        $group = ApplicationGroup::factory()
            ->forOrganization($this->organization)
            ->create([
                'settings' => ['default_permissions' => $permissions],
            ]);

        $this->assertEquals($permissions, $group->getDefaultPermissions());
    }

    public function test_add_application_attaches_application_to_group(): void
    {
        $application = Application::factory()->forOrganization($this->organization)->create();

        $this->parentGroup->addApplication($application->id);

        $this->assertTrue($this->parentGroup->applications->contains($application));
    }

    public function test_remove_application_detaches_application_from_group(): void
    {
        $application = Application::factory()->forOrganization($this->organization)->create();
        $this->parentGroup->applications()->attach($application->id);

        $this->parentGroup->removeApplication($application->id);

        $this->assertFalse($this->parentGroup->applications->contains($application));
    }

    public function test_move_to_parent_updates_parent_relationship(): void
    {
        $newParent = ApplicationGroup::factory()
            ->forOrganization($this->organization)
            ->create();

        $childGroup = ApplicationGroup::factory()
            ->childOf($this->parentGroup)
            ->create();

        $childGroup->moveToParent($newParent->id);

        $this->assertEquals($newParent->id, $childGroup->parent_id);
    }

    public function test_get_full_path_returns_hierarchical_path(): void
    {
        $rootGroup = ApplicationGroup::factory()
            ->forOrganization($this->organization)
            ->create(['name' => 'Root', 'parent_id' => null]);

        $childGroup = ApplicationGroup::factory()
            ->childOf($rootGroup)
            ->create(['name' => 'Child']);

        $grandchildGroup = ApplicationGroup::factory()
            ->childOf($childGroup)
            ->create(['name' => 'Grandchild']);

        $path = $grandchildGroup->getFullPath();

        $this->assertEquals('Root > Child > Grandchild', $path);
    }

    public function test_settings_are_cast_to_array(): void
    {
        $settings = [
            'inheritance_enabled' => true,
            'auto_assign_users' => false,
            'default_permissions' => ['read'],
        ];

        $group = ApplicationGroup::factory()
            ->forOrganization($this->organization)
            ->create(['settings' => $settings]);

        $this->assertIsArray($group->settings);
        $this->assertEquals($settings, $group->settings);
    }

    public function test_group_has_correct_fillable_attributes(): void
    {
        $fillable = [
            'name', 'description', 'organization_id', 'parent_id',
            'is_active', 'settings',
        ];

        $group = new ApplicationGroup;

        $this->assertEquals($fillable, $group->getFillable());
    }

    public function test_get_application_count_returns_direct_application_count(): void
    {
        $app1 = Application::factory()->forOrganization($this->organization)->create();
        $app2 = Application::factory()->forOrganization($this->organization)->create();

        $this->parentGroup->applications()->attach([$app1->id, $app2->id]);

        $this->assertEquals(2, $this->parentGroup->getApplicationCount());
    }

    public function test_get_total_application_count_includes_descendants(): void
    {
        // Add applications to parent group
        $parentApp = Application::factory()->forOrganization($this->organization)->create();
        $this->parentGroup->applications()->attach($parentApp->id);

        // Create child group with applications
        $childGroup = ApplicationGroup::factory()
            ->childOf($this->parentGroup)
            ->create();

        $childApp1 = Application::factory()->forOrganization($this->organization)->create();
        $childApp2 = Application::factory()->forOrganization($this->organization)->create();
        $childGroup->applications()->attach([$childApp1->id, $childApp2->id]);

        $totalCount = $this->parentGroup->getTotalApplicationCount();

        $this->assertEquals(3, $totalCount); // 1 parent + 2 child applications
    }
}
