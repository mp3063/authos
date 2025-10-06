<?php

namespace Tests\Browser\MultiTenant;

use App\Models\Organization;
use Illuminate\Foundation\Testing\DatabaseMigrations;
use Laravel\Dusk\Browser;
use Tests\Browser\Helpers\BrowserTestHelpers;
use Tests\DuskTestCase;

class OrganizationIsolationTest extends DuskTestCase
{
    use BrowserTestHelpers;
    use DatabaseMigrations;

    /**
     * Test users can only see their organization's data.
     */
    public function test_users_can_only_see_their_organization_data(): void
    {
        $org1 = Organization::factory()->create(['name' => 'Organization 1']);
        $org2 = Organization::factory()->create(['name' => 'Organization 2']);

        $user1 = $this->createTestUser();
        $user1->organizations()->attach($org1->id);

        $user2 = $this->createTestUser();
        $user2->organizations()->attach($org2->id);

        $this->browse(function (Browser $browser) use ($user1, $org1, $org2) {
            $this->loginToFilamentAs($browser, $user1);

            $browser->visit('/admin/organizations')
                ->pause(500)
                ->assertSee($org1->name)
                ->assertDontSee($org2->name);
        });
    }

    /**
     * Test super admin can see all organizations.
     */
    public function test_super_admin_can_see_all_organizations(): void
    {
        $org1 = Organization::factory()->create(['name' => 'Organization 1']);
        $org2 = Organization::factory()->create(['name' => 'Organization 2']);

        $admin = $this->createAdminUser();

        $this->browse(function (Browser $browser) use ($admin, $org1, $org2) {
            $this->loginToFilamentAs($browser, $admin);

            $browser->visit('/admin/organizations')
                ->pause(500)
                ->assertSee($org1->name)
                ->assertSee($org2->name);
        });
    }

    /**
     * Test organization switching.
     */
    public function test_organization_switching(): void
    {
        $org1 = Organization::factory()->create(['name' => 'Organization 1']);
        $org2 = Organization::factory()->create(['name' => 'Organization 2']);

        $user = $this->createTestUser();
        $user->organizations()->attach([$org1->id, $org2->id]);

        $this->browse(function (Browser $browser) use ($user, $org1, $org2) {
            $this->loginAs($browser, $user);

            $browser->visit('/dashboard')
                ->assertSee($org1->name);

            // Switch to org2
            $browser->click('button[data-org-switcher]')
                ->pause(200)
                ->click("button[data-org-id=\"{$org2->id}\"]")
                ->pause(500)
                ->assertSee($org2->name);
        });
    }

    /**
     * Test cross-organization data access is prevented.
     */
    public function test_cross_organization_data_access_is_prevented(): void
    {
        $org1 = Organization::factory()->create();
        $org2 = Organization::factory()->create();

        $user1 = $this->createTestUser();
        $user1->organizations()->attach($org1->id);

        $user2 = $this->createTestUser();
        $user2->organizations()->attach($org2->id);

        $this->browse(function (Browser $browser) use ($user1, $user2) {
            $this->loginToFilamentAs($browser, $user1);

            // Try to access user2's profile (should be denied)
            $browser->visit("/admin/users/{$user2->id}")
                ->pause(500)
                ->assertSee('403'); // Forbidden
        });
    }
}
