<?php

namespace Tests\Browser\Admin;

use App\Models\Organization;
use Illuminate\Foundation\Testing\DatabaseMigrations;
use Laravel\Dusk\Browser;
use Tests\Browser\Components\FilamentResourceTable;
use Tests\Browser\Helpers\BrowserTestHelpers;
use Tests\DuskTestCase;

class OrganizationManagementTest extends DuskTestCase
{
    use BrowserTestHelpers;
    use DatabaseMigrations;

    /**
     * Test admin can view organizations list.
     */
    public function test_admin_can_view_organizations_list(): void
    {
        $admin = $this->createAdminUser();
        Organization::factory()->create(['name' => 'Test Organization']);

        $this->browse(function (Browser $browser) use ($admin) {
            $this->loginToFilamentAs($browser, $admin);

            $browser->visit('/admin/organizations')
                ->within(new FilamentResourceTable, function (Browser $table) {
                    $table->assertHasRecords();
                })
                ->assertSee('Test Organization');
        });
    }

    /**
     * Test admin can create new organization.
     */
    public function test_admin_can_create_new_organization(): void
    {
        $admin = $this->createAdminUser();

        $this->browse(function (Browser $browser) use ($admin) {
            $this->loginToFilamentAs($browser, $admin);

            $browser->visit('/admin/organizations')
                ->click('button[data-action="create"], button:contains("New")')
                ->pause(500)
                ->type('input[wire\\:model="data.name"]', 'New Organization')
                ->type('input[wire\\:model="data.slug"]', 'new-organization')
                ->click('button[type="submit"]')
                ->pause(1000);

            $this->assertDatabaseHas('organizations', [
                'name' => 'New Organization',
                'slug' => 'new-organization',
            ]);
        });
    }

    /**
     * Test admin can search organizations.
     */
    public function test_admin_can_search_organizations(): void
    {
        $admin = $this->createAdminUser();
        $org = Organization::factory()->create([
            'name' => 'Searchable Org',
        ]);

        $this->browse(function (Browser $browser) use ($admin, $org) {
            $this->loginToFilamentAs($browser, $admin);

            $browser->visit('/admin/organizations')
                ->within(new FilamentResourceTable, function (Browser $table) use ($org) {
                    $table->search($org->name);
                })
                ->assertSee($org->name);
        });
    }

    /**
     * Test admin can edit organization.
     */
    public function test_admin_can_edit_organization(): void
    {
        $admin = $this->createAdminUser();
        $org = Organization::factory()->create();

        $this->browse(function (Browser $browser) use ($admin, $org) {
            $this->loginToFilamentAs($browser, $admin);

            $browser->visit('/admin/organizations')
                ->pause(500)
                ->within(new FilamentResourceTable, function (Browser $table) {
                    $table->clickRowAction('Edit', 1);
                })
                ->pause(500)
                ->type('input[wire\\:model="data.name"]', 'Updated Organization')
                ->click('button[type="submit"]')
                ->pause(1000);

            $this->assertDatabaseHas('organizations', [
                'id' => $org->id,
                'name' => 'Updated Organization',
            ]);
        });
    }
}
