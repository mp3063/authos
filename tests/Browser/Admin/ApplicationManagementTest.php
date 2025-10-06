<?php

namespace Tests\Browser\Admin;

use App\Models\Application;
use Illuminate\Foundation\Testing\DatabaseMigrations;
use Laravel\Dusk\Browser;
use Tests\Browser\Components\FilamentResourceTable;
use Tests\Browser\Helpers\BrowserTestHelpers;
use Tests\DuskTestCase;

class ApplicationManagementTest extends DuskTestCase
{
    use BrowserTestHelpers;
    use DatabaseMigrations;

    protected function setUp(): void
    {
        parent::setUp();
        $this->artisan('passport:keys');
        $this->artisan('passport:client', ['--personal' => true, '--name' => 'Test']);
    }

    /**
     * Test admin can view applications list.
     */
    public function test_admin_can_view_applications_list(): void
    {
        $admin = $this->createAdminUser();
        Application::factory()->create(['name' => 'Test Application']);

        $this->browse(function (Browser $browser) use ($admin) {
            $this->loginToFilamentAs($browser, $admin);

            $browser->visit('/admin/applications')
                ->within(new FilamentResourceTable, function (Browser $table) {
                    $table->assertHasRecords();
                })
                ->assertSee('Test Application');
        });
    }

    /**
     * Test admin can create new OAuth application.
     */
    public function test_admin_can_create_new_oauth_application(): void
    {
        $admin = $this->createAdminUser();

        $this->browse(function (Browser $browser) use ($admin) {
            $this->loginToFilamentAs($browser, $admin);

            $browser->visit('/admin/applications')
                ->click('button[data-action="create"], button:contains("New")')
                ->pause(500)
                ->type('input[wire\\:model="data.name"]', 'New OAuth App')
                ->type('input[wire\\:model="data.redirect_uri"]', 'http://localhost:3000/callback')
                ->click('button[type="submit"]')
                ->pause(1000);

            $this->assertDatabaseHas('applications', [
                'name' => 'New OAuth App',
            ]);
        });
    }

    /**
     * Test admin can view application credentials.
     */
    public function test_admin_can_view_application_credentials(): void
    {
        $admin = $this->createAdminUser();
        $app = Application::factory()->create();

        $this->browse(function (Browser $browser) use ($admin) {
            $this->loginToFilamentAs($browser, $admin);

            $browser->visit('/admin/applications')
                ->pause(500)
                ->within(new FilamentResourceTable, function (Browser $table) {
                    $table->clickRowAction('View', 1);
                })
                ->pause(500)
                ->assertSee('Client ID')
                ->assertSee('Client Secret');
        });
    }

    /**
     * Test admin can regenerate application credentials.
     */
    public function test_admin_can_regenerate_application_credentials(): void
    {
        $admin = $this->createAdminUser();
        $app = Application::factory()->create();
        $oldSecret = $app->client_secret;

        $this->browse(function (Browser $browser) use ($admin, $app, $oldSecret) {
            $this->loginToFilamentAs($browser, $admin);

            $browser->visit("/admin/applications/{$app->id}/edit")
                ->pause(500)
                ->click('button:contains("Regenerate Secret")')
                ->pause(300)
                ->click('button:contains("Confirm")')
                ->pause(1000);

            $app->refresh();
            $this->assertNotEquals($oldSecret, $app->client_secret);
        });
    }

    /**
     * Test admin can edit application.
     */
    public function test_admin_can_edit_application(): void
    {
        $admin = $this->createAdminUser();
        $app = Application::factory()->create();

        $this->browse(function (Browser $browser) use ($admin, $app) {
            $this->loginToFilamentAs($browser, $admin);

            $browser->visit('/admin/applications')
                ->pause(500)
                ->within(new FilamentResourceTable, function (Browser $table) {
                    $table->clickRowAction('Edit', 1);
                })
                ->pause(500)
                ->type('input[wire\\:model="data.name"]', 'Updated Application')
                ->click('button[type="submit"]')
                ->pause(1000);

            $this->assertDatabaseHas('applications', [
                'id' => $app->id,
                'name' => 'Updated Application',
            ]);
        });
    }

    /**
     * Test admin can delete application.
     */
    public function test_admin_can_delete_application(): void
    {
        $admin = $this->createAdminUser();
        $app = Application::factory()->create();

        $this->browse(function (Browser $browser) use ($admin, $app) {
            $this->loginToFilamentAs($browser, $admin);

            $browser->visit('/admin/applications')
                ->pause(500)
                ->within(new FilamentResourceTable, function (Browser $table) {
                    $table->clickRowAction('Delete', 1);
                })
                ->pause(300)
                ->click('button:contains("Confirm")')
                ->pause(1000);

            $this->assertSoftDeleted('applications', [
                'id' => $app->id,
            ]);
        });
    }
}
