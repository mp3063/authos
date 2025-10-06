<?php

namespace Tests\Browser\Admin;

use Illuminate\Foundation\Testing\DatabaseMigrations;
use Laravel\Dusk\Browser;
use Tests\Browser\Components\FilamentResourceTable;
use Tests\Browser\Helpers\BrowserTestHelpers;
use Tests\DuskTestCase;

class UserManagementTest extends DuskTestCase
{
    use BrowserTestHelpers, DatabaseMigrations;

    /**
     * Test admin can view users list.
     */
    public function test_admin_can_view_users_list(): void
    {
        $admin = $this->createAdminUser();
        $this->createTestUser(); // Create a test user to display

        $this->browse(function (Browser $browser) use ($admin) {
            $this->loginToFilamentAs($browser, $admin);

            $browser->visit('/admin/users')
                ->within(new FilamentResourceTable, function (Browser $table) {
                    $table->assertHasRecords();
                })
                ->pause(500);
        });
    }

    /**
     * Test admin can create new user.
     */
    public function test_admin_can_create_new_user(): void
    {
        $admin = $this->createAdminUser();

        $this->browse(function (Browser $browser) use ($admin) {
            $this->loginToFilamentAs($browser, $admin);

            $browser->visit('/admin/users')
                ->click('button[data-action="create"], button:contains("New")')
                ->pause(500)
                ->type('input[wire\\:model="data.name"]', 'Test User')
                ->type('input[wire\\:model="data.email"]', 'newuser@example.com')
                ->type('input[wire\\:model="data.password"]', 'SecurePassword123!')
                ->click('button[type="submit"]')
                ->pause(1000);

            $this->assertDatabaseHas('users', [
                'email' => 'newuser@example.com',
                'name' => 'Test User',
            ]);
        });
    }

    /**
     * Test admin can search users.
     */
    public function test_admin_can_search_users(): void
    {
        $admin = $this->createAdminUser();
        $user = $this->createTestUser([
            'name' => 'Searchable User',
            'email' => 'searchable@example.com',
        ]);

        $this->browse(function (Browser $browser) use ($admin, $user) {
            $this->loginToFilamentAs($browser, $admin);

            $browser->visit('/admin/users')
                ->within(new FilamentResourceTable, function (Browser $table) use ($user) {
                    $table->search($user->email);
                    $table->assertHasRecords();
                })
                ->assertSee($user->email);
        });
    }

    /**
     * Test admin can edit user.
     */
    public function test_admin_can_edit_user(): void
    {
        $admin = $this->createAdminUser();
        $user = $this->createTestUser();

        $this->browse(function (Browser $browser) use ($admin, $user) {
            $this->loginToFilamentAs($browser, $admin);

            $browser->visit('/admin/users')
                ->pause(500)
                ->within(new FilamentResourceTable, function (Browser $table) {
                    $table->clickRowAction('Edit', 1);
                })
                ->pause(500)
                ->type('input[wire\\:model="data.name"]', 'Updated Name')
                ->click('button[type="submit"]')
                ->pause(1000);

            $this->assertDatabaseHas('users', [
                'id' => $user->id,
                'name' => 'Updated Name',
            ]);
        });
    }

    /**
     * Test admin can delete user.
     */
    public function test_admin_can_delete_user(): void
    {
        $admin = $this->createAdminUser();
        $user = $this->createTestUser();

        $this->browse(function (Browser $browser) use ($admin, $user) {
            $this->loginToFilamentAs($browser, $admin);

            $browser->visit('/admin/users')
                ->pause(500)
                ->within(new FilamentResourceTable, function (Browser $table) {
                    $table->clickRowAction('Delete', 1);
                })
                ->pause(300)
                ->click('button:contains("Confirm")')
                ->pause(1000);

            $this->assertSoftDeleted('users', [
                'id' => $user->id,
            ]);
        });
    }
}
