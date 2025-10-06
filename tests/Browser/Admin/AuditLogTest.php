<?php

namespace Tests\Browser\Admin;

use App\Models\AuthenticationLog;
use Illuminate\Foundation\Testing\DatabaseMigrations;
use Laravel\Dusk\Browser;
use Tests\Browser\Components\FilamentResourceTable;
use Tests\Browser\Helpers\BrowserTestHelpers;
use Tests\DuskTestCase;

class AuditLogTest extends DuskTestCase
{
    use BrowserTestHelpers;
    use DatabaseMigrations;

    /**
     * Test admin can view authentication logs.
     */
    public function test_admin_can_view_authentication_logs(): void
    {
        $admin = $this->createAdminUser();
        $user = $this->createTestUser();

        AuthenticationLog::factory()->create([
            'user_id' => $user->id,
            'ip_address' => '192.168.1.1',
            'user_agent' => 'Mozilla/5.0',
            'action' => 'login',
        ]);

        $this->browse(function (Browser $browser) use ($admin, $user) {
            $this->loginToFilamentAs($browser, $admin);

            $browser->visit('/admin/authentication-logs')
                ->within(new FilamentResourceTable, function (Browser $table) {
                    $table->assertHasRecords();
                })
                ->assertSee($user->email)
                ->assertSee('login');
        });
    }

    /**
     * Test admin can filter authentication logs.
     */
    public function test_admin_can_filter_authentication_logs(): void
    {
        $admin = $this->createAdminUser();
        $user = $this->createTestUser();

        AuthenticationLog::factory()->create([
            'user_id' => $user->id,
            'action' => 'login',
        ]);

        AuthenticationLog::factory()->create([
            'user_id' => $user->id,
            'action' => 'logout',
        ]);

        $this->browse(function (Browser $browser) use ($admin) {
            $this->loginToFilamentAs($browser, $admin);

            $browser->visit('/admin/authentication-logs')
                ->click('button[data-filter]')
                ->pause(200)
                ->click('input[value="login"]')
                ->pause(500)
                ->assertSee('login')
                ->assertDontSee('logout');
        });
    }

    /**
     * Test admin can export audit logs.
     */
    public function test_admin_can_export_audit_logs(): void
    {
        $admin = $this->createAdminUser();

        AuthenticationLog::factory()->count(5)->create();

        $this->browse(function (Browser $browser) use ($admin) {
            $this->loginToFilamentAs($browser, $admin);

            $browser->visit('/admin/authentication-logs')
                ->click('button:contains("Export")')
                ->pause(300)
                ->click('button:contains("CSV")')
                ->pause(1000);

            // File should be downloaded
        });
    }
}
