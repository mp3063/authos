<?php

namespace Tests\Feature\Filament;

use App\Filament\Resources\AccountLockoutResource\Pages\ListAccountLockouts;
use App\Filament\Resources\AccountLockoutResource\Pages\ViewAccountLockout;
use App\Filament\Resources\AuthenticationLogResource\Pages\ListAuthenticationLogs;
use App\Filament\Resources\FailedLoginAttemptResource\Pages\ListFailedLoginAttempts;
use App\Filament\Resources\IpBlocklistResource\Pages\ListIpBlocklist;
use App\Filament\Resources\SecurityIncidentResource\Pages\ListSecurityIncidents;
use App\Models\AccountLockout;
use App\Models\AuthenticationLog;
use App\Models\FailedLoginAttempt;
use App\Models\IpBlocklist;
use App\Models\Organization;
use App\Models\SecurityIncident;
use App\Models\User;
use Livewire\Livewire;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use Tests\Feature\Filament\Concerns\CallsHiddenActions;
use Tests\Integration\IntegrationTestCase;

class SecurityActionAuthorizationTest extends IntegrationTestCase
{
    use CallsHiddenActions;

    private Organization $organization;

    protected function setUp(): void
    {
        parent::setUp();

        $this->organization = $this->createOrganization();
    }

    private function actingAsRole(string $role): User
    {
        $user = $this->createUser(['organization_id' => $this->organization->id], $role);
        $this->actingAs($user);

        return $user;
    }

    private function incident(): SecurityIncident
    {
        return SecurityIncident::factory()->create(['organization_id' => $this->organization->id, 'status' => 'open']);
    }

    private function lockout(): AccountLockout
    {
        $member = User::factory()->create(['organization_id' => $this->organization->id]);

        return AccountLockout::factory()->active()->create(['user_id' => $member->id]);
    }

    /**
     * @return array<string, array{0: string}>
     */
    public static function rolesWithoutResolveOrUnlock(): array
    {
        return [
            'auditor' => ['Auditor'],
            'custom role' => ['custom'],
        ];
    }

    private function actingAsReadOnly(string $kind): void
    {
        if ($kind === 'custom') {
            $this->actingAs($this->createUserWithCustomPermissions($this->organization, ['admin.access', 'auth_logs.read']));

            return;
        }

        $this->actingAsRole($kind);
    }

    #[Test]
    #[DataProvider('rolesWithoutResolveOrUnlock')]
    public function it_hides_and_forbids_resolve_and_dismiss_for_a_role_without_the_permission(string $kind): void
    {
        $this->actingAsReadOnly($kind);
        $incident = $this->incident();

        $list = Livewire::test(ListSecurityIncidents::class)->assertCanSeeTableRecords([$incident]);
        $this->forceTableBulkAction($list, 'resolve', [$incident]);
        $this->forceTableBulkAction($list, 'dismiss', [$incident]);

        $this->assertSame('open', $incident->fresh()->status);
        $this->assertNull($incident->fresh()->resolved_at);
    }

    #[Test]
    public function an_owner_can_resolve_and_dismiss_incidents(): void
    {
        $this->actingAsRole('Organization Owner');
        $resolved = $this->incident();
        $dismissed = $this->incident();

        $list = Livewire::test(ListSecurityIncidents::class);
        $this->forceTableBulkAction($list, 'resolve', [$resolved]);
        $this->forceTableBulkAction($list, 'dismiss', [$dismissed]);

        $this->assertSame('resolved', $resolved->fresh()->status);
        $this->assertSame('dismissed', $dismissed->fresh()->status);
    }

    #[Test]
    #[DataProvider('rolesWithoutResolveOrUnlock')]
    public function it_hides_and_forbids_unlock_for_a_role_without_the_permission(string $kind): void
    {
        $this->actingAsReadOnly($kind);
        $lockout = $this->lockout();

        $list = Livewire::test(ListAccountLockouts::class)
            ->assertTableActionHidden('unlock', $lockout)
            ->assertTableBulkActionHidden('delete');
        $this->forceTableAction($list, 'unlock', $lockout);
        $this->forceTableBulkAction($list, 'bulk_unlock', [$lockout]);
        $this->forceTableBulkAction($list, 'delete', [$lockout]);

        $view = Livewire::test(ViewAccountLockout::class, ['record' => $lockout->getRouteKey()])->assertActionHidden('unlock');
        $this->forcePageAction($view, 'unlock');

        $this->assertNull($lockout->fresh()->unlocked_at);
        $this->assertNotNull(AccountLockout::find($lockout->id));
    }

    #[Test]
    public function an_admin_can_unlock_accounts_but_not_delete_lockouts(): void
    {
        $this->actingAsRole('Organization Admin');
        $single = $this->lockout();
        $bulk = $this->lockout();

        $list = Livewire::test(ListAccountLockouts::class)
            ->assertTableActionVisible('unlock', $single)
            ->assertTableBulkActionHidden('delete')
            ->callTableAction('unlock', $single);
        $this->forceTableBulkAction($list, 'bulk_unlock', [$bulk]);
        $this->forceTableBulkAction($list, 'delete', [$bulk]);

        $this->assertNotNull($single->fresh()->unlocked_at);
        $this->assertNotNull($bulk->fresh()->unlocked_at);
        $this->assertNotNull(AccountLockout::find($bulk->id));
    }

    #[Test]
    public function an_owner_cannot_open_the_global_ip_blocklist_or_failed_login_pages(): void
    {
        $this->actingAsRole('Organization Owner');

        Livewire::test(ListIpBlocklist::class)->assertForbidden();
        Livewire::test(ListFailedLoginAttempts::class)->assertForbidden();
    }

    #[Test]
    public function a_super_admin_can_unblock_and_bulk_delete_ip_blocks(): void
    {
        $this->actingAs($this->createSuperAdmin());
        $block = IpBlocklist::factory()->create(['is_active' => true]);
        $other = IpBlocklist::factory()->create(['is_active' => true]);

        $list = Livewire::test(ListIpBlocklist::class)->callTableAction('unblock', $block);
        $this->forceTableBulkAction($list, 'delete', [$other]);

        $this->assertFalse($block->fresh()->is_active);
        $this->assertNull(IpBlocklist::find($other->id));
    }

    #[Test]
    #[DataProvider('rolesWithoutResolveOrUnlock')]
    public function it_hides_and_forbids_clearing_and_deleting_authentication_logs_for_a_non_super_admin(string $kind): void
    {
        $this->actingAsReadOnly($kind);
        $member = User::factory()->create(['organization_id' => $this->organization->id]);
        $log = AuthenticationLog::factory()->create(['user_id' => $member->id, 'created_at' => now()->subDays(200)]);

        $list = Livewire::test(ListAuthenticationLogs::class)
            ->assertActionHidden('clear_old_logs')
            ->assertTableBulkActionHidden('delete');
        $this->forcePageAction($list, 'clear_old_logs');
        $this->forceTableBulkAction($list, 'delete', [$log]);

        $this->assertNotNull(AuthenticationLog::find($log->id));
    }

    #[Test]
    public function an_owner_cannot_delete_authentication_logs_in_bulk(): void
    {
        $this->actingAsRole('Organization Owner');
        $member = User::factory()->create(['organization_id' => $this->organization->id]);
        $log = AuthenticationLog::factory()->create(['user_id' => $member->id, 'created_at' => now()->subDays(200)]);

        $list = Livewire::test(ListAuthenticationLogs::class)
            ->assertActionHidden('clear_old_logs')
            ->assertTableBulkActionHidden('delete');
        $this->forcePageAction($list, 'clear_old_logs');
        $this->forceTableBulkAction($list, 'delete', [$log]);

        $this->assertNotNull(AuthenticationLog::find($log->id));
    }

    #[Test]
    public function a_super_admin_can_clear_old_logs_and_failed_login_entries(): void
    {
        $this->actingAs($this->createSuperAdmin());
        $member = User::factory()->create(['organization_id' => $this->organization->id]);
        $log = AuthenticationLog::factory()->create(['user_id' => $member->id, 'created_at' => now()->subDays(200)]);
        $attempt = FailedLoginAttempt::factory()->create(['attempted_at' => now()->subDays(60)]);

        Livewire::test(ListAuthenticationLogs::class)->callAction('clear_old_logs');
        Livewire::test(ListFailedLoginAttempts::class)->callAction('clear_old_entries');

        $this->assertNull(AuthenticationLog::find($log->id));
        $this->assertNull(FailedLoginAttempt::find($attempt->id));
    }

    #[Test]
    public function it_offers_no_stub_export_actions(): void
    {
        $this->actingAs($this->createSuperAdmin());

        Livewire::test(ListAuthenticationLogs::class)
            ->assertActionDoesNotExist('export_logs')
            ->assertTableBulkActionDoesNotExist('export');
        Livewire::test(ListFailedLoginAttempts::class)
            ->assertActionDoesNotExist('export')
            ->assertTableBulkActionDoesNotExist('export');
    }
}
