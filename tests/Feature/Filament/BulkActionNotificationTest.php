<?php

namespace Tests\Feature\Filament;

use App\Filament\Resources\ApplicationGroupResource\Pages\ListApplicationGroups;
use App\Filament\Resources\CustomRoleResource\Pages\ListCustomRoles;
use App\Filament\Resources\IpBlocklistResource\Pages\ListIpBlocklist;
use App\Filament\Resources\PermissionResource\Pages\ListPermissions;
use App\Filament\Resources\RoleResource\Pages\ListRoles;
use App\Filament\Resources\WebhookResource\Pages\ListWebhooks;
use App\Models\ApplicationGroup;
use App\Models\CustomRole;
use App\Models\IpBlocklist;
use App\Models\Organization;
use App\Models\Permission;
use App\Models\Role;
use App\Models\Webhook;
use Filament\Notifications\Livewire\Notifications;
use Filament\Notifications\Notification;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Facades\Gate;
use Livewire\Livewire;
use PHPUnit\Framework\Attributes\Test;
use Tests\Feature\Filament\Concerns\CallsHiddenActions;
use Tests\Integration\IntegrationTestCase;

class BulkActionNotificationTest extends IntegrationTestCase
{
    use CallsHiddenActions;

    private Organization $organization;

    protected function setUp(): void
    {
        parent::setUp();

        $this->organization = $this->createOrganization();
    }

    private function actingAsOwner(): void
    {
        $this->actingAs($this->createUser(['organization_id' => $this->organization->id], 'Organization Owner'));
    }

    private function refuseUpdateOf(Model $refused): void
    {
        Gate::before(fn ($user, string $ability, array $arguments): ?bool => $ability === 'update' && ($arguments[0] ?? null)?->is($refused) ? false : null);
    }

    /**
     * @return list<string>
     */
    private function notificationTitles(): array
    {
        $notifications = new Notifications;
        $notifications->mount();

        return $notifications->notifications
            ->map(fn (Notification $notification): ?string => $notification->getTitle())
            ->values()
            ->all();
    }

    #[Test]
    public function it_reports_a_partial_result_when_some_groups_are_refused(): void
    {
        $this->actingAsOwner();
        $own = ApplicationGroup::factory()->create(['organization_id' => $this->organization->id, 'is_active' => false]);
        $refused = ApplicationGroup::factory()->create(['organization_id' => $this->organization->id, 'is_active' => false]);
        $this->refuseUpdateOf($refused);

        $list = Livewire::test(ListApplicationGroups::class);
        $this->forceTableBulkAction($list, 'activate', [$own, $refused]);

        $this->assertTrue($own->fresh()->is_active);
        $this->assertFalse($refused->fresh()->is_active);
        $this->assertSame(['1 of 2 groups activated'], $this->notificationTitles());
    }

    #[Test]
    public function it_reports_a_partial_result_when_some_webhooks_are_refused(): void
    {
        $this->actingAsOwner();
        $own = Webhook::factory()->create(['organization_id' => $this->organization->id, 'is_active' => false]);
        $refused = Webhook::factory()->create(['organization_id' => $this->organization->id, 'is_active' => false]);
        $this->refuseUpdateOf($refused);

        $list = Livewire::test(ListWebhooks::class);
        $this->forceTableBulkAction($list, 'enable', [$own, $refused]);

        $this->assertTrue($own->fresh()->is_active);
        $this->assertFalse($refused->fresh()->is_active);
        $this->assertSame(['1 of 2 webhooks enabled'], $this->notificationTitles());
    }

    #[Test]
    public function it_reports_a_partial_result_when_a_group_with_children_is_skipped_on_delete(): void
    {
        $this->actingAsOwner();
        $parent = ApplicationGroup::factory()->create(['organization_id' => $this->organization->id]);
        ApplicationGroup::factory()->childOf($parent)->create();
        $leaf = ApplicationGroup::factory()->create(['organization_id' => $this->organization->id]);

        Livewire::test(ListApplicationGroups::class)->callTableBulkAction('delete', [$parent, $leaf]);

        $this->assertNotNull(ApplicationGroup::find($parent->id));
        $this->assertNull(ApplicationGroup::find($leaf->id));
        $this->assertSame(['1 of 2 groups deleted'], $this->notificationTitles());
    }

    #[Test]
    public function it_reports_success_when_every_group_is_processed(): void
    {
        $this->actingAsOwner();
        $group = ApplicationGroup::factory()->create(['organization_id' => $this->organization->id, 'is_active' => false]);

        Livewire::test(ListApplicationGroups::class)->callTableBulkAction('activate', [$group]);

        $this->assertSame(['Groups activated successfully'], $this->notificationTitles());
    }

    #[Test]
    public function it_keeps_the_success_title_on_the_super_admin_only_bulk_actions(): void
    {
        $this->actingAs($this->createSuperAdmin());
        $customRole = CustomRole::factory()->forOrganization($this->organization)->create(['is_active' => false]);
        $block = IpBlocklist::factory()->create(['is_active' => false]);
        $role = Role::where('guard_name', 'web')->firstOrFail();
        $permission = Permission::where('guard_name', 'web')->firstOrFail();

        $titles = [];
        Livewire::test(ListCustomRoles::class)->callTableBulkAction('activate', [$customRole]);
        $titles = [...$titles, ...$this->notificationTitles()];
        Livewire::test(ListIpBlocklist::class)->callTableBulkAction('bulk_block', [$block]);
        $titles = [...$titles, ...$this->notificationTitles()];
        Livewire::test(ListRoles::class)->callTableBulkAction('assign_permission', [$role], ['permission' => $permission->id]);
        $titles = [...$titles, ...$this->notificationTitles()];
        Livewire::test(ListPermissions::class)->callTableBulkAction('assign_to_role', [$permission], ['role' => $role->id]);
        $titles = [...$titles, ...$this->notificationTitles()];

        $this->assertSame([
            'Roles activated successfully',
            'Selected IPs blocked successfully',
            'Permission assigned to selected roles',
            'Permissions assigned to role',
        ], $titles);
    }
}
