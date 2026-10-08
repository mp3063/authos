<?php

namespace Tests\Feature\Filament;

use App\Filament\Resources\ApplicationResource;
use App\Filament\Resources\Invitations\Pages\ListInvitations;
use App\Filament\Resources\RoleResource\Pages\EditRole;
use App\Filament\Resources\RoleResource\RelationManagers\UsersRelationManager;
use App\Filament\Resources\SecurityIncidentResource;
use App\Filament\Resources\SecurityIncidentResource\Pages\ListSecurityIncidents;
use App\Filament\Resources\SocialAccounts\Pages\ListSocialAccounts;
use App\Filament\Resources\UserResource;
use App\Filament\Resources\WebhookResource;
use App\Models\Application;
use App\Models\Invitation;
use App\Models\Role;
use App\Models\SecurityIncident;
use App\Models\SocialAccount;
use App\Models\User;
use App\Models\Webhook;
use Filament\Facades\Filament;
use Livewire\Livewire;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use Tests\Integration\IntegrationTestCase;

class OrganizationScopingTest extends IntegrationTestCase
{
    /**
     * @return array<string, array{class-string, class-string}>
     */
    public static function organizationScopedResources(): array
    {
        return [
            'users' => [UserResource::class, User::class],
            'applications' => [ApplicationResource::class, Application::class],
            'webhooks' => [WebhookResource::class, Webhook::class],
        ];
    }

    /**
     * @param  class-string  $resource
     * @param  class-string  $model
     */
    #[Test]
    #[DataProvider('organizationScopedResources')]
    public function it_shows_no_rows_to_a_non_super_admin_without_an_organization(string $resource, string $model): void
    {
        $model::factory()->create();
        $user = $this->createUser([], 'Organization Owner', 'web');
        $user->update(['organization_id' => null]);
        $this->actingAs($user);
        Filament::setCurrentPanel(Filament::getPanel('admin'));

        $this->assertGreaterThan(0, $model::count());
        $this->assertSame(0, $resource::getEloquentQuery()->count());
    }

    #[Test]
    public function it_keeps_a_super_admin_with_an_organization_unscoped(): void
    {
        User::factory()->create();
        $superAdmin = $this->createSuperAdmin();
        $this->actingAs($superAdmin);
        Filament::setCurrentPanel(Filament::getPanel('admin'));

        $this->assertSame(User::count(), UserResource::getEloquentQuery()->count());
    }

    #[Test]
    public function it_lists_only_own_organization_invitations(): void
    {
        $owner = $this->createUser([], 'Organization Owner', 'web');
        $own = Invitation::factory()->create(['organization_id' => $owner->organization_id]);
        $foreign = Invitation::factory()->create();
        $this->actingAs($owner);

        Livewire::test(ListInvitations::class)
            ->assertCanSeeTableRecords([$own])
            ->assertCanNotSeeTableRecords([$foreign]);
    }

    #[Test]
    public function it_lists_only_own_organization_social_accounts(): void
    {
        $owner = $this->createUser([], 'Organization Owner', 'web');
        $own = SocialAccount::factory()->create(['user_id' => $owner->id]);
        $foreign = SocialAccount::factory()->create();
        $this->actingAs($owner);

        Livewire::test(ListSocialAccounts::class)
            ->assertCanSeeTableRecords([$own])
            ->assertCanNotSeeTableRecords([$foreign]);
    }

    #[Test]
    public function it_lists_only_own_organization_holders_of_a_global_role(): void
    {
        $owner = $this->createUser([], 'Organization Owner', 'web');
        $foreignMember = User::factory()->create();
        $globalRole = Role::create(['name' => 'Shared Role', 'guard_name' => 'web']);
        $owner->assignRole($globalRole);
        $foreignMember->assignRole($globalRole);
        $this->actingAs($owner);

        Livewire::test(UsersRelationManager::class, ['ownerRecord' => $globalRole, 'pageClass' => EditRole::class])
            ->assertCanSeeTableRecords([$owner])
            ->assertCanNotSeeTableRecords([$foreignMember]);
    }

    #[Test]
    public function it_lists_security_incidents_by_own_organization_or_own_organization_user(): void
    {
        $owner = $this->createUser([], 'Organization Owner', 'web');
        $ownUser = User::factory()->create(['organization_id' => $owner->organization_id]);
        $foreignUser = User::factory()->create();
        $own = SecurityIncident::factory()->create(['organization_id' => $owner->organization_id, 'user_id' => null]);
        $fallback = SecurityIncident::factory()->create(['organization_id' => null, 'user_id' => $ownUser->id]);
        $foreign = SecurityIncident::factory()->create(['organization_id' => $foreignUser->organization_id, 'user_id' => $ownUser->id]);
        $this->actingAs($owner);

        Livewire::test(ListSecurityIncidents::class)
            ->assertCanSeeTableRecords([$own, $fallback])
            ->assertCanNotSeeTableRecords([$foreign]);
    }

    #[Test]
    public function it_excludes_other_organizations_from_navigation_badges(): void
    {
        $owner = $this->createUser([], 'Organization Owner', 'web');
        $foreignUser = User::factory()->create();
        SecurityIncident::factory()->count(3)->create([
            'organization_id' => $foreignUser->organization_id,
            'user_id' => $foreignUser->id,
            'status' => 'open',
            'severity' => 'critical',
            'detected_at' => now(),
        ]);
        $this->actingAs($owner);
        Filament::setCurrentPanel(Filament::getPanel('admin'));

        $this->assertNull(SecurityIncidentResource::getNavigationBadge());
        $this->assertSame('primary', SecurityIncidentResource::getNavigationBadgeColor());
    }
}
