<?php

namespace Tests\Feature\Filament;

use App\Filament\Widgets\ApplicationAccessMatrix;
use App\Filament\Widgets\AuthStatsOverview;
use App\Filament\Widgets\ErrorTrendsWidget;
use App\Filament\Widgets\LoginActivityChart;
use App\Filament\Widgets\OAuthFlowMonitorWidget;
use App\Filament\Widgets\OrganizationOverviewWidget;
use App\Filament\Widgets\PendingInvitationsWidget;
use App\Filament\Widgets\RealTimeMetricsWidget;
use App\Filament\Widgets\RecentAuthenticationLogs;
use App\Filament\Widgets\SecurityMonitoringWidget;
use App\Filament\Widgets\SystemHealthWidget;
use App\Filament\Widgets\UserActivityWidget;
use App\Filament\Widgets\WebhookActivityChart;
use App\Models\Application;
use App\Models\AuthenticationLog;
use App\Models\CustomRole;
use App\Models\Invitation;
use App\Models\Organization;
use App\Models\User;
use App\Models\Webhook;
use App\Models\WebhookDelivery;
use Illuminate\Support\Facades\Cache;
use Livewire\Livewire;
use PHPUnit\Framework\Attributes\Test;
use Tests\Integration\IntegrationTestCase;

class DashboardWidgetAuthorizationTest extends IntegrationTestCase
{
    private Organization $organization;

    private Organization $otherOrganization;

    protected function setUp(): void
    {
        parent::setUp();

        Cache::flush();
        $this->organization = $this->createOrganization();
        $this->otherOrganization = $this->createOrganization();
    }

    private function member(string $role, ?Organization $organization = null): User
    {
        return $this->createUser(['organization_id' => ($organization ?? $this->organization)->id], $role, 'web');
    }

    private function withoutPermissions(): User
    {
        $user = $this->createUser(['organization_id' => $this->organization->id], '', 'web');
        CustomRole::factory()->forOrganization($this->organization)->create(['permissions' => ['profile.read']])->assignToUser($user);

        return $user;
    }

    private function widgetData(string $widget, string $method = 'getData'): array
    {
        $instance = new $widget;
        $reflection = new \ReflectionMethod($instance, $method);

        return $reflection->invoke($instance);
    }

    #[Test]
    public function it_shows_global_widgets_to_super_admins_only(): void
    {
        $widgets = [
            AuthStatsOverview::class,
            SystemHealthWidget::class,
            RealTimeMetricsWidget::class,
            SecurityMonitoringWidget::class,
            ErrorTrendsWidget::class,
            OAuthFlowMonitorWidget::class,
        ];

        foreach (['Organization Owner', 'Organization Admin', 'Auditor'] as $role) {
            $this->actingAs($this->member($role));

            foreach ($widgets as $widget) {
                $this->assertFalse($widget::canView(), "{$role} must not see {$widget}");
            }
        }

        $this->actingAs($this->createSuperAdmin());

        foreach ($widgets as $widget) {
            $this->assertTrue($widget::canView(), "Super admin must see {$widget}");
        }
    }

    #[Test]
    public function it_scopes_recent_authentication_logs_to_the_callers_organization(): void
    {
        $admin = $this->member('Organization Admin');
        $ownLog = AuthenticationLog::factory()->create(['user_id' => $admin->id]);
        $foreignLog = AuthenticationLog::factory()->create(['user_id' => $this->member('User', $this->otherOrganization)->id]);

        $this->actingAs($admin);

        $this->assertTrue(RecentAuthenticationLogs::canView());
        Livewire::test(RecentAuthenticationLogs::class)
            ->assertCanSeeTableRecords([$ownLog])
            ->assertCanNotSeeTableRecords([$foreignLog]);

        $this->actingAs($this->member('Organization Member'));
        $this->assertFalse(RecentAuthenticationLogs::canView());
    }

    #[Test]
    public function it_scopes_the_login_activity_chart_to_the_callers_organization(): void
    {
        $admin = $this->member('Organization Admin');
        AuthenticationLog::factory()->create(['user_id' => $admin->id, 'event' => 'login_success', 'created_at' => now()]);
        AuthenticationLog::factory()->count(3)->create([
            'user_id' => $this->member('User', $this->otherOrganization)->id,
            'event' => 'login_success',
            'created_at' => now(),
        ]);

        $this->actingAs($admin);

        $this->assertTrue(LoginActivityChart::canView());
        $this->assertSame(1, $this->widgetData(LoginActivityChart::class)['datasets'][0]['data'][6]);

        $this->actingAs($this->member('Organization Member'));
        $this->assertFalse(LoginActivityChart::canView());
    }

    #[Test]
    public function it_scopes_the_webhook_activity_chart_to_the_callers_organization(): void
    {
        $admin = $this->member('Organization Admin');
        WebhookDelivery::factory()->create(['webhook_id' => Webhook::factory()->create(['organization_id' => $this->organization->id])->id]);
        WebhookDelivery::factory()->count(2)->create(['webhook_id' => Webhook::factory()->create(['organization_id' => $this->otherOrganization->id])->id]);

        $this->actingAs($admin);

        $this->assertTrue(WebhookActivityChart::canView());
        $this->assertSame(1, $this->widgetData(WebhookActivityChart::class)['datasets'][0]['data'][6]);

        $this->actingAs($this->member('Auditor'));
        $this->assertFalse(WebhookActivityChart::canView());

        $this->actingAs($this->createSuperAdmin());
        $this->assertSame(3, $this->widgetData(WebhookActivityChart::class)['datasets'][0]['data'][6]);
    }

    #[Test]
    public function it_scopes_user_activity_to_the_callers_organization(): void
    {
        $admin = $this->member('Organization Admin');
        $ownLog = AuthenticationLog::factory()->create(['user_id' => $admin->id]);
        $foreignLog = AuthenticationLog::factory()->create(['user_id' => $this->member('User', $this->otherOrganization)->id]);

        $this->actingAs($admin);

        $this->assertTrue(UserActivityWidget::canView());
        Livewire::test(UserActivityWidget::class)
            ->assertCanSeeTableRecords([$ownLog])
            ->assertCanNotSeeTableRecords([$foreignLog]);

        $this->actingAs($this->withoutPermissions());
        $this->assertFalse(UserActivityWidget::canView());
    }

    #[Test]
    public function it_scopes_the_organization_overview_to_the_callers_organization(): void
    {
        Application::factory()->count(2)->create(['organization_id' => $this->organization->id]);
        Application::factory()->count(5)->create(['organization_id' => $this->otherOrganization->id]);

        $this->actingAs($this->member('Organization Admin'));

        $this->assertTrue(OrganizationOverviewWidget::canView());
        $stats = collect($this->widgetData(OrganizationOverviewWidget::class, 'getStats'));
        $this->assertSame(2, $stats->first(fn ($stat) => $stat->getLabel() === 'Applications')->getValue());

        $this->actingAs($this->withoutPermissions());
        $this->assertFalse(OrganizationOverviewWidget::canView());
    }

    #[Test]
    public function it_scopes_pending_invitations_to_the_callers_organization(): void
    {
        $own = Invitation::factory()->forOrganization($this->organization)->create();
        $foreign = Invitation::factory()->forOrganization($this->otherOrganization)->create();

        $this->actingAs($this->member('Organization Admin'));

        $this->assertTrue(PendingInvitationsWidget::canView());
        Livewire::test(PendingInvitationsWidget::class)
            ->assertCanSeeTableRecords([$own])
            ->assertCanNotSeeTableRecords([$foreign]);

        $this->actingAs($this->member('Auditor'));
        $this->assertFalse(PendingInvitationsWidget::canView());
    }

    #[Test]
    public function it_refuses_to_mount_the_invitations_widget_without_users_create(): void
    {
        $invitation = Invitation::factory()->forOrganization($this->organization)->create();

        $this->actingAs($this->member('Auditor'));

        Livewire::test(PendingInvitationsWidget::class)->assertForbidden();

        $this->assertDatabaseHas('invitations', ['id' => $invitation->id]);
    }

    #[Test]
    public function it_scopes_the_access_matrix_to_the_callers_organization(): void
    {
        $own = Application::factory()->create(['organization_id' => $this->organization->id, 'is_active' => true]);
        $foreign = Application::factory()->create(['organization_id' => $this->otherOrganization->id, 'is_active' => true]);

        $this->actingAs($this->member('Organization Admin'));

        $this->assertTrue(ApplicationAccessMatrix::canView());
        $applications = (new ApplicationAccessMatrix)->getViewData()['applications'];
        $this->assertSame([$own->id], $applications->pluck('id')->all());

        $this->actingAs($this->member('Organization Admin', $this->otherOrganization));
        $applications = (new ApplicationAccessMatrix)->getViewData()['applications'];
        $this->assertSame([$foreign->id], $applications->pluck('id')->all());

        $this->actingAs($this->member('Auditor'));
        $this->assertFalse(ApplicationAccessMatrix::canView());
    }

    #[Test]
    public function it_refuses_access_grants_without_applications_update(): void
    {
        $application = Application::factory()->create(['organization_id' => $this->organization->id]);
        $target = $this->member('User');

        $this->actingAs($this->member('Auditor'));

        (new ApplicationAccessMatrix)->grantAccess($target->id, $application->id);

        $this->assertDatabaseMissing('user_applications', ['user_id' => $target->id, 'application_id' => $application->id]);
    }

    #[Test]
    public function it_grants_and_revokes_access_within_the_callers_organization_only(): void
    {
        $application = Application::factory()->create(['organization_id' => $this->organization->id]);
        $foreignApplication = Application::factory()->create(['organization_id' => $this->otherOrganization->id]);
        $target = $this->member('User');
        $foreignUser = $this->member('User', $this->otherOrganization);

        $this->actingAs($this->member('Organization Admin'));

        $component = Livewire::test(ApplicationAccessMatrix::class)
            ->call('grantAccess', $target->id, $application->id)
            ->call('grantAccess', $foreignUser->id, $application->id)
            ->call('grantAccess', $target->id, $foreignApplication->id);

        $this->assertDatabaseHas('user_applications', ['user_id' => $target->id, 'application_id' => $application->id]);
        $this->assertDatabaseMissing('user_applications', ['user_id' => $foreignUser->id]);
        $this->assertDatabaseMissing('user_applications', ['application_id' => $foreignApplication->id]);

        $component->call('revokeAccess', $target->id, $application->id);

        $this->assertDatabaseMissing('user_applications', ['user_id' => $target->id, 'application_id' => $application->id]);
    }

    #[Test]
    public function it_grants_widget_access_through_permissions_rather_than_role_names(): void
    {
        $application = Application::factory()->create(['organization_id' => $this->organization->id]);
        $target = $this->member('User');
        $manager = $this->createUser(['organization_id' => $this->organization->id], '', 'web');
        CustomRole::factory()->forOrganization($this->organization)->create(['permissions' => ['applications.update', 'users.create']])->assignToUser($manager);

        $this->actingAs($manager);

        $this->assertTrue(PendingInvitationsWidget::canView());
        $this->assertTrue(ApplicationAccessMatrix::canView());
        Livewire::test(ApplicationAccessMatrix::class)->call('grantAccess', $target->id, $application->id);
        $this->assertDatabaseHas('user_applications', ['user_id' => $target->id, 'application_id' => $application->id]);
    }
}
