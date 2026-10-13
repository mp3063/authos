<?php

namespace Tests\Integration\Organizations;

use App\Http\Middleware\EnforceOrganizationBoundary;
use App\Http\Middleware\SetPermissionContext;
use App\Models\Application;
use App\Models\AuditExport;
use App\Models\Invitation;
use App\Models\Organization;
use App\Models\OrganizationBranding;
use App\Models\User;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Http\Request;
use Illuminate\Http\Response;
use Illuminate\Support\Facades\Storage;
use Illuminate\Support\Facades\URL;
use Laravel\Passport\Passport;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use Spatie\Permission\PermissionRegistrar;
use Tests\TestCase;

class OrganizationEndpointsAuthorizationTest extends TestCase
{
    use RefreshDatabase;

    private Organization $organization;

    private Organization $foreign;

    protected function setUp(): void
    {
        parent::setUp();

        $this->organization = Organization::factory()->create();
        $this->foreign = Organization::factory()->create(['name' => 'Foreign Org']);
    }

    /**
     * @return array<string, array{0: string, 1: string, 2: array<string, mixed>}>
     */
    public static function foreignOrganizationRequests(): array
    {
        return [
            'show' => ['getJson', '', []],
            'update' => ['putJson', '', ['name' => 'Hijacked']],
            'settings' => ['getJson', '/settings', []],
            'update settings' => ['putJson', '/settings', ['require_mfa' => true]],
            'reset settings' => ['postJson', '/settings/reset', []],
            'users' => ['getJson', '/users', []],
            'applications' => ['getJson', '/applications', []],
            'analytics' => ['getJson', '/analytics', []],
            'user metrics' => ['getJson', '/metrics/users', []],
            'application metrics' => ['getJson', '/metrics/applications', []],
            'security metrics' => ['getJson', '/metrics/security', []],
            'export' => ['postJson', '/export', ['data_type' => 'applications']],
            'user activity report' => ['getJson', '/reports/user-activity', []],
            'application usage report' => ['getJson', '/reports/application-usage', []],
            'security audit report' => ['getJson', '/reports/security-audit', []],
        ];
    }

    /**
     * @param  array<string, mixed>  $payload
     */
    #[Test]
    #[DataProvider('foreignOrganizationRequests')]
    public function an_owner_cannot_reach_another_organization_without_the_boundary_middleware(string $method, string $suffix, array $payload): void
    {
        $this->withoutMiddleware(EnforceOrganizationBoundary::class);
        $owner = $this->createUser(['organization_id' => $this->organization->id], 'Organization Owner', 'api');
        Passport::actingAs($owner);

        $response = $this->{$method}("/api/v1/organizations/{$this->foreign->id}{$suffix}", $payload);

        $response->assertNotFound();
        $this->assertSame('Foreign Org', $this->foreign->fresh()->name);
    }

    #[Test]
    public function a_user_who_can_update_users_cannot_list_another_organizations_users(): void
    {
        $this->withoutMiddleware(EnforceOrganizationBoundary::class);
        $admin = $this->createUser(['organization_id' => $this->organization->id], 'Organization Admin', 'api');
        User::factory()->create(['organization_id' => $this->foreign->id]);
        Passport::actingAs($admin);

        $this->getJson("/api/v1/organizations/{$this->foreign->id}/users")->assertNotFound();
        $this->getJson("/api/v1/organizations/{$this->organization->id}/users")->assertOk();
    }

    #[Test]
    public function a_super_admin_still_reaches_any_organization(): void
    {
        $superAdmin = $this->createSuperAdmin();
        Passport::actingAs($superAdmin);

        $this->getJson("/api/v1/organizations/{$this->foreign->id}")->assertOk();
        $this->getJson("/api/v1/organizations/{$this->foreign->id}/users")->assertOk();
        $this->getJson("/api/v1/organizations/{$this->foreign->id}/settings")->assertOk();
    }

    #[Test]
    public function a_super_admin_sees_the_security_settings_of_any_organization(): void
    {
        $this->foreign->update(['settings' => ['security' => ['mfa' => 'required']]]);
        Passport::actingAs($this->createSuperAdmin());

        $response = $this->getJson("/api/v1/organizations/{$this->foreign->id}");

        $response->assertOk()->assertJsonPath('security_settings.mfa', 'required');
    }

    #[Test]
    public function a_member_cannot_update_their_organization_and_an_owner_cannot_delete_it(): void
    {
        $member = $this->createUser(['organization_id' => $this->organization->id], 'User', 'api');
        $owner = $this->createUser(['organization_id' => $this->organization->id], 'Organization Owner', 'api');

        Passport::actingAs($member);
        $this->putJson("/api/v1/organizations/{$this->organization->id}", ['name' => 'Renamed'])->assertForbidden();

        Passport::actingAs($owner);
        $this->deleteJson("/api/v1/organizations/{$this->organization->id}")->assertForbidden();
        $this->postJson('/api/v1/organizations', ['name' => 'Another'])->assertForbidden();
        $this->assertDatabaseHas('organizations', ['id' => $this->organization->id]);
    }

    #[Test]
    public function an_owner_cannot_read_or_change_the_branding_of_another_organization(): void
    {
        $owner = $this->createUser(['organization_id' => $this->organization->id], 'Organization Owner', 'api');
        Passport::actingAs($owner, ['enterprise.branding.manage']);

        $this->getJson("/api/v1/enterprise/organizations/{$this->foreign->id}/branding")->assertForbidden();
        $this->putJson("/api/v1/enterprise/organizations/{$this->foreign->id}/branding", ['primary_color' => '#112233'])->assertForbidden();
        $this->assertFalse(OrganizationBranding::where('organization_id', $this->foreign->id)->exists());
    }

    #[Test]
    public function a_member_cannot_change_their_organizations_branding(): void
    {
        $member = $this->createUser(['organization_id' => $this->organization->id], 'User', 'api');
        Passport::actingAs($member, ['enterprise.branding.manage']);

        $this->putJson("/api/v1/enterprise/organizations/{$this->organization->id}/branding", ['primary_color' => '#112233'])->assertForbidden();
        $this->getJson("/api/v1/enterprise/organizations/{$this->organization->id}/branding")->assertOk();
    }

    #[Test]
    public function a_member_without_update_gets_forbidden_before_validation_can_reveal_other_organizations_data(): void
    {
        $member = $this->createUser(['organization_id' => $this->organization->id], 'User', 'api');
        $this->foreign->update(['slug' => 'taken-slug']);
        $foreignUser = User::factory()->create(['organization_id' => $this->foreign->id]);
        Passport::actingAs($member);

        $this->putJson("/api/v1/organizations/{$this->organization->id}", ['slug' => 'taken-slug'])->assertForbidden();
        $this->postJson("/api/v1/organizations/{$this->organization->id}/users", ['user_id' => $foreignUser->id, 'application_id' => 999999])->assertForbidden();
    }

    #[Test]
    public function granting_and_revoking_access_treats_another_organizations_user_or_application_as_not_found(): void
    {
        $owner = $this->createUser(['organization_id' => $this->organization->id], 'Organization Owner', 'api');
        $foreignUser = User::factory()->create(['organization_id' => $this->foreign->id]);
        $foreignApp = Application::factory()->create(['organization_id' => $this->foreign->id]);
        $ownApp = Application::factory()->create(['organization_id' => $this->organization->id]);
        Passport::actingAs($owner);

        $this->postJson("/api/v1/organizations/{$this->organization->id}/users", ['user_id' => $foreignUser->id, 'application_id' => $ownApp->id])->assertNotFound();
        $this->postJson("/api/v1/organizations/{$this->organization->id}/users", ['user_id' => $owner->id, 'application_id' => $foreignApp->id])->assertNotFound();
        $this->deleteJson("/api/v1/organizations/{$this->organization->id}/users/{$foreignUser->id}/applications/{$ownApp->id}")->assertNotFound();
    }

    #[Test]
    public function a_member_cannot_read_the_security_audit_or_user_activity_reports_but_an_owner_can(): void
    {
        $member = $this->createUser(['organization_id' => $this->organization->id], 'User', 'api');
        $owner = $this->createUser(['organization_id' => $this->organization->id], 'Organization Owner', 'api');

        Passport::actingAs($member);
        $this->getJson("/api/v1/organizations/{$this->organization->id}/reports/security-audit")->assertForbidden();

        Passport::actingAs($owner);
        $this->getJson("/api/v1/organizations/{$this->organization->id}/reports/security-audit")->assertOk();
        $this->getJson("/api/v1/organizations/{$this->organization->id}/reports/user-activity")->assertOk();
    }

    #[Test]
    public function an_inviter_who_no_longer_holds_users_create_cannot_resend_or_cancel_their_invitation(): void
    {
        $exAdmin = $this->createUser(['organization_id' => $this->organization->id], 'User', 'api');
        $invitation = Invitation::factory()->create([
            'organization_id' => $this->organization->id,
            'inviter_id' => $exAdmin->id,
            'role' => 'User',
        ]);
        $token = $invitation->token;
        Passport::actingAs($exAdmin);

        $this->postJson("/api/v1/organizations/{$this->organization->id}/invitations/{$invitation->id}/resend")->assertStatus(400);
        $this->deleteJson("/api/v1/organizations/{$this->organization->id}/invitations/{$invitation->id}")->assertStatus(400);

        $this->assertSame($token, $invitation->fresh()->token);
        $this->assertSame('pending', $invitation->fresh()->status);
    }

    #[Test]
    public function the_permission_context_is_cleared_after_the_request(): void
    {
        $owner = $this->createUser(['organization_id' => $this->organization->id], 'Organization Owner', 'api');
        Passport::actingAs($owner);

        $this->getJson("/api/v1/organizations/{$this->organization->id}")->assertOk();

        $this->assertNull(app(PermissionRegistrar::class)->getPermissionsTeamId());
    }

    #[Test]
    public function the_permission_context_is_null_for_a_user_without_an_organization(): void
    {
        $registrar = app(PermissionRegistrar::class);
        $registrar->setPermissionsTeamId($this->foreign->id);
        $user = User::factory()->create(['organization_id' => null]);
        $request = Request::create('/api/v1/organizations');
        $request->setUserResolver(fn () => $user);
        $seen = 'unset';

        (new SetPermissionContext)->handle($request, function () use ($registrar, &$seen) {
            $seen = $registrar->getPermissionsTeamId();

            return new Response;
        });

        $this->assertNull($seen);
    }

    #[Test]
    public function a_member_cannot_read_the_status_or_download_of_a_users_export(): void
    {
        Storage::fake('local');
        $member = $this->createUser(['organization_id' => $this->organization->id], 'User', 'api');
        $export = $this->completedExport(['data_type' => 'users']);
        Passport::actingAs($member);

        $this->getJson("/api/v1/organizations/{$this->organization->id}/exports/{$export->id}")->assertForbidden();
        $this->getJson($this->downloadUrl($export))->assertForbidden();
    }

    #[Test]
    public function a_member_can_read_the_status_and_download_of_an_applications_export(): void
    {
        Storage::fake('local');
        $member = $this->createUser(['organization_id' => $this->organization->id], 'User', 'api');
        $export = $this->completedExport(['data_type' => 'applications']);
        Passport::actingAs($member);

        $this->getJson("/api/v1/organizations/{$this->organization->id}/exports/{$export->id}")->assertOk();
        $this->get($this->downloadUrl($export))->assertOk();
    }

    #[Test]
    public function an_owner_can_read_the_status_and_download_of_a_users_export(): void
    {
        Storage::fake('local');
        $owner = $this->createUser(['organization_id' => $this->organization->id], 'Organization Owner', 'api');
        $export = $this->completedExport(['data_type' => 'users']);
        Passport::actingAs($owner);

        $this->getJson("/api/v1/organizations/{$this->organization->id}/exports/{$export->id}")->assertOk();
        $this->get($this->downloadUrl($export))->assertOk();
    }

    private function completedExport(array $filters): AuditExport
    {
        $export = AuditExport::factory()->completed()->create([
            'organization_id' => $this->organization->id,
            'type' => 'json',
            'filters' => $filters,
        ]);
        Storage::disk('local')->put($export->file_path, '[]');

        return $export;
    }

    private function downloadUrl(AuditExport $export): string
    {
        return URL::temporarySignedRoute(
            'api.organizations.exports.download',
            now()->addHour(),
            ['id' => $this->organization->id, 'exportId' => $export->id]
        );
    }
}
