<?php

namespace Tests\Integration\BulkOperations;

use App\Http\Middleware\EnforceOrganizationBoundary;
use App\Models\BulkImportJob;
use App\Models\User;
use Illuminate\Support\Facades\Storage;
use PHPUnit\Framework\Attributes\Test;
use Spatie\Permission\PermissionRegistrar;
use Tests\Integration\IntegrationTestCase;

class BulkEndpointsAuthorizationTest extends IntegrationTestCase
{
    #[Test]
    public function it_hides_another_organizations_bulk_endpoints_from_an_owner_without_the_boundary_middleware(): void
    {
        $this->withoutMiddleware(EnforceOrganizationBoundary::class);
        $owner = $this->createApiOrganizationOwner();
        $foreign = $this->createApiUser();
        $this->actingAsApiUserWithToken($owner);
        $base = "/api/v1/organizations/{$foreign->organization_id}/bulk";
        $payload = ['user_ids' => [$foreign->id]];

        $this->postJson("{$base}/invite-users", ['emails' => ['x@example.com']])->assertNotFound();
        $this->postJson("{$base}/assign-roles", $payload + ['role' => 'User'])->assertNotFound();
        $this->postJson("{$base}/export-users", [])->assertNotFound();
        $this->postJson("{$base}/import-users", [])->assertNotFound();
        $this->postJson("{$base}/enable-mfa", $payload)->assertNotFound();
        $this->deleteJson("{$base}/delete-users", $payload)->assertNotFound();

        $this->assertNull($foreign->fresh()->mfa_required_at);
        $this->assertModelExists($foreign);
    }

    #[Test]
    public function it_assigns_and_revokes_a_bulk_role_in_the_target_organization_without_an_ambient_team(): void
    {
        $owner = $this->createApiOrganizationOwner();
        $organizationId = $owner->organization_id;
        $this->setupRoleWithPermissions('Organization Member', 'web', $organizationId);
        $this->setupRoleWithPermissions('Organization Member', 'api', $organizationId);
        $target = User::factory()->create(['organization_id' => $organizationId]);
        $this->actingAsApiUserWithToken($owner);
        $url = "/api/v1/organizations/{$organizationId}/bulk/assign-roles";

        $this->postJson($url, ['user_ids' => [$target->id], 'role' => 'Organization Member'])->assertOk();

        $this->assertNull(app(PermissionRegistrar::class)->getPermissionsTeamId());
        $assigned = $this->assignedRolesNamed($target, 'Organization Member');
        $this->assertCount(1, $assigned);
        $this->assertSame($organizationId, $assigned->first()->organization_id);
        $this->assertSame('api', $assigned->first()->guard_name);

        $this->postJson($url, ['user_ids' => [$target->id], 'role' => 'Organization Member', 'action' => 'revoke'])->assertOk();

        $this->assertCount(0, $this->assignedRolesNamed($target, 'Organization Member'));
    }

    #[Test]
    public function it_lists_every_organizations_jobs_for_a_super_admin_with_or_without_an_organization(): void
    {
        $own = $this->createApiOrganizationOwner();
        $otherJob = BulkImportJob::factory()->create();
        $ownJob = BulkImportJob::factory()->create(['organization_id' => $own->organization_id]);
        $superWithOrg = $this->createApiSuperAdmin();
        $superWithoutOrg = $this->createApiSuperAdmin();
        $superWithoutOrg->forceFill(['organization_id' => null])->save();

        foreach ([$superWithOrg, $superWithoutOrg] as $super) {
            $this->actingAsApiUserWithToken($super);
            $ids = collect($this->getJson('/api/v1/bulk/imports?all=1')->assertOk()->json('data'))->pluck('id');
            $this->assertEqualsCanonicalizing([$otherJob->id, $ownJob->id], $ids->all());
        }

        $this->actingAsApiUserWithToken($own);
        $ids = collect($this->getJson('/api/v1/bulk/imports?all=1')->assertOk()->json('data'))->pluck('id');
        $this->assertSame([$ownJob->id], $ids->all());
    }

    #[Test]
    public function it_exports_the_roles_of_another_organizations_users_for_a_super_admin(): void
    {
        Storage::fake('local');
        Storage::fake('public');
        $super = $this->createApiSuperAdmin();
        $member = $this->createApiUser();
        $this->actingAsApiUserWithToken($super);

        $response = $this->postJson("/api/v1/organizations/{$member->organization_id}/bulk/export-users", [
            'format' => 'csv',
            'include_roles' => true,
        ])->assertOk();

        $path = 'exports/'.$response->json('data.filename');
        $csv = Storage::disk(config('filesystems.default'))->get($path);
        $this->assertStringContainsString($member->email, $csv);
        $this->assertMatchesRegularExpression('/Active,User,/', $csv);
    }
}
