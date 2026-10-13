<?php

namespace Tests\Integration\BulkOperations;

use App\Models\Organization;
use App\Models\User;
use PHPUnit\Framework\Attributes\Test;
use Tests\Integration\IntegrationTestCase;

class BulkUserGuardsTest extends IntegrationTestCase
{
    private Organization $organization;

    protected function setUp(): void
    {
        parent::setUp();

        $this->organization = $this->createOrganization();
    }

    #[Test]
    public function it_forbids_bulk_delete_without_users_delete_with_403(): void
    {
        $admin = $this->createApiOrganizationAdmin(['organization_id' => $this->organization->id]);
        $member = User::factory()->create(['organization_id' => $this->organization->id]);

        $response = $this->actingAs($admin, 'api')
            ->deleteJson("/api/v1/organizations/{$this->organization->id}/bulk/delete-users", [
                'user_ids' => [$member->id],
            ]);

        $response->assertForbidden();
        $this->assertNotSoftDeleted('users', ['id' => $member->id]);
    }

    #[Test]
    public function it_skips_the_caller_and_users_exceeding_the_caller_in_bulk_delete_and_deactivate(): void
    {
        $caller = $this->createApiOrganizationAdmin(['organization_id' => $this->organization->id]);
        $caller->givePermissionTo('users.delete');
        $owner = $this->createUser(['organization_id' => $this->organization->id], 'Organization Owner', 'api');
        $peer = $this->createApiOrganizationAdmin(['organization_id' => $this->organization->id]);
        $member = User::factory()->create(['organization_id' => $this->organization->id]);
        $ids = [$caller->id, $owner->id, $peer->id, $member->id];

        $this->actingAs($caller, 'api')
            ->deleteJson("/api/v1/organizations/{$this->organization->id}/bulk/delete-users", ['user_ids' => $ids])
            ->assertOk()
            ->assertJsonPath('data.deleted_count', 2);

        $this->assertNotSoftDeleted('users', ['id' => $caller->id]);
        $this->assertNotSoftDeleted('users', ['id' => $owner->id]);
        $this->assertSoftDeleted('users', ['id' => $peer->id]);
        $this->assertSoftDeleted('users', ['id' => $member->id]);

        $peer = $this->createApiOrganizationAdmin(['organization_id' => $this->organization->id]);
        $member = User::factory()->create(['organization_id' => $this->organization->id, 'is_active' => true]);

        $this->actingAs($caller, 'api')
            ->patchJson('/api/v1/users/bulk', [
                'user_ids' => [$caller->id, $owner->id, $peer->id, $member->id],
                'action' => 'deactivate',
            ])
            ->assertOk()
            ->assertJsonPath('data.affected_count', 2);

        $this->assertTrue((bool) $caller->fresh()->is_active);
        $this->assertTrue((bool) $owner->fresh()->is_active);
        $this->assertFalse((bool) $peer->fresh()->is_active);
        $this->assertFalse((bool) $member->fresh()->is_active);
    }

    #[Test]
    public function it_forbids_users_bulk_delete_without_users_delete_with_403(): void
    {
        $admin = $this->createApiOrganizationAdmin(['organization_id' => $this->organization->id]);
        $member = User::factory()->create(['organization_id' => $this->organization->id]);

        $this->actingAs($admin, 'api')
            ->patchJson('/api/v1/users/bulk', ['user_ids' => [$member->id], 'action' => 'delete'])
            ->assertForbidden();

        $this->assertNotSoftDeleted('users', ['id' => $member->id]);
    }

    #[Test]
    public function it_skips_the_caller_and_users_exceeding_the_caller_in_users_bulk_delete(): void
    {
        $caller = $this->createApiOrganizationAdmin(['organization_id' => $this->organization->id]);
        $caller->givePermissionTo('users.delete');
        $owner = $this->createUser(['organization_id' => $this->organization->id], 'Organization Owner', 'api');
        $peer = $this->createApiOrganizationAdmin(['organization_id' => $this->organization->id]);
        $member = User::factory()->create(['organization_id' => $this->organization->id]);

        $this->actingAs($caller, 'api')
            ->patchJson('/api/v1/users/bulk', [
                'user_ids' => [$caller->id, $owner->id, $peer->id, $member->id],
                'action' => 'delete',
            ])
            ->assertOk()
            ->assertJsonPath('data.affected_count', 2);

        $this->assertNotSoftDeleted('users', ['id' => $caller->id]);
        $this->assertNotSoftDeleted('users', ['id' => $owner->id]);
        $this->assertSoftDeleted('users', ['id' => $peer->id]);
        $this->assertSoftDeleted('users', ['id' => $member->id]);
    }

    #[Test]
    public function it_skips_users_exceeding_the_caller_in_users_bulk_activate(): void
    {
        $caller = $this->createApiOrganizationAdmin(['organization_id' => $this->organization->id]);
        $owner = $this->createUser(['organization_id' => $this->organization->id, 'is_active' => false], 'Organization Owner', 'api');
        $member = User::factory()->create(['organization_id' => $this->organization->id, 'is_active' => false]);

        $this->actingAs($caller, 'api')
            ->patchJson('/api/v1/users/bulk', [
                'user_ids' => [$owner->id, $member->id],
                'action' => 'activate',
            ])
            ->assertOk()
            ->assertJsonPath('data.affected_count', 1);

        $this->assertFalse((bool) $owner->fresh()->is_active);
        $this->assertTrue((bool) $member->fresh()->is_active);
    }

    #[Test]
    public function it_skips_users_exceeding_the_caller_in_bulk_enable_mfa(): void
    {
        $caller = $this->createApiOrganizationAdmin(['organization_id' => $this->organization->id]);
        $owner = $this->createUser(['organization_id' => $this->organization->id], 'Organization Owner', 'api');
        $member = User::factory()->create(['organization_id' => $this->organization->id]);

        $this->actingAs($caller, 'api')
            ->postJson("/api/v1/organizations/{$this->organization->id}/bulk/enable-mfa", [
                'user_ids' => [$caller->id, $owner->id, $member->id],
            ])
            ->assertOk()
            ->assertJsonPath('data.enabled_count', 2);
    }

    #[Test]
    public function it_treats_foreign_user_ids_like_missing_ids_in_bulk_delete_and_enable_mfa(): void
    {
        $caller = $this->createApiOrganizationAdmin(['organization_id' => $this->organization->id]);
        $caller->givePermissionTo('users.delete');
        $foreign = User::factory()->create(['organization_id' => $this->createOrganization()->id]);
        $missingId = User::max('id') + 1000;
        $deleteUrl = "/api/v1/organizations/{$this->organization->id}/bulk/delete-users";
        $mfaUrl = "/api/v1/organizations/{$this->organization->id}/bulk/enable-mfa";

        $this->actingAs($caller, 'api');
        $foreignDelete = $this->deleteJson($deleteUrl, ['user_ids' => [$foreign->id]]);
        $missingDelete = $this->deleteJson($deleteUrl, ['user_ids' => [$missingId]])->assertOk();
        $foreignMfa = $this->postJson($mfaUrl, ['user_ids' => [$foreign->id]]);
        $missingMfa = $this->postJson($mfaUrl, ['user_ids' => [$missingId]])->assertOk();

        $this->assertSame($missingDelete->status(), $foreignDelete->status());
        $this->assertSame($missingDelete->json(), $foreignDelete->json());
        $this->assertSame($missingMfa->status(), $foreignMfa->status());
        $this->assertSame($missingMfa->json(), $foreignMfa->json());
        $this->assertNotSoftDeleted('users', ['id' => $foreign->id]);
    }
}
