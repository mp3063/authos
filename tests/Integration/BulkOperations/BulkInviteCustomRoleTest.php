<?php

namespace Tests\Integration\BulkOperations;

use App\Models\CustomRole;
use App\Models\Organization;
use App\Models\User;
use Illuminate\Testing\TestResponse;
use PHPUnit\Framework\Attributes\Test;
use Tests\Integration\IntegrationTestCase;

class BulkInviteCustomRoleTest extends IntegrationTestCase
{
    private Organization $organization;

    protected function setUp(): void
    {
        parent::setUp();

        $this->organization = $this->createOrganization();
    }

    #[Test]
    public function it_rejects_a_non_integer_custom_role_id_with_422(): void
    {
        $owner = $this->createApiOrganizationOwner(['organization_id' => $this->organization->id]);

        $this->invite($owner, ['email' => 'invitee@example.com', 'custom_role_id' => 'abc'])
            ->assertUnprocessable()
            ->assertJsonValidationErrors('invitations.0.custom_role_id');

        $this->assertDatabaseMissing('invitations', ['email' => 'invitee@example.com']);
    }

    #[Test]
    public function it_refuses_an_inactive_custom_role_in_a_bulk_invite(): void
    {
        $owner = $this->createApiOrganizationOwner(['organization_id' => $this->organization->id]);
        $customRole = CustomRole::factory()->inactive()->create([
            'organization_id' => $this->organization->id,
            'permissions' => ['users.read'],
        ]);

        $response = $this->invite($owner, ['email' => 'invitee@example.com', 'custom_role_id' => $customRole->id]);

        $this->assertSame(0, $response->json('data.invited_count'));
        $this->assertSame('invitee@example.com', $response->json('data.failed.0.email'));
        $this->assertDatabaseMissing('invitations', ['email' => 'invitee@example.com']);
    }

    #[Test]
    public function it_rejects_an_out_of_range_invitation_lifetime_with_422(): void
    {
        $owner = $this->createApiOrganizationOwner(['organization_id' => $this->organization->id]);

        $this->invite($owner, ['email' => 'invitee@example.com', 'expires_in_days' => 365])
            ->assertUnprocessable()
            ->assertJsonValidationErrors('invitations.0.expires_in_days');

        $this->assertDatabaseMissing('invitations', ['email' => 'invitee@example.com']);
    }

    /**
     * @param  array<string, mixed>  $invitation
     */
    private function invite(User $caller, array $invitation): TestResponse
    {
        return $this->actingAs($caller, 'api')
            ->postJson("/api/v1/organizations/{$this->organization->id}/bulk/invite-users", [
                'invitations' => [$invitation],
            ]);
    }
}
