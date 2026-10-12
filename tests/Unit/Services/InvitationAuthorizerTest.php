<?php

namespace Tests\Unit\Services;

use App\Models\CustomRole;
use App\Models\Invitation;
use App\Models\User;
use App\Services\InvitationAuthorizer;
use PHPUnit\Framework\Attributes\Test;
use Spatie\Permission\PermissionRegistrar;
use Tests\TestCase;

class InvitationAuthorizerTest extends TestCase
{
    #[Test]
    public function it_lets_owners_and_admins_manage_invitations_without_an_ambient_team(): void
    {
        foreach (['Organization Owner', 'Organization Admin'] as $role) {
            $user = $this->withoutAmbientTeam($this->createUser([], $role, 'web'));

            $this->assertInvitationAccess(true, $user);
        }
    }

    #[Test]
    public function it_lets_a_custom_role_with_users_create_manage_invitations(): void
    {
        $user = $this->createUser([], 'User', 'web');
        CustomRole::factory()->forOrganization($user->organization)
            ->create(['permissions' => ['users.create']])
            ->assignToUser($user);

        $this->assertInvitationAccess(true, $this->withoutAmbientTeam($user));
    }

    #[Test]
    public function it_denies_a_member_without_users_create(): void
    {
        $this->assertInvitationAccess(false, $this->withoutAmbientTeam($this->createUser([], 'User', 'web')));
    }

    private function assertInvitationAccess(bool $expected, User $user): void
    {
        $authorizer = app(InvitationAuthorizer::class);
        $invitation = Invitation::factory()->create(['organization_id' => $user->organization_id]);

        $this->assertSame($expected, $authorizer->canInviteToOrganization($user, $user->organization));
        $this->assertSame($expected, $authorizer->canViewInvitations($user, $user->organization));
        $this->assertSame($expected, $authorizer->canManageInvitation($user, $invitation));
    }

    private function withoutAmbientTeam(User $user): User
    {
        app(PermissionRegistrar::class)->setPermissionsTeamId(null);

        return $user->unsetRelation('roles')->unsetRelation('permissions');
    }
}
