<?php

namespace Tests\Integration\Users;

use App\Http\Middleware\EnforceOrganizationBoundary;
use App\Models\Organization;
use App\Models\Role;
use App\Models\User;
use App\Services\SocialAuthService;
use App\Services\UserRoleService;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\DB;
use Laravel\Passport\Passport;
use Mockery;
use PHPUnit\Framework\Attributes\Test;
use Tests\TestCase;

class UserEndpointsAuthorizationTest extends TestCase
{
    use RefreshDatabase;

    private Organization $organization;

    private User $member;

    protected function setUp(): void
    {
        parent::setUp();

        $this->organization = Organization::factory()->create();
        $this->member = $this->createApiUser(['organization_id' => $this->organization->id]);
    }

    #[Test]
    public function an_owner_cannot_delete_a_user_of_another_organization_even_without_the_boundary_middleware(): void
    {
        $this->withoutMiddleware(EnforceOrganizationBoundary::class);
        $owner = $this->createUser(['organization_id' => $this->organization->id], 'Organization Owner', 'api');
        $foreign = $this->createApiUser();
        Passport::actingAs($owner, ['users.delete']);

        $response = $this->deleteJson("/api/v1/users/{$foreign->id}");

        $response->assertNotFound();
        $this->assertDatabaseHas('users', ['id' => $foreign->id]);
    }

    #[Test]
    public function an_owner_cannot_read_update_or_list_roles_of_another_organizations_user_without_the_boundary_middleware(): void
    {
        $this->withoutMiddleware(EnforceOrganizationBoundary::class);
        $owner = $this->createUser(['organization_id' => $this->organization->id], 'Organization Owner', 'api');
        $foreign = $this->createApiUser();
        Passport::actingAs($owner);

        $this->getJson("/api/v1/users/{$foreign->id}")->assertNotFound();
        $this->putJson("/api/v1/users/{$foreign->id}", ['name' => 'Hijacked'])->assertNotFound();
        $this->getJson("/api/v1/users/{$foreign->id}/roles")->assertNotFound();
        $this->getJson("/api/v1/users/{$foreign->id}/sessions")->assertNotFound();
        $this->deleteJson("/api/v1/users/{$foreign->id}/sessions")->assertNotFound();
        $this->assertNotSame('Hijacked', $foreign->fresh()->name);
    }

    #[Test]
    public function an_owner_can_list_an_organization_members_sessions(): void
    {
        $owner = $this->createUser(['organization_id' => $this->organization->id], 'Organization Owner', 'api');
        $this->member->createToken('Laptop', ['*']);
        Passport::actingAs($owner);

        $this->getJson("/api/v1/users/{$this->member->id}/sessions")->assertOk();
    }

    #[Test]
    public function an_auditor_can_view_but_not_terminate_a_members_sessions(): void
    {
        $auditor = $this->createUser(['organization_id' => $this->organization->id], 'Auditor', 'api');
        $token = $this->member->createToken('Laptop', ['*']);
        Passport::actingAs($auditor);

        $this->getJson("/api/v1/users/{$this->member->id}/sessions")->assertOk();
        $this->deleteJson("/api/v1/users/{$this->member->id}/sessions/{$token->token->id}")->assertForbidden();
    }

    #[Test]
    public function a_user_manager_can_terminate_but_not_view_a_members_sessions(): void
    {
        $manager = $this->createUser(['organization_id' => $this->organization->id], 'User Manager', 'api');
        $token = $this->member->createToken('Laptop', ['*']);
        Passport::actingAs($manager);

        $this->getJson("/api/v1/users/{$this->member->id}/sessions")->assertForbidden();
        $this->deleteJson("/api/v1/users/{$this->member->id}/sessions/{$token->token->id}")->assertOk();
    }

    #[Test]
    public function a_regular_user_can_manage_only_their_own_sessions(): void
    {
        $other = $this->createApiUser(['organization_id' => $this->organization->id]);
        Passport::actingAs($this->member);

        $this->getJson("/api/v1/users/{$this->member->id}/sessions")->assertOk();
        $this->getJson("/api/v1/users/{$other->id}/sessions")->assertForbidden();
        $this->deleteJson("/api/v1/users/{$other->id}/sessions")->assertForbidden();
    }

    #[Test]
    public function the_social_callback_lists_only_organization_and_global_roles(): void
    {
        $otherOrganization = Organization::factory()->create();
        $foreignRole = Role::create(['name' => 'Foreign Auditor', 'guard_name' => 'api', 'organization_id' => $otherOrganization->id]);
        $this->member->refresh();
        DB::table('model_has_roles')->insert([
            'role_id' => $foreignRole->id,
            'model_type' => $this->member->getMorphClass(),
            'model_id' => $this->member->id,
            'organization_id' => $otherOrganization->id,
        ]);

        $service = Mockery::mock(SocialAuthService::class);
        $service->shouldReceive('isProviderSupported')->andReturn(true);
        $service->shouldReceive('isProviderEnabled')->andReturn(true);
        $service->shouldReceive('handleCallback')->andReturn([
            'user' => $this->member,
            'access_token' => 'token',
            'refresh_token' => 'refresh',
            'expires_in' => 3600,
            'token_type' => 'Bearer',
        ]);
        $this->app->instance(SocialAuthService::class, $service);

        $roles = $this->getJson('/api/v1/auth/social/google/callback')->json('data.user.roles');

        $this->assertSame(
            Role::whereKey(app(UserRoleService::class)->assignedRoleIds($this->member))
                ->where('organization_id', $this->organization->id)->pluck('name')->unique()->values()->all(),
            $roles
        );
        $this->assertNotContains('Foreign Auditor', $roles);
        $this->assertContains('User', $roles);
    }
}
