<?php

namespace Tests\Integration\Users;

use App\Models\Application;
use App\Models\Organization;
use App\Models\User;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Laravel\Passport\Passport;
use PHPUnit\Framework\Attributes\Test;
use Tests\TestCase;

class UserApplicationsAuthorizationTest extends TestCase
{
    use RefreshDatabase;

    private Organization $organization;

    private Application $application;

    private User $member;

    protected function setUp(): void
    {
        parent::setUp();

        $this->organization = Organization::factory()->create();
        $this->application = Application::factory()->create(['organization_id' => $this->organization->id]);
        $this->member = $this->createApiUser(['organization_id' => $this->organization->id]);
    }

    #[Test]
    public function an_application_manager_can_grant_access_through_applications_update(): void
    {
        $manager = $this->createUser(['organization_id' => $this->organization->id], 'Application Manager', 'api');
        Passport::actingAs($manager, ['applications.update']);

        $response = $this->postJson("/api/v1/users/{$this->member->id}/applications", [
            'application_id' => $this->application->id,
            'permissions' => ['applications.read'],
        ]);

        $response->assertOk();
        $this->assertDatabaseHas('user_applications', [
            'user_id' => $this->member->id,
            'application_id' => $this->application->id,
        ]);
    }

    #[Test]
    public function a_user_manager_without_applications_update_cannot_grant_access(): void
    {
        $userManager = $this->createUser(['organization_id' => $this->organization->id], 'User Manager', 'api');
        Passport::actingAs($userManager, ['applications.update']);

        $response = $this->postJson("/api/v1/users/{$this->member->id}/applications", [
            'application_id' => $this->application->id,
            'permissions' => ['applications.read'],
        ]);

        $response->assertForbidden();
        $this->assertDatabaseMissing('user_applications', ['user_id' => $this->member->id]);
    }

    #[Test]
    public function a_foreign_user_id_on_single_grant_is_refused(): void
    {
        $manager = $this->createUser(['organization_id' => $this->organization->id], 'Application Manager', 'api');
        $foreignUser = User::factory()->create(['organization_id' => Organization::factory()->create()->id]);
        Passport::actingAs($manager, ['applications.update']);

        $response = $this->postJson("/api/v1/users/{$foreignUser->id}/applications", [
            'application_id' => $this->application->id,
            'permissions' => ['applications.read'],
        ]);

        $response->assertNotFound();
        $this->assertDatabaseMissing('user_applications', ['user_id' => $foreignUser->id]);
    }

    #[Test]
    public function a_foreign_user_id_on_single_revoke_is_refused(): void
    {
        $manager = $this->createUser(['organization_id' => $this->organization->id], 'Application Manager', 'api');
        $foreignOrganization = Organization::factory()->create();
        $foreignApplication = Application::factory()->create(['organization_id' => $foreignOrganization->id]);
        $foreignUser = User::factory()->create(['organization_id' => $foreignOrganization->id]);
        $foreignUser->applications()->attach($foreignApplication->id, ['granted_at' => now()]);
        Passport::actingAs($manager, ['applications.update']);

        $response = $this->deleteJson("/api/v1/users/{$foreignUser->id}/applications/{$foreignApplication->id}");

        $response->assertNotFound();
        $this->assertDatabaseHas('user_applications', [
            'user_id' => $foreignUser->id,
            'application_id' => $foreignApplication->id,
        ]);
    }

    #[Test]
    public function an_application_manager_can_list_another_users_applications(): void
    {
        $manager = $this->createUser(['organization_id' => $this->organization->id], 'Application Manager', 'api');
        $this->member->applications()->attach($this->application->id, ['granted_at' => now()]);
        Passport::actingAs($manager, ['applications.read']);

        $this->getJson("/api/v1/users/{$this->member->id}/applications")->assertOk();
    }

    #[Test]
    public function an_organization_owner_can_list_another_users_applications(): void
    {
        $owner = $this->createApiOrganizationOwner(['organization_id' => $this->organization->id]);
        Passport::actingAs($owner, ['applications.read']);

        $this->getJson("/api/v1/users/{$this->member->id}/applications")->assertOk();
    }

    #[Test]
    public function a_plain_user_cannot_list_another_users_applications(): void
    {
        $other = $this->createApiUser(['organization_id' => $this->organization->id]);
        Passport::actingAs($other, ['applications.read']);

        $this->getJson("/api/v1/users/{$this->member->id}/applications")->assertForbidden();
    }

    #[Test]
    public function an_admin_cannot_list_a_foreign_users_applications(): void
    {
        $admin = $this->createApiOrganizationAdmin(['organization_id' => $this->organization->id]);
        $foreignUser = User::factory()->create(['organization_id' => Organization::factory()->create()->id]);
        Passport::actingAs($admin, ['applications.read']);

        $this->getJson("/api/v1/users/{$foreignUser->id}/applications")->assertNotFound();
    }
}
