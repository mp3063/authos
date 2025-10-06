<?php

namespace Tests\Security;

use App\Models\Application;
use App\Models\Organization;
use App\Models\User;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Laravel\Passport\Passport;
use Tests\TestCase;

/**
 * OWASP A01:2021 - Broken Access Control
 *
 * Tests for:
 * - Multi-tenant isolation violations
 * - Vertical privilege escalation
 * - Horizontal privilege escalation
 * - Insecure direct object references (IDOR)
 * - Missing function level access control
 * - API authorization bypass
 */
class OwaspA01BrokenAccessControlTest extends TestCase
{
    use RefreshDatabase;

    protected Organization $org1;

    protected Organization $org2;

    protected User $admin1;

    protected User $admin2;

    protected User $user1;

    protected User $user2;

    protected function setUp(): void
    {
        parent::setUp();

        // Create roles if they don't exist
        \Spatie\Permission\Models\Role::firstOrCreate(['name' => 'Organization Admin', 'guard_name' => 'web']);
        \Spatie\Permission\Models\Role::firstOrCreate(['name' => 'User', 'guard_name' => 'web']);
        \Spatie\Permission\Models\Role::firstOrCreate(['name' => 'Super Admin', 'guard_name' => 'web']);

        // Create two separate organizations
        $this->org1 = Organization::factory()->create(['name' => 'Organization 1']);
        $this->org2 = Organization::factory()->create(['name' => 'Organization 2']);

        // Create admins for each organization
        $this->admin1 = User::factory()->create(['organization_id' => $this->org1->id]);
        $this->admin1->assignRole('Organization Admin');

        $this->admin2 = User::factory()->create(['organization_id' => $this->org2->id]);
        $this->admin2->assignRole('Organization Admin');

        // Create regular users for each organization
        $this->user1 = User::factory()->create(['organization_id' => $this->org1->id]);
        $this->user1->assignRole('User');

        $this->user2 = User::factory()->create(['organization_id' => $this->org2->id]);
        $this->user2->assignRole('User');
    }

    /** @test */
    public function it_prevents_cross_organization_user_access()
    {
        Passport::actingAs($this->admin1);

        // Try to access user from different organization
        $response = $this->getJson("/api/v1/users/{$this->user2->id}");

        $response->assertStatus(403);
        $this->assertStringContainsString('not belong to your organization', $response->json('message'));
    }

    /** @test */
    public function it_prevents_cross_organization_user_update()
    {
        Passport::actingAs($this->admin1);

        $response = $this->putJson("/api/v1/users/{$this->user2->id}", [
            'name' => 'Hacked Name',
            'email' => 'hacked@test.com',
        ]);

        $response->assertStatus(403);
        $this->user2->refresh();
        $this->assertNotEquals('Hacked Name', $this->user2->name);
    }

    /** @test */
    public function it_prevents_cross_organization_user_deletion()
    {
        Passport::actingAs($this->admin1);

        $response = $this->deleteJson("/api/v1/users/{$this->user2->id}");

        $response->assertStatus(403);
        $this->assertDatabaseHas('users', ['id' => $this->user2->id]);
    }

    /** @test */
    public function it_prevents_regular_user_from_accessing_admin_endpoints()
    {
        Passport::actingAs($this->user1);

        // Try to access organization settings
        $response = $this->getJson("/api/v1/organizations/{$this->org1->id}");
        $response->assertStatus(403);

        // Try to create application
        $response = $this->postJson('/api/v1/applications', [
            'name' => 'Unauthorized App',
            'redirect_uri' => 'https://test.com',
        ]);
        $response->assertStatus(403);
    }

    /** @test */
    public function it_prevents_vertical_privilege_escalation_through_role_modification()
    {
        Passport::actingAs($this->user1);

        // Try to assign admin role to self
        $response = $this->postJson("/api/v1/users/{$this->user1->id}/roles", [
            'roles' => ['Organization Admin'],
        ]);

        $response->assertStatus(403);
        $this->user1->refresh();
        $this->assertFalse($this->user1->hasRole('Organization Admin'));
    }

    /** @test */
    public function it_prevents_horizontal_privilege_escalation_in_same_organization()
    {
        // Create another user in same org
        $user3 = User::factory()->create(['organization_id' => $this->org1->id]);
        $user3->assignRole('User');

        Passport::actingAs($this->user1);

        // Try to update another user's profile
        $response = $this->putJson("/api/v1/users/{$user3->id}", [
            'name' => 'Hijacked Name',
        ]);

        $response->assertStatus(403);
    }

    /** @test */
    public function it_prevents_idor_in_application_access()
    {
        $app1 = Application::factory()->create(['organization_id' => $this->org1->id]);
        $app2 = Application::factory()->create(['organization_id' => $this->org2->id]);

        Passport::actingAs($this->admin1);

        // Try to access application from different organization
        $response = $this->getJson("/api/v1/applications/{$app2->id}");

        $response->assertStatus(403);
    }

    /** @test */
    public function it_prevents_idor_in_application_credentials_access()
    {
        $app2 = Application::factory()->create(['organization_id' => $this->org2->id]);

        Passport::actingAs($this->admin1);

        // Try to regenerate credentials for another org's application
        $response = $this->postJson("/api/v1/applications/{$app2->id}/regenerate-credentials");

        $response->assertStatus(403);
    }

    /** @test */
    public function it_prevents_mass_assignment_of_organization_id()
    {
        Passport::actingAs($this->admin1);

        // Try to create user with different organization_id
        $response = $this->postJson('/api/v1/users', [
            'name' => 'Test User',
            'email' => 'test@example.com',
            'password' => 'password123',
            'organization_id' => $this->org2->id, // Try to assign to different org
        ]);

        if ($response->status() === 201) {
            $userId = $response->json('data.id');
            $user = User::find($userId);
            $this->assertEquals($this->org1->id, $user->organization_id);
        }
    }

    /** @test */
    public function it_prevents_parameter_tampering_for_organization_context()
    {
        Passport::actingAs($this->admin1);

        // Try to list users with manipulated organization_id parameter
        $response = $this->getJson("/api/v1/users?organization_id={$this->org2->id}");

        $users = $response->json('data');

        // Should only return users from authenticated user's organization
        foreach ($users as $user) {
            $this->assertEquals($this->org1->id, $user['organization_id']);
        }
    }

    /** @test */
    public function it_prevents_access_to_super_admin_only_endpoints()
    {
        Passport::actingAs($this->admin1);

        // Try to access super admin endpoints (if they exist)
        $response = $this->getJson('/api/v1/admin/system-settings');

        // Should be forbidden unless user is super admin
        if (! $this->admin1->hasRole('Super Admin')) {
            $response->assertStatus(403);
        }
    }

    /** @test */
    public function it_validates_api_token_scope_restrictions()
    {
        Passport::actingAs($this->user1, ['read-only']);

        // Try to perform write operation with read-only scope
        $response = $this->postJson('/api/v1/applications', [
            'name' => 'Test App',
            'redirect_uri' => 'https://test.com',
        ]);

        $response->assertStatus(403);
    }

    /** @test */
    public function it_prevents_file_path_traversal_in_organization_resources()
    {
        Passport::actingAs($this->admin1);

        // Try path traversal in avatar upload
        $response = $this->postJson("/api/v1/organizations/{$this->org1->id}/branding", [
            'logo_path' => '../../../etc/passwd',
        ]);

        // Should either reject or sanitize the path
        $this->assertNotEquals('../../../etc/passwd', $this->org1->fresh()->logo_path ?? '');
    }

    /** @test */
    public function it_enforces_rate_limiting_per_role()
    {
        Passport::actingAs($this->user1);

        // Regular users should have stricter rate limits
        $responses = [];

        for ($i = 0; $i < 120; $i++) {
            $responses[] = $this->getJson('/api/v1/profile');
        }

        $tooManyRequests = collect($responses)->first(fn ($r) => $r->status() === 429);
        $this->assertNotNull($tooManyRequests, 'Rate limiting should be enforced');
    }

    /** @test */
    public function it_prevents_session_fixation_attacks()
    {
        // Get initial session
        $response = $this->postJson('/api/auth/login', [
            'email' => $this->user1->email,
            'password' => 'password',
        ]);

        $initialToken = $response->json('data.token');

        // Logout and login again
        $this->withToken($initialToken)->postJson('/api/auth/logout');

        $response2 = $this->postJson('/api/auth/login', [
            'email' => $this->user1->email,
            'password' => 'password',
        ]);

        $newToken = $response2->json('data.token');

        // Tokens should be different (session regeneration)
        $this->assertNotEquals($initialToken, $newToken);

        // Old token should be invalid
        $response3 = $this->withToken($initialToken)->getJson('/api/v1/profile');
        $response3->assertStatus(401);
    }

    /** @test */
    public function it_validates_authorization_for_webhook_endpoints()
    {
        $webhook = \App\Models\Webhook::factory()->create(['organization_id' => $this->org2->id]);

        Passport::actingAs($this->admin1);

        // Try to access webhook from different organization
        $response = $this->getJson("/api/v1/webhooks/{$webhook->id}");
        $response->assertStatus(403);

        // Try to delete webhook from different organization
        $response = $this->deleteJson("/api/v1/webhooks/{$webhook->id}");
        $response->assertStatus(403);
    }

    /** @test */
    public function it_prevents_forced_browsing_to_unauthorized_resources()
    {
        Passport::actingAs($this->user1);

        // Try to access various admin-only endpoints
        $adminEndpoints = [
            '/api/v1/organizations',
            '/api/v1/organizations/'.$this->org1->id,
            '/api/v1/audit-logs',
            '/api/v1/security-incidents',
        ];

        foreach ($adminEndpoints as $endpoint) {
            $response = $this->getJson($endpoint);
            $response->assertStatus(403, "Endpoint {$endpoint} should be forbidden");
        }
    }

    protected function withToken(string $token)
    {
        return $this->withHeaders([
            'Authorization' => 'Bearer '.$token,
        ]);
    }
}
