<?php

namespace Tests\Feature\Api\Enterprise;

use App\Models\CustomDomain;
use App\Models\Organization;
use App\Models\User;
use App\Services\DomainVerificationService;
use Laravel\Passport\Passport;
use Mockery;
use Spatie\Permission\Models\Role;
use Tests\TestCase;

class DomainControllerTest extends TestCase
{
    private Organization $organization;

    private User $adminUser;

    private User $regularUser;

    private DomainVerificationService $domainService;

    protected function setUp(): void
    {
        parent::setUp();

        $this->organization = Organization::factory()->create([
            'settings' => [
                'enterprise_features' => [
                    'custom_domains_enabled' => true,
                ],
            ],
        ]);

        Role::firstOrCreate(['name' => 'User', 'guard_name' => 'api']);
        Role::firstOrCreate(['name' => 'Organization Admin', 'guard_name' => 'api']);
        Role::firstOrCreate(['name' => 'Super Admin', 'guard_name' => 'api']);

        $this->adminUser = $this->createApiOrganizationAdmin([
            'organization_id' => $this->organization->id,
        ]);

        $this->regularUser = $this->createApiUser([
            'organization_id' => $this->organization->id,
        ]);

        $this->domainService = Mockery::mock(DomainVerificationService::class);
        $this->app->instance(DomainVerificationService::class, $this->domainService);
    }

    protected function tearDown(): void
    {
        Mockery::close();
        parent::tearDown();
    }

    public function test_can_add_custom_domain(): void
    {
        $customDomain = CustomDomain::factory()->make([
            'organization_id' => $this->organization->id,
            'domain' => 'auth.example.com',
            'verification_code' => 'abc123xyz',
            'verification_method' => 'dns',
            'status' => 'pending',
        ]);

        $this->domainService
            ->shouldReceive('addDomain')
            ->once()
            ->with($this->organization->id, 'auth.example.com')
            ->andReturn($customDomain);

        Passport::actingAs($this->adminUser, ['enterprise.domains.manage']);

        $response = $this->postJson('/api/v1/enterprise/domains', [
            'domain' => 'auth.example.com',
        ]);

        $response->assertStatus(201)
            ->assertJsonStructure([
                'success',
                'data' => [
                    'domain',
                    'verification_code',
                    'verification_method',
                    'status',
                ],
                'message',
            ])
            ->assertJson([
                'success' => true,
                'data' => [
                    'domain' => 'auth.example.com',
                    'status' => 'pending',
                ],
            ]);
    }

    public function test_can_list_custom_domains(): void
    {
        CustomDomain::factory()->count(3)->create([
            'organization_id' => $this->organization->id,
        ]);

        Passport::actingAs($this->adminUser, ['enterprise.domains.read']);

        $response = $this->getJson('/api/v1/enterprise/domains');

        $response->assertStatus(200)
            ->assertJsonStructure([
                'success',
                'data' => [
                    '*' => [
                        'id',
                        'domain',
                        'verification_code',
                        'verification_method',
                        'status',
                        'verified_at',
                        'created_at',
                    ],
                ],
                'message',
            ])
            ->assertJsonCount(3, 'data');
    }

    public function test_can_verify_domain(): void
    {
        $domain = CustomDomain::factory()->create([
            'organization_id' => $this->organization->id,
            'domain' => 'auth.example.com',
            'verification_code' => 'abc123xyz',
            'status' => 'pending',
        ]);

        $this->domainService
            ->shouldReceive('verifyDomain')
            ->once()
            ->with($domain->id)
            ->andReturn([
                'success' => true,
                'verified' => true,
                'message' => 'Domain verified successfully',
            ]);

        Passport::actingAs($this->adminUser, ['enterprise.domains.manage']);

        $response = $this->postJson("/api/v1/enterprise/domains/{$domain->id}/verify");

        $response->assertStatus(200)
            ->assertJsonStructure([
                'success',
                'data' => [
                    'verified',
                    'message',
                ],
                'message',
            ])
            ->assertJson([
                'success' => true,
                'data' => [
                    'verified' => true,
                ],
            ]);
    }

    public function test_can_delete_domain(): void
    {
        $domain = CustomDomain::factory()->create([
            'organization_id' => $this->organization->id,
        ]);

        $this->domainService
            ->shouldReceive('removeDomain')
            ->once()
            ->with(Mockery::on(function ($arg) use ($domain) {
                return $arg instanceof CustomDomain && $arg->id === $domain->id;
            }))
            ->andReturnUsing(function ($domain) {
                return $domain->delete();
            });

        Passport::actingAs($this->adminUser, ['enterprise.domains.manage']);

        $response = $this->deleteJson("/api/v1/enterprise/domains/{$domain->id}");

        $response->assertStatus(200)
            ->assertJson([
                'success' => true,
                'message' => 'Domain deleted successfully',
            ]);

        $this->assertDatabaseMissing('custom_domains', [
            'id' => $domain->id,
        ]);
    }

    public function test_validates_domain_format(): void
    {
        Passport::actingAs($this->adminUser, ['enterprise.domains.manage']);

        $response = $this->postJson('/api/v1/enterprise/domains', [
            'domain' => 'invalid domain name',
        ]);

        $response->assertStatus(422)
            ->assertJsonValidationErrors(['domain']);
    }

    public function test_prevents_duplicate_domains(): void
    {
        CustomDomain::factory()->create([
            'organization_id' => $this->organization->id,
            'domain' => 'auth.example.com',
        ]);

        // No mock needed - validation catches duplicates before service is called

        Passport::actingAs($this->adminUser, ['enterprise.domains.manage']);

        $response = $this->postJson('/api/v1/enterprise/domains', [
            'domain' => 'auth.example.com',
        ]);

        $response->assertStatus(422)
            ->assertJsonValidationErrors(['domain']);
    }

    public function test_cannot_verify_unowned_domain(): void
    {
        $otherOrganization = Organization::factory()->create();
        $domain = CustomDomain::factory()->create([
            'organization_id' => $otherOrganization->id,
        ]);

        Passport::actingAs($this->adminUser, ['enterprise.domains.manage']);

        $response = $this->postJson("/api/v1/enterprise/domains/{$domain->id}/verify");

        $response->assertStatus(404);
    }

    public function test_cannot_delete_another_organizations_domain(): void
    {
        $otherOrganization = Organization::factory()->create();
        $domain = CustomDomain::factory()->create([
            'organization_id' => $otherOrganization->id,
        ]);

        Passport::actingAs($this->adminUser, ['enterprise.domains.manage']);

        $response = $this->deleteJson("/api/v1/enterprise/domains/{$domain->id}");

        $response->assertStatus(404);

        $this->assertDatabaseHas('custom_domains', [
            'id' => $domain->id,
        ]);
    }

    public function test_verification_fails_when_dns_record_not_found(): void
    {
        $domain = CustomDomain::factory()->create([
            'organization_id' => $this->organization->id,
            'verification_code' => 'abc123xyz',
            'status' => 'pending',
        ]);

        $this->domainService
            ->shouldReceive('verifyDomain')
            ->once()
            ->with($domain->id)
            ->andReturn([
                'success' => false,
                'verified' => false,
                'message' => 'DNS TXT record not found',
            ]);

        Passport::actingAs($this->adminUser, ['enterprise.domains.manage']);

        $response = $this->postJson("/api/v1/enterprise/domains/{$domain->id}/verify");

        $response->assertStatus(200)
            ->assertJson([
                'success' => true,
                'data' => [
                    'verified' => false,
                ],
            ]);
    }

    public function test_requires_domain_permission(): void
    {
        Passport::actingAs($this->regularUser, ['applications.read']);

        $response = $this->postJson('/api/v1/enterprise/domains', [
            'domain' => 'auth.example.com',
        ]);

        $response->assertStatus(403);
    }

    public function test_domains_disabled_for_organization_returns_error(): void
    {
        $this->organization->update([
            'settings' => [
                'enterprise_features' => [
                    'custom_domains_enabled' => false,
                ],
            ],
        ]);

        Passport::actingAs($this->adminUser, ['enterprise.domains.manage']);

        $response = $this->postJson('/api/v1/enterprise/domains', [
            'domain' => 'auth.example.com',
        ]);

        $response->assertStatus(403)
            ->assertJson([
                'success' => false,
                'error' => 'feature_disabled',
            ]);
    }
}
