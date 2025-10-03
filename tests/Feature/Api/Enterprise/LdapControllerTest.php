<?php

namespace Tests\Feature\Api\Enterprise;

use App\Models\Organization;
use App\Models\User;
use App\Services\LdapAuthService;
use Laravel\Passport\Passport;
use Mockery;
use Spatie\Permission\Models\Role;
use Tests\TestCase;

class LdapControllerTest extends TestCase
{
    private Organization $organization;

    private User $adminUser;

    private User $regularUser;

    private LdapAuthService $ldapService;

    protected function setUp(): void
    {
        parent::setUp();

        $this->organization = Organization::factory()->create([
            'settings' => [
                'enterprise_features' => [
                    'ldap_enabled' => true,
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

        // Create an LDAP configuration for the organization
        \App\Models\LdapConfiguration::create([
            'organization_id' => $this->organization->id,
            'name' => 'Test LDAP Config',
            'host' => 'ldap.test.com',
            'port' => 389,
            'base_dn' => 'dc=test,dc=com',
            'username' => 'cn=admin,dc=test,dc=com',
            'password' => 'password',
            'is_active' => true,
        ]);

        $this->ldapService = Mockery::mock(LdapAuthService::class);
        $this->app->instance(LdapAuthService::class, $this->ldapService);
    }

    protected function tearDown(): void
    {
        Mockery::close();
        parent::tearDown();
    }

    public function test_can_test_ldap_connection(): void
    {
        $this->ldapService
            ->shouldReceive('testConnection')
            ->once()
            ->with(Mockery::on(function ($config) {
                return $config instanceof \App\Models\LdapConfiguration
                    && $config->host === 'ldap.example.com'
                    && $config->port === 389
                    && $config->base_dn === 'dc=example,dc=com'
                    && $config->username === 'cn=admin,dc=example,dc=com'
                    && $config->password === 'secret';
            }))
            ->andReturn([
                'success' => true,
                'message' => 'Connection successful',
                'user_count' => 10,
            ]);

        Passport::actingAs($this->adminUser, ['enterprise.ldap.manage']);

        $response = $this->postJson('/api/v1/enterprise/ldap/test', [
            'host' => 'ldap.example.com',
            'port' => 389,
            'base_dn' => 'dc=example,dc=com',
            'bind_dn' => 'cn=admin,dc=example,dc=com',
            'bind_password' => 'secret',
        ]);

        $response->assertStatus(200)
            ->assertJsonStructure([
                'success',
                'data' => [
                    'connection_status',
                    'message',
                ],
                'message',
            ])
            ->assertJson([
                'success' => true,
                'data' => [
                    'connection_status' => 'success',
                ],
            ]);
    }

    public function test_cannot_test_connection_with_invalid_credentials(): void
    {
        $this->ldapService
            ->shouldReceive('testConnection')
            ->once()
            ->with(Mockery::type(\App\Models\LdapConfiguration::class))
            ->andReturn([
                'success' => false,
                'message' => 'Invalid credentials',
            ]);

        Passport::actingAs($this->adminUser, ['enterprise.ldap.manage']);

        $response = $this->postJson('/api/v1/enterprise/ldap/test', [
            'host' => 'ldap.example.com',
            'port' => 389,
            'base_dn' => 'dc=example,dc=com',
            'bind_dn' => 'cn=admin,dc=example,dc=com',
            'bind_password' => 'wrong',
        ]);

        $response->assertStatus(200)
            ->assertJson([
                'success' => true,
                'data' => [
                    'connection_status' => 'failed',
                ],
            ]);
    }

    public function test_validates_ldap_configuration_data(): void
    {
        Passport::actingAs($this->adminUser, ['enterprise.ldap.manage']);

        $response = $this->postJson('/api/v1/enterprise/ldap/test', [
            'host' => '',
            'port' => 'invalid',
        ]);

        $response->assertStatus(422)
            ->assertJsonStructure([
                'success',
                'error',
                'error_description',
                'errors' => [
                    'host',
                    'port',
                    'base_dn',
                    'bind_dn',
                    'bind_password',
                ],
            ]);
    }

    public function test_can_configure_ldap(): void
    {
        Passport::actingAs($this->adminUser, ['enterprise.ldap.manage']);

        $response = $this->postJson('/api/v1/enterprise/ldap/configure', [
            'host' => 'ldap.example.com',
            'port' => 389,
            'base_dn' => 'dc=example,dc=com',
            'bind_dn' => 'cn=admin,dc=example,dc=com',
            'bind_password' => 'secret',
            'user_filter' => '(objectClass=person)',
            'username_attribute' => 'uid',
            'email_attribute' => 'mail',
            'name_attribute' => 'cn',
        ]);

        $response->assertStatus(200)
            ->assertJsonStructure([
                'success',
                'data' => [
                    'ldap_config',
                ],
                'message',
            ]);

        $this->assertDatabaseHas('organizations', [
            'id' => $this->organization->id,
        ]);

        $config = $this->organization->fresh()->settings['ldap_config'] ?? null;
        $this->assertNotNull($config);
        $this->assertEquals('ldap.example.com', $config['host']);
    }

    public function test_can_sync_users(): void
    {
        $this->ldapService
            ->shouldReceive('syncUsers')
            ->once()
            ->with(
                Mockery::type(\App\Models\LdapConfiguration::class),
                Mockery::type(\App\Models\Organization::class)
            )
            ->andReturn([
                'success' => true,
                'created' => 5,
                'updated' => 3,
                'failed' => 0,
            ]);

        Passport::actingAs($this->adminUser, ['enterprise.ldap.manage']);

        $response = $this->postJson('/api/v1/enterprise/ldap/sync');

        $response->assertStatus(200)
            ->assertJsonStructure([
                'success',
                'data' => [
                    'sync_results' => [
                        'created',
                        'updated',
                        'failed',
                    ],
                ],
                'message',
            ])
            ->assertJson([
                'success' => true,
                'data' => [
                    'sync_results' => [
                        'created' => 5,
                        'updated' => 3,
                        'failed' => 0,
                    ],
                ],
            ]);
    }

    public function test_can_list_ldap_users(): void
    {
        $this->ldapService
            ->shouldReceive('getUsersFromLdap')
            ->once()
            ->with(
                Mockery::type(\App\Models\LdapConfiguration::class),
                100
            )
            ->andReturn([
                [
                    'username' => 'john.doe',
                    'email' => 'john@example.com',
                    'name' => 'John Doe',
                    'dn' => 'cn=john.doe,dc=example,dc=com',
                ],
                [
                    'username' => 'jane.smith',
                    'email' => 'jane@example.com',
                    'name' => 'Jane Smith',
                    'dn' => 'cn=jane.smith,dc=example,dc=com',
                ],
            ]);

        Passport::actingAs($this->adminUser, ['enterprise.ldap.manage']);

        $response = $this->getJson('/api/v1/enterprise/ldap/users');

        $response->assertStatus(200)
            ->assertJsonStructure([
                'success',
                'data' => [
                    '*' => [
                        'username',
                        'email',
                        'name',
                        'dn',
                    ],
                ],
                'message',
            ])
            ->assertJsonCount(2, 'data');
    }

    public function test_cannot_access_another_organizations_ldap(): void
    {
        $otherOrganization = Organization::factory()->create([
            'settings' => [
                'enterprise_features' => [
                    'ldap_enabled' => true,
                ],
            ],
        ]);
        $otherAdmin = $this->createApiOrganizationAdmin([
            'organization_id' => $otherOrganization->id,
        ]);

        // Create LDAP config for other organization
        \App\Models\LdapConfiguration::create([
            'organization_id' => $otherOrganization->id,
            'name' => 'Other LDAP Config',
            'host' => 'ldap.other.com',
            'port' => 389,
            'base_dn' => 'dc=other,dc=com',
            'username' => 'cn=admin,dc=other,dc=com',
            'password' => 'password',
            'is_active' => true,
        ]);

        // Should only sync their own organization's users
        $this->ldapService
            ->shouldReceive('syncUsers')
            ->once()
            ->with(
                Mockery::type(\App\Models\LdapConfiguration::class),
                Mockery::type(\App\Models\Organization::class)
            )
            ->andReturn([
                'success' => true,
                'created' => 0,
                'updated' => 0,
                'failed' => 0,
            ]);

        Passport::actingAs($otherAdmin, ['enterprise.ldap.manage']);

        $response = $this->postJson('/api/v1/enterprise/ldap/sync');

        $response->assertStatus(200);
    }

    public function test_requires_ldap_permission(): void
    {
        Passport::actingAs($this->regularUser, ['applications.read']);

        $response = $this->postJson('/api/v1/enterprise/ldap/test', [
            'host' => 'ldap.example.com',
            'port' => 389,
            'base_dn' => 'dc=example,dc=com',
            'bind_dn' => 'cn=admin,dc=example,dc=com',
            'bind_password' => 'secret',
        ]);

        $response->assertStatus(403);
    }

    public function test_ldap_disabled_for_organization_returns_error(): void
    {
        $this->organization->update([
            'settings' => [
                'enterprise_features' => [
                    'ldap_enabled' => false,
                ],
            ],
        ]);

        Passport::actingAs($this->adminUser, ['enterprise.ldap.manage']);

        $response = $this->postJson('/api/v1/enterprise/ldap/test', [
            'host' => 'ldap.example.com',
            'port' => 389,
            'base_dn' => 'dc=example,dc=com',
            'bind_dn' => 'cn=admin,dc=example,dc=com',
            'bind_password' => 'secret',
        ]);

        $response->assertStatus(403)
            ->assertJson([
                'success' => false,
                'error' => 'feature_disabled',
            ]);
    }
}
