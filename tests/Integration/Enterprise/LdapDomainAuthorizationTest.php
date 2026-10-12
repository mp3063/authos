<?php

namespace Tests\Integration\Enterprise;

use App\Models\CustomDomain;
use App\Models\LdapConfiguration;
use PHPUnit\Framework\Attributes\Test;
use Tests\Integration\IntegrationTestCase;

class LdapDomainAuthorizationTest extends IntegrationTestCase
{
    /**
     * @return array<string, mixed>
     */
    private function ldapPayload(): array
    {
        return [
            'host' => 'ldap.example.com',
            'port' => 389,
            'base_dn' => 'dc=example,dc=com',
            'username' => 'cn=admin,dc=example,dc=com',
            'password' => 'secret',
        ];
    }

    #[Test]
    public function it_requires_auth_logs_read_to_list_domains(): void
    {
        $member = $this->createApiUser();
        CustomDomain::factory()->create(['organization_id' => $member->organization_id]);
        $this->actingAsApiUserWithToken($member);

        $this->getJson('/api/v1/enterprise/domains')->assertForbidden();
    }

    #[Test]
    public function it_lists_only_own_organization_domains_for_roles_holding_auth_logs_read(): void
    {
        $admin = $this->createApiOrganizationAdmin();
        $own = CustomDomain::factory()->create(['organization_id' => $admin->organization_id]);
        CustomDomain::factory()->create();
        $this->actingAsApiUserWithToken($admin);

        $response = $this->getJson('/api/v1/enterprise/domains')->assertOk();

        $this->assertSame([$own->id], collect($response->json('data'))->pluck('id')->all());
    }

    #[Test]
    public function it_refuses_domain_writes_to_an_organization_admin(): void
    {
        $admin = $this->createApiOrganizationAdmin();
        $domain = CustomDomain::factory()->create(['organization_id' => $admin->organization_id]);
        $this->actingAsApiUserWithToken($admin);

        $this->postJson('/api/v1/enterprise/domains', ['domain' => 'new.example.com'])->assertForbidden();
        $this->postJson("/api/v1/enterprise/domains/{$domain->id}/verify")->assertForbidden();
        $this->deleteJson("/api/v1/enterprise/domains/{$domain->id}")->assertForbidden();

        $this->assertModelExists($domain);
        $this->assertDatabaseMissing('custom_domains', ['domain' => 'new.example.com']);
    }

    #[Test]
    public function it_hides_another_organizations_domain_from_the_owner_with_404(): void
    {
        $owner = $this->createApiOrganizationOwner();
        $foreign = CustomDomain::factory()->create();
        $this->actingAsApiUserWithToken($owner);

        $this->postJson("/api/v1/enterprise/domains/{$foreign->id}/verify")->assertNotFound();
        $this->deleteJson("/api/v1/enterprise/domains/{$foreign->id}")->assertNotFound();

        $this->assertModelExists($foreign);
    }

    #[Test]
    public function it_lets_the_owner_add_and_remove_a_domain(): void
    {
        $owner = $this->createApiOrganizationOwner();
        $this->actingAsApiUserWithToken($owner);

        $this->postJson('/api/v1/enterprise/domains', ['domain' => 'auth.example.com'])->assertCreated();
        $domain = CustomDomain::where('domain', 'auth.example.com')->firstOrFail();
        $this->assertSame($owner->organization_id, $domain->organization_id);

        $this->deleteJson("/api/v1/enterprise/domains/{$domain->id}")->assertOk();
        $this->assertModelMissing($domain);
    }

    #[Test]
    public function it_lets_a_super_admin_remove_any_organizations_domain(): void
    {
        $superAdmin = $this->createApiSuperAdmin();
        $foreign = CustomDomain::factory()->create();
        $this->actingAsApiUserWithToken($superAdmin);

        $this->deleteJson("/api/v1/enterprise/domains/{$foreign->id}")->assertOk();

        $this->assertModelMissing($foreign);
    }

    #[Test]
    public function it_refuses_ldap_management_to_roles_without_organizations_update(): void
    {
        foreach (['Organization Admin', 'Auditor', 'User'] as $role) {
            $user = $this->createUser([], $role, 'api');
            $this->actingAsApiUserWithToken($user);

            $this->postJson('/api/v1/enterprise/ldap/configure', $this->ldapPayload())->assertForbidden();
            $this->postJson('/api/v1/enterprise/ldap/test', $this->ldapPayload())->assertForbidden();
            $this->postJson('/api/v1/enterprise/ldap/sync')->assertForbidden();
            $this->getJson('/api/v1/enterprise/ldap/users')->assertForbidden();

            $this->assertDatabaseMissing('ldap_configurations', ['organization_id' => $user->organization_id]);
        }
    }

    #[Test]
    public function it_lets_the_owner_configure_ldap_for_their_own_organization_only(): void
    {
        $owner = $this->createApiOrganizationOwner();
        $own = LdapConfiguration::factory()->create(['organization_id' => $owner->organization_id]);
        $foreignConfig = LdapConfiguration::factory()->create(['organization_id' => $this->createOrganization()->id]);
        $this->actingAsApiUserWithToken($owner);

        $this->postJson('/api/v1/enterprise/ldap/configure', $this->ldapPayload())->assertOk();

        $this->assertSame('ldap.example.com', $own->fresh()->host);
        $this->assertNotSame('ldap.example.com', $foreignConfig->fresh()->host);
    }

    #[Test]
    public function it_refuses_ldap_management_to_a_user_without_an_organization(): void
    {
        $owner = $this->createApiOrganizationOwner();
        $owner->forceFill(['organization_id' => null])->save();
        $this->actingAsApiUserWithToken($owner->fresh());

        $this->postJson('/api/v1/enterprise/ldap/configure', $this->ldapPayload())->assertForbidden();

        $this->assertDatabaseMissing('ldap_configurations', ['host' => 'ldap.example.com']);
    }
}
