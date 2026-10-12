<?php

namespace Tests\Integration\SSO;

use App\Models\SSOConfiguration;
use App\Models\User;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use Tests\Integration\IntegrationTestCase;

class SsoAuthorizationTest extends IntegrationTestCase
{
    private const CALLBACK_URL = 'https://app.example.com/callback';

    /**
     * @return array<string, array{string, string, array<string, string>}>
     */
    public static function writeEndpoints(): array
    {
        return [
            'update configuration' => ['put', '/api/v1/sso/configurations/{id}', ['callback_url' => 'https://attacker.example.com/cb']],
            'delete configuration' => ['delete', '/api/v1/sso/configurations/{id}', []],
            'upload certificate' => ['post', '/api/v1/sso/saml/certificates/{id}', ['x509_cert' => 'attacker-cert']],
            'rotate certificate' => ['post', '/api/v1/sso/saml/certificates/{id}/rotate', ['new_x509_cert' => 'attacker-cert']],
        ];
    }

    #[Test]
    #[DataProvider('writeEndpoints')]
    public function it_refuses_writes_to_an_organization_admin(string $method, string $url, array $payload): void
    {
        $admin = $this->createApiOrganizationAdmin();
        $config = $this->createConfiguration($admin);

        $this->actingAsApiUserWithToken($admin, ['sso'])
            ->json($method, str_replace('{id}', (string) $config->id, $url), $payload)
            ->assertForbidden();

        $this->assertModelExists($config);
        $this->assertSame(self::CALLBACK_URL, $config->fresh()->callback_url);
        $this->assertArrayNotHasKey('x509_cert', $config->fresh()->configuration ?? []);
    }

    #[Test]
    #[DataProvider('writeEndpoints')]
    public function it_refuses_writes_to_an_application_manager(string $method, string $url, array $payload): void
    {
        $manager = $this->createUser([], 'Application Manager', 'api');
        $config = $this->createConfiguration($manager);

        $this->actingAsApiUserWithToken($manager, ['sso'])
            ->json($method, str_replace('{id}', (string) $config->id, $url), $payload)
            ->assertForbidden();

        $this->assertModelExists($config);
        $this->assertSame(self::CALLBACK_URL, $config->fresh()->callback_url);
    }

    #[Test]
    public function it_refuses_creating_a_configuration_to_an_organization_admin(): void
    {
        $admin = $this->createApiOrganizationAdmin();
        $application = $this->createOAuthApplication(['organization_id' => $admin->organization_id]);

        $this->actingAsApiUserWithToken($admin, ['sso'])
            ->postJson('/api/v1/sso/configurations', [
                'application_id' => $application->id,
                'logout_url' => 'https://app.example.com/logout',
                'callback_url' => self::CALLBACK_URL,
                'allowed_domains' => ['example.com'],
            ])
            ->assertForbidden();

        $this->assertDatabaseMissing('sso_configurations', ['application_id' => $application->id]);
    }

    #[Test]
    public function it_lets_the_organization_owner_create_update_and_delete_a_configuration(): void
    {
        $owner = $this->createApiOrganizationOwner();
        $application = $this->createOAuthApplication(['organization_id' => $owner->organization_id]);
        $this->actingAsApiUserWithToken($owner, ['sso']);

        $created = $this->postJson('/api/v1/sso/configurations', [
            'application_id' => $application->id,
            'logout_url' => 'https://app.example.com/logout',
            'callback_url' => self::CALLBACK_URL,
            'allowed_domains' => ['example.com'],
        ])->assertCreated();
        $id = $created->json('id');

        $this->putJson("/api/v1/sso/configurations/{$id}", ['callback_url' => 'https://app.example.com/new'])->assertOk();
        $this->deleteJson("/api/v1/sso/configurations/{$id}")->assertOk();
    }

    #[Test]
    public function it_requires_auth_logs_read_to_view_the_configuration_and_certificates(): void
    {
        $member = $this->createApiUser();
        $config = $this->createConfiguration($member, ['configuration' => ['x509_cert' => 'cert']]);
        $this->actingAsApiUserWithToken($member, ['sso']);

        $this->getJson("/api/v1/sso/configurations/{$member->organization_id}")->assertForbidden();
        $this->getJson("/api/v1/sso/saml/certificates/{$config->id}")->assertForbidden();
    }

    #[Test]
    public function it_lets_an_auditor_view_but_not_write(): void
    {
        $auditor = $this->createUser([], 'Auditor', 'api');
        $config = $this->createConfiguration($auditor, ['configuration' => ['x509_cert' => 'cert']]);
        $this->actingAsApiUserWithToken($auditor, ['sso']);

        $this->getJson("/api/v1/sso/configurations/{$auditor->organization_id}")->assertOk();
        $this->getJson("/api/v1/sso/saml/certificates/{$config->id}")->assertOk();
        $this->putJson("/api/v1/sso/configurations/{$config->id}", ['callback_url' => 'https://app.example.com/new'])->assertForbidden();
    }

    #[Test]
    public function it_refuses_viewing_another_organizations_configuration_with_403(): void
    {
        $owner = $this->createApiOrganizationOwner();
        $foreign = $this->createConfiguration($this->createApiOrganizationOwner());

        $this->actingAsApiUserWithToken($owner, ['sso'])
            ->getJson('/api/v1/sso/configurations/'.$foreign->application->organization_id)
            ->assertForbidden();
    }

    #[Test]
    public function it_refuses_a_user_without_an_organization(): void
    {
        $owner = $this->createApiOrganizationOwner();
        $global = $this->createConfiguration($owner);
        $owner->forceFill(['organization_id' => null])->save();

        $this->actingAsApiUserWithToken($owner->fresh(), ['sso'])
            ->putJson("/api/v1/sso/configurations/{$global->id}", ['callback_url' => 'https://attacker.example.com/cb'])
            ->assertNotFound();

        $this->assertSame(self::CALLBACK_URL, $global->fresh()->callback_url);
    }

    #[Test]
    public function it_lets_a_super_admin_manage_any_configuration(): void
    {
        $superAdmin = $this->createApiSuperAdmin();
        $config = $this->createConfiguration($this->createApiOrganizationOwner());

        $this->actingAsApiUserWithToken($superAdmin, ['sso'])
            ->putJson("/api/v1/sso/configurations/{$config->id}", ['callback_url' => 'https://app.example.com/new'])
            ->assertOk();
    }

    /**
     * @param  array<string, mixed>  $attributes
     */
    private function createConfiguration(User $member, array $attributes = []): SSOConfiguration
    {
        $application = $this->createOAuthApplication(['organization_id' => $member->organization_id]);

        return SSOConfiguration::factory()->create([
            'application_id' => $application->id,
            'callback_url' => self::CALLBACK_URL,
            'is_active' => true,
            ...$attributes,
        ]);
    }
}
