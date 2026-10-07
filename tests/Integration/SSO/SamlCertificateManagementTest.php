<?php

namespace Tests\Integration\SSO;

use App\Models\SSOConfiguration;
use App\Models\User;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use Tests\Integration\IntegrationTestCase;

class SamlCertificateManagementTest extends IntegrationTestCase
{
    private const ORIGINAL_CERT = 'original-idp-certificate';

    private const NEW_CERT = 'attacker-idp-certificate';

    /**
     * @return array<string, array{string, string, array<string, string>}>
     */
    public static function certificateEndpoints(): array
    {
        return [
            'view' => ['get', '', []],
            'update' => ['post', '', ['x509_cert' => self::NEW_CERT]],
            'rotate' => ['post', '/rotate', ['new_x509_cert' => self::NEW_CERT]],
        ];
    }

    #[Test]
    #[DataProvider('certificateEndpoints')]
    public function it_hides_another_organizations_configuration_with_404(string $method, string $suffix, array $payload): void
    {
        $config = $this->createSamlConfiguration($this->createUser());
        $otherOwner = $this->createUser([], 'Organization Owner', 'api');

        $response = $this->actingAsApiUserWithToken($otherOwner, ['sso'])
            ->json($method, "/api/v1/sso/saml/certificates/{$config->id}{$suffix}", $payload);

        $response->assertNotFound();
        $this->assertSame(self::ORIGINAL_CERT, $config->fresh()->configuration['x509_cert']);
    }

    #[Test]
    public function it_forbids_a_regular_member_from_replacing_the_idp_certificate_with_403(): void
    {
        $member = $this->createApiUser();
        $config = $this->createSamlConfiguration($member);

        $response = $this->actingAsApiUserWithToken($member, ['sso'])
            ->postJson("/api/v1/sso/saml/certificates/{$config->id}", ['x509_cert' => self::NEW_CERT]);

        $response->assertForbidden();
        $this->assertSame(self::ORIGINAL_CERT, $config->fresh()->configuration['x509_cert']);
    }

    #[Test]
    public function it_lets_the_organization_owner_replace_the_idp_certificate(): void
    {
        $owner = $this->createUser([], 'Organization Owner', 'api');
        $config = $this->createSamlConfiguration($owner);

        $response = $this->actingAsApiUserWithToken($owner, ['sso'])
            ->postJson("/api/v1/sso/saml/certificates/{$config->id}", ['x509_cert' => self::NEW_CERT]);

        $response->assertOk()->assertJsonPath('cert_type', 'idp');
        $this->assertSame(self::NEW_CERT, $config->fresh()->configuration['x509_cert']);
    }

    #[Test]
    public function it_lets_an_organization_admin_view_certificates(): void
    {
        $admin = $this->createApiOrganizationAdmin();
        $config = $this->createSamlConfiguration($admin);

        $response = $this->actingAsApiUserWithToken($admin, ['sso'])
            ->getJson("/api/v1/sso/saml/certificates/{$config->id}");

        $response->assertOk()->assertJsonPath('certificates.0.type', 'idp');
    }

    private function createSamlConfiguration(User $organizationMember): SSOConfiguration
    {
        $application = $this->createOAuthApplication(['organization_id' => $organizationMember->organization_id]);

        return SSOConfiguration::factory()->create([
            'application_id' => $application->id,
            'provider' => 'saml2',
            'configuration' => ['x509_cert' => self::ORIGINAL_CERT],
        ]);
    }
}
