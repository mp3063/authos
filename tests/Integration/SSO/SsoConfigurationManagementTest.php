<?php

namespace Tests\Integration\SSO;

use App\Models\SSOConfiguration;
use App\Models\User;
use PHPUnit\Framework\Attributes\Test;
use Tests\Integration\IntegrationTestCase;

class SsoConfigurationManagementTest extends IntegrationTestCase
{
    private const CALLBACK_URL = 'https://app.example.com/callback';

    #[Test]
    public function it_returns_the_configuration_without_the_client_secret(): void
    {
        $admin = $this->createApiOrganizationAdmin();
        $this->createSsoConfiguration($admin, [
            'configuration' => ['client_id' => 'client-123', 'client_secret' => 'top-secret'],
        ]);

        $response = $this->actingAsApiUserWithToken($admin, ['sso'])
            ->getJson("/api/v1/sso/configurations/{$admin->organization_id}");

        $response->assertOk()->assertJsonPath('configuration.client_id', 'client-123');
        $this->assertStringNotContainsString('top-secret', $response->getContent());
    }

    #[Test]
    public function it_strips_keys_ending_in_a_sensitive_word_from_the_configuration(): void
    {
        $admin = $this->createApiOrganizationAdmin();
        $this->createSsoConfiguration($admin, [
            'configuration' => [
                'client_id' => 'client-123',
                'sp_private_key' => 'private-key-value',
                'bind_password' => 'bind-password-value',
                'spApiKey' => 'api-key-value',
                'password_min_length' => 12,
                'has_password' => true,
            ],
        ]);

        $response = $this->actingAsApiUserWithToken($admin, ['sso'])
            ->getJson("/api/v1/sso/configurations/{$admin->organization_id}");

        $response->assertOk()
            ->assertJsonPath('configuration.password_min_length', 12)
            ->assertJsonPath('configuration.has_password', true);
        $this->assertStringNotContainsString('private-key-value', $response->getContent());
        $this->assertStringNotContainsString('bind-password-value', $response->getContent());
        $this->assertStringNotContainsString('api-key-value', $response->getContent());
    }

    #[Test]
    public function it_rejects_creating_a_configuration_for_another_organizations_application_with_422(): void
    {
        $admin = $this->createApiOrganizationAdmin();
        $foreignApplication = $this->createOAuthApplication();

        $response = $this->actingAsApiUserWithToken($admin, ['sso'])
            ->postJson('/api/v1/sso/configurations', [
                'application_id' => $foreignApplication->id,
                'logout_url' => 'https://attacker.example.com/logout',
                'callback_url' => 'https://attacker.example.com/callback',
            ]);

        $response->assertUnprocessable()->assertJsonValidationErrors(['application_id' => 'The selected application id is invalid.']);
        $this->assertDatabaseMissing('sso_configurations', ['application_id' => $foreignApplication->id]);
    }

    #[Test]
    public function it_hides_another_organizations_configuration_from_update_with_404(): void
    {
        $config = $this->createSsoConfiguration($this->createApiOrganizationAdmin());
        $otherAdmin = $this->createApiOrganizationAdmin();

        $response = $this->actingAsApiUserWithToken($otherAdmin, ['sso'])
            ->putJson("/api/v1/sso/configurations/{$config->id}", ['callback_url' => 'https://attacker.example.com/callback']);

        $response->assertNotFound();
        $this->assertSame(self::CALLBACK_URL, $config->fresh()->callback_url);
    }

    #[Test]
    public function it_hides_another_organizations_configuration_from_delete_with_404(): void
    {
        $config = $this->createSsoConfiguration($this->createApiOrganizationAdmin());
        $otherAdmin = $this->createApiOrganizationAdmin();

        $response = $this->actingAsApiUserWithToken($otherAdmin, ['sso'])
            ->deleteJson("/api/v1/sso/configurations/{$config->id}");

        $response->assertNotFound();
        $this->assertModelExists($config);
    }

    #[Test]
    public function it_forbids_a_regular_member_from_updating_the_configuration_with_403(): void
    {
        $member = $this->createApiUser();
        $config = $this->createSsoConfiguration($member);

        $response = $this->actingAsApiUserWithToken($member, ['sso'])
            ->putJson("/api/v1/sso/configurations/{$config->id}", ['callback_url' => 'https://attacker.example.com/callback']);

        $response->assertForbidden();
        $this->assertSame(self::CALLBACK_URL, $config->fresh()->callback_url);
    }

    #[Test]
    public function it_lets_an_organization_admin_update_their_configuration(): void
    {
        $admin = $this->createApiOrganizationAdmin();
        $config = $this->createSsoConfiguration($admin);

        $response = $this->actingAsApiUserWithToken($admin, ['sso'])
            ->putJson("/api/v1/sso/configurations/{$config->id}", ['callback_url' => 'https://app.example.com/new-callback']);

        $response->assertOk()->assertJsonPath('callback_url', 'https://app.example.com/new-callback');
        $this->assertSame('https://app.example.com/new-callback', $config->fresh()->callback_url);
    }

    /**
     * @param  array<string, mixed>  $attributes
     */
    private function createSsoConfiguration(User $organizationMember, array $attributes = []): SSOConfiguration
    {
        $application = $this->createOAuthApplication(['organization_id' => $organizationMember->organization_id]);

        return SSOConfiguration::factory()->create([
            'application_id' => $application->id,
            'callback_url' => self::CALLBACK_URL,
            'is_active' => true,
            ...$attributes,
        ]);
    }
}
