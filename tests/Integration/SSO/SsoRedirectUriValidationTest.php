<?php

namespace Tests\Integration\SSO;

use App\Models\SSOConfiguration;
use App\Models\User;
use PHPUnit\Framework\Attributes\Test;
use Tests\Integration\IntegrationTestCase;

class SsoRedirectUriValidationTest extends IntegrationTestCase
{
    private const CALLBACK_URL = 'https://app.example.com/sso/callback';

    #[Test]
    public function it_rejects_an_arbitrary_redirect_uri_when_no_domains_are_allowed_with_422(): void
    {
        [$user, $config] = $this->createUserWithSsoConfiguration();

        $response = $this->initiate($user, $config, 'https://attacker.example.net/steal');

        $response->assertUnprocessable()->assertJsonPath('errors.redirect_uri.0', 'Invalid redirect URI for this SSO configuration');
        $this->assertDatabaseMissing('sso_sessions', ['user_id' => $user->id]);
    }

    #[Test]
    public function it_accepts_the_configured_callback_url_when_no_domains_are_allowed(): void
    {
        [$user, $config] = $this->createUserWithSsoConfiguration();

        $response = $this->initiate($user, $config, self::CALLBACK_URL);

        $response->assertOk();
        $this->assertDatabaseHas('sso_sessions', ['user_id' => $user->id]);
    }

    #[Test]
    public function it_rejects_a_plain_http_redirect_uri_on_an_allowed_domain_with_422(): void
    {
        [$user, $config] = $this->createUserWithSsoConfiguration(['allowed.example.com']);

        $response = $this->initiate($user, $config, 'http://allowed.example.com/cb');

        $response->assertUnprocessable()->assertJsonValidationErrors('redirect_uri');
        $this->assertDatabaseMissing('sso_sessions', ['user_id' => $user->id]);
    }

    #[Test]
    public function it_accepts_an_https_redirect_uri_on_an_allowed_domain(): void
    {
        [$user, $config] = $this->createUserWithSsoConfiguration(['allowed.example.com']);

        $this->initiate($user, $config, 'https://allowed.example.com/cb')->assertOk();
    }

    #[Test]
    public function it_does_not_let_hard_coded_test_domains_bypass_allowed_domains(): void
    {
        [$user, $config] = $this->createUserWithSsoConfiguration(['allowed.example.com']);

        $this->initiate($user, $config, 'https://app-a.example.com/cb')->assertUnprocessable();
        $this->initiate($user, $config, 'http://localhost/cb')->assertUnprocessable();
    }

    #[Test]
    public function it_accepts_plain_http_on_localhost_outside_production_when_allowed(): void
    {
        [$user, $config] = $this->createUserWithSsoConfiguration(['localhost']);

        $this->initiate($user, $config, 'http://localhost:8080/cb')->assertOk();
    }

    #[Test]
    public function it_rejects_an_sso_configuration_of_another_application_with_422(): void
    {
        [$user, $config] = $this->createUserWithSsoConfiguration();
        $otherApplication = $this->createOAuthApplication(['organization_id' => $user->organization_id]);
        $user->applications()->attach($otherApplication->id, ['granted_at' => now()]);

        $response = $this->actingAsApiUserWithToken($user, ['sso'])
            ->postJson('/api/v1/sso/initiate', [
                'application_id' => $otherApplication->id,
                'sso_configuration_id' => $config->id,
                'redirect_uri' => self::CALLBACK_URL,
            ]);

        $response->assertUnprocessable()->assertJsonValidationErrors('sso_configuration_id');
        $this->assertDatabaseMissing('sso_sessions', ['user_id' => $user->id]);
    }

    /**
     * @return array{User, SSOConfiguration}
     */
    private function createUserWithSsoConfiguration(array $allowedDomains = []): array
    {
        $user = $this->createApiUser();
        $application = $this->createOAuthApplication(['organization_id' => $user->organization_id]);
        $user->applications()->attach($application->id, ['granted_at' => now()]);

        $config = SSOConfiguration::factory()->create([
            'application_id' => $application->id,
            'provider' => 'oidc',
            'callback_url' => self::CALLBACK_URL,
            'allowed_domains' => $allowedDomains,
            'is_active' => true,
        ]);

        return [$user, $config];
    }

    private function initiate(User $user, SSOConfiguration $config, string $redirectUri)
    {
        return $this->actingAsApiUserWithToken($user, ['sso'])
            ->postJson('/api/v1/sso/initiate', [
                'application_id' => $config->application_id,
                'sso_configuration_id' => $config->id,
                'redirect_uri' => $redirectUri,
            ]);
    }
}
