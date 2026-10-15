<?php

namespace Tests\Integration\Security;

use App\Models\CustomDomain;
use App\Models\Organization;
use App\Models\SSOConfiguration;
use App\Models\Webhook;
use PHPUnit\Framework\Attributes\Test;
use Tests\Integration\IntegrationTestCase;

class ExistenceOracleTest extends IntegrationTestCase
{
    private function foreignSsoConfiguration(): SSOConfiguration
    {
        $application = $this->createOAuthApplication([], $this->createOrganization());

        return SSOConfiguration::factory()->create(['application_id' => $application->id]);
    }

    #[Test]
    public function it_answers_an_unknown_and_a_foreign_sso_configuration_alike_for_a_caller_without_the_ability(): void
    {
        $member = $this->createApiUser();
        $foreign = $this->foreignSsoConfiguration();
        $this->actingAsApiUserWithToken($member);

        $this->putJson("/api/v1/sso/configurations/{$foreign->id}", [])->assertForbidden();
        $this->putJson('/api/v1/sso/configurations/999999', [])->assertForbidden();
        $this->deleteJson("/api/v1/sso/configurations/{$foreign->id}")->assertForbidden();
        $this->deleteJson('/api/v1/sso/configurations/999999')->assertForbidden();
    }

    #[Test]
    public function it_answers_an_unknown_and_a_foreign_organization_alike_when_reading_sso_configuration_without_the_ability(): void
    {
        $member = $this->createApiUser();
        $foreign = $this->createOrganization();
        $this->actingAsApiUserWithToken($member);

        $this->getJson("/api/v1/sso/configurations/{$foreign->id}")->assertForbidden();
        $this->getJson('/api/v1/sso/configurations/999999')->assertForbidden();
    }

    #[Test]
    public function it_answers_an_unknown_and_a_foreign_organization_alike_when_reading_sso_configuration_with_auth_logs_read(): void
    {
        $admin = $this->createApiOrganizationAdmin();
        $foreign = $this->createOrganization();
        $this->actingAsApiUserWithToken($admin, ['sso']);

        $this->getJson("/api/v1/sso/configurations/{$foreign->id}")->assertForbidden();
        $this->getJson('/api/v1/sso/configurations/999999')->assertForbidden();
    }

    #[Test]
    public function it_returns_not_found_for_an_unknown_sso_configuration_only_after_authorization(): void
    {
        $owner = $this->createApiOrganizationOwner();
        $this->actingAsApiUserWithToken($owner);

        $this->putJson('/api/v1/sso/configurations/999999', [])->assertNotFound();
    }

    #[Test]
    public function it_does_not_echo_exception_text_from_sso_configuration_lookup(): void
    {
        $owner = $this->createApiOrganizationOwner();
        $this->actingAsApiUserWithToken($owner);
        $application = $this->createOAuthApplication(['organization_id' => $owner->organization_id]);
        $config = SSOConfiguration::factory()->create(['application_id' => $application->id]);

        SSOConfiguration::deleting(fn () => throw new \RuntimeException('SQLSTATE secret detail'));

        $response = $this->deleteJson("/api/v1/sso/configurations/{$config->id}");

        $response->assertNotFound();
        $this->assertStringNotContainsString('secret detail', $response->getContent());
    }

    #[Test]
    public function it_answers_an_unknown_and_a_foreign_organization_alike_for_branding_without_the_ability(): void
    {
        $member = $this->createApiUser();
        $foreign = $this->createOrganization();
        $this->actingAsApiUserWithToken($member);

        $this->getJson("/api/v1/enterprise/organizations/{$foreign->id}/branding")->assertForbidden();
        $this->getJson('/api/v1/enterprise/organizations/999999/branding')->assertForbidden();
        $this->putJson("/api/v1/enterprise/organizations/{$foreign->id}/branding", [])->assertForbidden();
        $this->putJson('/api/v1/enterprise/organizations/999999/branding', [])->assertForbidden();
    }

    #[Test]
    public function it_answers_an_unknown_and_a_foreign_domain_alike_without_the_ability(): void
    {
        $member = $this->createApiUser();
        $foreign = CustomDomain::factory()->create(['organization_id' => $this->createOrganization()->id]);
        $this->actingAsApiUserWithToken($member);

        $this->postJson("/api/v1/enterprise/domains/{$foreign->id}/verify")->assertForbidden();
        $this->postJson('/api/v1/enterprise/domains/999999/verify')->assertForbidden();
        $this->deleteJson("/api/v1/enterprise/domains/{$foreign->id}")->assertForbidden();
        $this->deleteJson('/api/v1/enterprise/domains/999999')->assertForbidden();
    }

    #[Test]
    public function it_returns_not_found_for_an_unknown_domain_only_after_authorization(): void
    {
        $owner = $this->createApiOrganizationOwner();
        $this->actingAsApiUserWithToken($owner);

        $this->deleteJson('/api/v1/enterprise/domains/999999')->assertNotFound();
    }

    #[Test]
    public function it_rejects_a_webhook_update_by_a_caller_without_update_before_validating(): void
    {
        $member = $this->createApiUser();
        $webhook = Webhook::factory()->create(['organization_id' => $member->organization_id]);
        $this->actingAsApiUserWithToken($member);

        $this->putJson("/api/v1/webhooks/{$webhook->id}", ['url' => 'not-a-url'])->assertForbidden();
    }

    #[Test]
    public function it_answers_an_unknown_and_a_foreign_webhook_update_alike_before_validating(): void
    {
        $member = $this->createApiUser();
        $foreign = Webhook::factory()->create(['organization_id' => Organization::factory()->create()->id]);
        $this->actingAsApiUserWithToken($member);

        $this->putJson("/api/v1/webhooks/{$foreign->id}", ['url' => 'not-a-url'])->assertForbidden();
        $this->putJson('/api/v1/webhooks/999999', ['url' => 'not-a-url'])->assertForbidden();
    }
}
