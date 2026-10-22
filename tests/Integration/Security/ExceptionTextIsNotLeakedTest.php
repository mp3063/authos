<?php

namespace Tests\Integration\Security;

use App\Models\LdapConfiguration;
use App\Models\WebhookEvent;
use App\Services\BrandingService;
use App\Services\DomainVerificationService;
use App\Services\LdapAuthService;
use App\Services\SocialAuthService;
use App\Services\SSO\OidcFlowService;
use App\Services\SSO\SsoSessionManager;
use App\Services\WebhookService;
use Exception;
use Illuminate\Http\UploadedFile;
use Illuminate\Support\Facades\Exceptions;
use Illuminate\Support\Facades\Storage;
use Mockery\MockInterface;
use PHPUnit\Framework\Attributes\Test;
use Tests\Integration\IntegrationTestCase;

class ExceptionTextIsNotLeakedTest extends IntegrationTestCase
{
    private const SECRET = 'SQLSTATE secret detail at /var/www/internal/path';

    protected function setUp(): void
    {
        parent::setUp();

        Exceptions::fake();
    }

    #[Test]
    public function it_answers_a_failed_logo_upload_with_a_fixed_message(): void
    {
        Storage::fake('public');
        $owner = $this->createApiOrganizationOwner();
        $this->mock(BrandingService::class, fn (MockInterface $mock) => $mock->shouldReceive('uploadLogo')->andThrow(new Exception(self::SECRET)));

        $response = $this->actingAsApiUserWithToken($owner, ['enterprise.branding.manage'])
            ->postJson("/api/v1/enterprise/organizations/{$owner->organization_id}/branding/logo", [
                'logo' => UploadedFile::fake()->image('logo.png', 200, 200),
            ]);

        $response->assertStatus(500)->assertJsonPath('error.message', 'Logo upload failed');
        $this->assertStringNotContainsString(self::SECRET, $response->getContent());
        Exceptions::assertReported(fn (Exception $e) => $e->getMessage() === self::SECRET);
    }

    #[Test]
    public function it_answers_a_failed_ldap_sync_with_a_fixed_message(): void
    {
        $owner = $this->createApiOrganizationOwner();
        LdapConfiguration::factory()->create(['organization_id' => $owner->organization_id, 'is_active' => true]);
        $this->mock(LdapAuthService::class, fn (MockInterface $mock) => $mock->shouldReceive('syncUsers')->andThrow(new Exception(self::SECRET)));

        $response = $this->actingAsApiUserWithToken($owner)->postJson('/api/v1/enterprise/ldap/sync');

        $response->assertStatus(500)->assertJsonPath('error.message', 'LDAP user sync failed');
        $this->assertStringNotContainsString(self::SECRET, $response->getContent());
        Exceptions::assertReported(fn (Exception $e) => $e->getMessage() === self::SECRET);
    }

    #[Test]
    public function it_answers_a_failed_sso_callback_with_a_fixed_message(): void
    {
        $this->mock(OidcFlowService::class, fn (MockInterface $mock) => $mock->shouldReceive('handleOIDCCallback')->andThrow(new Exception(self::SECRET)));

        $response = $this->postJson('/api/v1/sso/callback', ['code' => 'idp-code', 'state' => 'some-state']);

        $response->assertStatus(400)->assertExactJson(['success' => false, 'error' => 'SSO authentication failed']);
        Exceptions::assertReported(fn (Exception $e) => $e->getMessage() === self::SECRET);
    }

    #[Test]
    public function it_answers_a_failed_sso_cleanup_with_a_fixed_message(): void
    {
        $this->mock(SsoSessionManager::class, fn (MockInterface $mock) => $mock->shouldReceive('cleanupExpiredSessions')->andThrow(new Exception(self::SECRET)));

        $response = $this->actingAsApiUserWithToken($this->createApiSuperAdmin())->postJson('/api/v1/sso/cleanup');

        $response->assertStatus(500)->assertExactJson(['message' => 'Cleanup failed']);
        Exceptions::assertReported(fn (Exception $e) => $e->getMessage() === self::SECRET);
    }

    #[Test]
    public function it_answers_a_failed_social_provider_lookup_with_a_fixed_message(): void
    {
        $this->mock(SocialAuthService::class, fn (MockInterface $mock) => $mock->shouldReceive('getAvailableProviders')->andThrow(new Exception(self::SECRET)));

        $response = $this->getJson('/api/v1/auth/social/providers');

        $response->assertStatus(500)->assertExactJson(['success' => false, 'message' => 'Failed to get social providers']);
        Exceptions::assertReported(fn (Exception $e) => $e->getMessage() === self::SECRET);
    }

    #[Test]
    public function it_answers_a_failed_domain_add_with_a_fixed_message(): void
    {
        $owner = $this->createApiOrganizationOwner();
        $this->mock(DomainVerificationService::class, fn (MockInterface $mock) => $mock->shouldReceive('addDomain')->andThrow(new Exception(self::SECRET)));

        $response = $this->actingAs($owner, 'api')->postJson('/api/v1/enterprise/domains', ['domain' => 'custom.example.com']);

        $response->assertStatus(500)->assertJsonPath('error.message', 'Failed to add domain');
        $this->assertStringNotContainsString(self::SECRET, $response->getContent());
        Exceptions::assertReported(fn (Exception $e) => $e->getMessage() === self::SECRET);
    }

    #[Test]
    public function it_answers_a_duplicate_domain_with_a_fixed_validation_error(): void
    {
        $owner = $this->createApiOrganizationOwner();
        $this->mock(DomainVerificationService::class, fn (MockInterface $mock) => $mock->shouldReceive('addDomain')->andThrow(new Exception('Domain already exists in '.self::SECRET)));

        $response = $this->actingAs($owner, 'api')->postJson('/api/v1/enterprise/domains', ['domain' => 'custom.example.com']);

        $response->assertUnprocessable()->assertJsonPath('errors.domain.0', 'Domain already exists');
        $this->assertStringNotContainsString(self::SECRET, $response->getContent());
        Exceptions::assertNothingReported();
    }

    #[Test]
    public function it_answers_a_failed_webhook_creation_with_a_fixed_message(): void
    {
        WebhookEvent::create(['name' => 'user.created', 'category' => 'user', 'description' => 'A user was created', 'is_active' => true, 'version' => '1.0']);
        $this->mock(WebhookService::class, fn (MockInterface $mock) => $mock->shouldReceive('createWebhook')->andThrow(new Exception(self::SECRET)));

        $response = $this->actingAsApiUserWithToken($this->createApiOrganizationAdmin())->postJson('/api/v1/webhooks', [
            'name' => 'Hook',
            'url' => 'https://example.com/hook',
            'events' => ['user.created'],
        ]);

        $response->assertStatus(500)->assertJsonPath('error.message', 'Failed to create webhook');
        $this->assertStringNotContainsString(self::SECRET, $response->getContent());
        Exceptions::assertReported(fn (Exception $e) => $e->getMessage() === self::SECRET);
    }
}
