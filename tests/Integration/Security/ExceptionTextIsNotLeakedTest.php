<?php

namespace Tests\Integration\Security;

use App\Filament\Resources\LdapConfigurations\Pages\ListLdapConfigurations;
use App\Jobs\ProcessBulkImportJob;
use App\Models\BulkImportJob;
use App\Models\CustomDomain;
use App\Models\Invitation;
use App\Models\LdapConfiguration;
use App\Models\WebhookEvent;
use App\Services\BrandingService;
use App\Services\BulkOperationService;
use App\Services\DomainVerificationService;
use App\Services\LdapAuthService;
use App\Services\SocialAuthService;
use App\Services\SSO\OidcFlowService;
use App\Services\SSO\SsoSessionManager;
use App\Services\WebhookService;
use Exception;
use Filament\Notifications\Notification;
use Illuminate\Http\UploadedFile;
use Illuminate\Support\Facades\Exceptions;
use Illuminate\Support\Facades\Storage;
use InvalidArgumentException;
use Livewire\Livewire;
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

    #[Test]
    public function it_gives_a_fixed_reason_for_an_invitation_that_fails_in_a_bulk_invite(): void
    {
        $owner = $this->createApiOrganizationOwner();
        Invitation::creating(fn () => throw new Exception(self::SECRET));

        $response = $this->actingAs($owner, 'api')
            ->postJson("/api/v1/organizations/{$owner->organization_id}/bulk/invite-users", [
                'invitations' => [['email' => 'invitee@example.com']],
            ]);

        $response->assertJsonFragment(['email' => 'invitee@example.com', 'reason' => 'Failed to create invitation']);
        $this->assertStringNotContainsString(self::SECRET, $response->getContent());
        Exceptions::assertReported(fn (Exception $e) => $e->getMessage() === self::SECRET);
    }

    #[Test]
    public function it_gives_a_fixed_reason_for_a_user_that_fails_in_a_bulk_operation(): void
    {
        $user = $this->createUser();

        $result = app(BulkOperationService::class)->bulkUserOperations([$user->id], 'bogus', $user->organization);

        $this->assertSame('Failed to apply the operation to this user', $result['failed'][0]['reason']);
        Exceptions::assertReported(fn (InvalidArgumentException $e) => $e->getMessage() === 'Invalid operation: bogus');
    }

    #[Test]
    public function it_stores_a_fixed_error_for_a_failed_bulk_import_job(): void
    {
        $importJob = BulkImportJob::factory()->create();

        (new ProcessBulkImportJob($importJob))->failed(new Exception(self::SECRET));

        $this->assertSame('Import failed', $importJob->fresh()->errors[0]['message']);
    }

    #[Test]
    public function it_answers_a_failed_domain_verification_with_a_fixed_message(): void
    {
        $owner = $this->createApiOrganizationOwner();
        $domain = CustomDomain::factory()->create(['organization_id' => $owner->organization_id]);
        $this->partialMock(DomainVerificationService::class, fn (MockInterface $mock) => $mock->shouldReceive('checkDnsTxtRecord')->andThrow(new Exception(self::SECRET)));

        $response = $this->actingAs($owner, 'api')->postJson("/api/v1/enterprise/domains/{$domain->id}/verify");

        $response->assertJsonFragment(['message' => 'Verification failed']);
        $this->assertStringNotContainsString(self::SECRET, $response->getContent());
    }

    #[Test]
    public function it_shows_a_fixed_message_when_an_ldap_connection_test_fails_in_the_panel(): void
    {
        $owner = $this->createUser([], 'Organization Owner');
        $this->actingAs($owner);
        $ldap = LdapConfiguration::factory()->create(['organization_id' => $owner->organization_id]);
        $this->mock(LdapAuthService::class, fn (MockInterface $mock) => $mock->shouldReceive('testConnection')->andThrow(new Exception(self::SECRET)));

        Livewire::test(ListLdapConfigurations::class)
            ->callTableAction('test_connection', $ldap)
            ->assertNotified(
                Notification::make()
                    ->danger()
                    ->title('Connection Failed')
                    ->body('Could not connect to the LDAP server. Check the configuration, or contact an administrator.')
            );

        Exceptions::assertReported(fn (Exception $e) => $e->getMessage() === self::SECRET);
    }
}
