<?php

namespace Tests\Integration\Security;

use App\Models\LdapConfiguration;
use App\Services\BrandingService;
use App\Services\LdapAuthService;
use App\Services\SSO\OidcFlowService;
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
}
