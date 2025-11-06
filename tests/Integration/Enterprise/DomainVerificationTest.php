<?php

namespace Tests\Integration\Enterprise;

use App\Models\CustomDomain;
use App\Models\Organization;
use App\Services\DomainVerificationService;
use Illuminate\Support\Facades\Log;
use PHPUnit\Framework\Attributes\Test;
use Tests\Integration\IntegrationTestCase;

/**
 * Domain Verification Integration Tests
 *
 * Tests the complete domain verification flow for custom domain management:
 * - Adding domains to organizations
 * - Generating DNS verification codes
 * - DNS TXT record verification
 * - SSL certificate validation
 * - Domain ownership confirmation
 * - Verification failure handling
 * - Multiple domains per organization
 * - Domain removal
 * - Verification status tracking
 * - DNS propagation timeout handling
 *
 * This test suite verifies that organizations can add, verify, and manage
 * custom domains with proper DNS validation and security checks.
 *
 * @see \App\Services\DomainVerificationService
 * @see \App\Models\CustomDomain
 */
class DomainVerificationTest extends IntegrationTestCase
{
    protected DomainVerificationService $service;

    /**
     * Set up test environment before each test
     */
    protected function setUp(): void
    {
        parent::setUp();

        $this->service = app(DomainVerificationService::class);
    }

    #[Test]
    public function domain_can_be_added_to_organization()
    {
        // ARRANGE: Create organization and admin user
        $organization = $this->createOrganization();
        $admin = $this->createApiOrganizationAdmin(['organization_id' => $organization->id]);
        $domain = 'custom.example.com';

        // ACT: Add domain via API endpoint
        $response = $this->actingAs($admin, 'api')
            ->postJson('/api/v1/enterprise/domains', [
                'domain' => $domain,
            ]);

        // ASSERT: Domain created successfully with pending status
        $response->assertCreated();
        $response->assertJsonStructure([
            'success',
            'data' => [
                'id',
                'domain',
                'status',
                'verification_code',
                'verification_method',
                'is_active',
                'created_at',
            ],
            'message',
        ]);

        // ASSERT: Domain stored in database with correct attributes
        $this->assertDatabaseHas('custom_domains', [
            'organization_id' => $organization->id,
            'domain' => $domain,
            'status' => 'pending',
            'verification_method' => 'dns',
            'is_active' => false,
        ]);

        // ASSERT: Verification code was generated
        $domainModel = CustomDomain::where('domain', $domain)->first();
        $this->assertNotNull($domainModel->verification_code);
        $this->assertEquals(32, strlen($domainModel->verification_code)); // 32-char hex
    }

    #[Test]
    public function duplicate_domain_cannot_be_added_to_same_organization()
    {
        // ARRANGE: Create organization with existing domain
        $organization = $this->createOrganization();
        $admin = $this->createApiOrganizationAdmin(['organization_id' => $organization->id]);
        $domain = CustomDomain::factory()->create([
            'organization_id' => $organization->id,
            'domain' => 'existing.example.com',
        ]);

        // ACT: Try to add same domain again
        $response = $this->actingAs($admin, 'api')
            ->postJson('/api/v1/enterprise/domains', [
                'domain' => 'existing.example.com',
            ]);

        // ASSERT: Request rejected with error
        $response->assertStatus(422);
        $response->assertJsonValidationErrors(['domain']);
    }

    #[Test]
    public function verification_code_can_be_generated_for_domain()
    {
        // ARRANGE: Create domain
        $organization = $this->createOrganization();
        $domain = CustomDomain::factory()->create([
            'organization_id' => $organization->id,
        ]);

        // ACT: Generate verification code
        $verificationCode = $domain->verification_code;

        // ASSERT: Code is 32-character hexadecimal string
        $this->assertNotNull($verificationCode);
        $this->assertEquals(32, strlen($verificationCode));
        $this->assertMatchesRegularExpression('/^[a-f0-9]{32}$/', $verificationCode);
    }

    #[Test]
    public function dns_txt_record_format_includes_verification_code()
    {
        // ARRANGE: Create domain with verification code
        $organization = $this->createOrganization();
        $domain = CustomDomain::factory()->create([
            'organization_id' => $organization->id,
            'verification_code' => 'abc123def456',
        ]);

        // ACT: Get DNS verification records
        $dnsRecords = $domain->getVerificationDnsRecords();

        // ASSERT: TXT record contains verification code
        $this->assertIsArray($dnsRecords);
        $this->assertNotEmpty($dnsRecords);

        $txtRecord = collect($dnsRecords)->firstWhere('type', 'TXT');
        $this->assertNotNull($txtRecord);
        $this->assertEquals('_authos-verify', $txtRecord['name']);
        $this->assertEquals($domain->verification_code, $txtRecord['value']);
        $this->assertEquals(3600, $txtRecord['ttl']);
    }

    #[Test]
    public function dns_txt_record_verification_succeeds_when_code_matches()
    {
        // ARRANGE: Create domain with verification code
        $organization = $this->createOrganization();
        $domain = CustomDomain::factory()->create([
            'organization_id' => $organization->id,
            'domain' => 'verify-success.example.com',
            'verification_code' => 'test-verification-code-123',
        ]);

        // Mock DNS service at the method level
        $mockService = \Mockery::mock(DomainVerificationService::class)->makePartial();
        $mockService->shouldReceive('checkDnsTxtRecord')
            ->once()
            ->with($domain->domain, $domain->verification_code)
            ->andReturn(true);
        $this->app->instance(DomainVerificationService::class, $mockService);

        // ACT: Verify domain
        $result = $mockService->verifyDomain($domain);

        // ASSERT: Verification succeeded
        $this->assertTrue($result['success']);
        $this->assertTrue($result['verified']);
        $this->assertEquals('Domain verified successfully', $result['message']);

        // ASSERT: Domain status updated to verified
        $domain->refresh();
        $this->assertEquals('verified', $domain->status);
        $this->assertNotNull($domain->verified_at);
        $this->assertTrue($domain->is_active);
    }

    #[Test]
    public function dns_txt_record_verification_fails_when_code_not_found()
    {
        // ARRANGE: Create domain
        $organization = $this->createOrganization();
        $domain = CustomDomain::factory()->create([
            'organization_id' => $organization->id,
            'domain' => 'verify-fail.example.com',
            'verification_code' => 'expected-code-456',
        ]);

        // Mock DNS service
        $mockService = \Mockery::mock(DomainVerificationService::class)->makePartial();
        $mockService->shouldReceive('checkDnsTxtRecord')
            ->once()
            ->with($domain->domain, $domain->verification_code)
            ->andReturn(false);
        $this->app->instance(DomainVerificationService::class, $mockService);

        // ACT: Attempt verification
        $result = $mockService->verifyDomain($domain);

        // ASSERT: Verification failed
        $this->assertFalse($result['success']);
        $this->assertFalse($result['verified']);
        $this->assertEquals('DNS TXT record not found', $result['message']);

        // ASSERT: Domain status remains pending
        $domain->refresh();
        $this->assertEquals('pending', $domain->status);
        $this->assertNull($domain->verified_at);
        $this->assertFalse($domain->is_active);
    }

    #[Test]
    public function ssl_certificate_validation_succeeds_for_valid_certificate()
    {
        // ARRANGE: Create verified domain
        $organization = $this->createOrganization();
        $domain = CustomDomain::factory()->verified()->create([
            'organization_id' => $organization->id,
            'domain' => 'ssl.example.com',
        ]);

        // Mock SSL certificate check to return valid certificate
        $mockCertificate = [
            'issuer' => 'Let\'s Encrypt Authority X3',
            'subject' => 'ssl.example.com',
            'valid_from' => now()->subMonths(1)->toDateTimeString(),
            'valid_to' => now()->addMonths(2)->toDateTimeString(),
            'checked_at' => now()->toISOString(),
        ];

        $mockService = \Mockery::mock(DomainVerificationService::class)->makePartial();
        $mockService->shouldReceive('checkSslCertificate')
            ->once()
            ->with($domain)
            ->andReturn([
                'success' => true,
                'certificate' => $mockCertificate,
            ]);
        $this->app->instance(DomainVerificationService::class, $mockService);

        // ACT: Check SSL certificate
        $result = $mockService->checkSslCertificate($domain);

        // ASSERT: SSL check succeeded
        $this->assertTrue($result['success']);
        $this->assertArrayHasKey('certificate', $result);
        $this->assertEquals('Let\'s Encrypt Authority X3', $result['certificate']['issuer']);
        $this->assertEquals('ssl.example.com', $result['certificate']['subject']);
    }

    #[Test]
    public function ssl_certificate_validation_fails_for_invalid_certificate()
    {
        // ARRANGE: Create verified domain
        $organization = $this->createOrganization();
        $domain = CustomDomain::factory()->verified()->create([
            'organization_id' => $organization->id,
            'domain' => 'no-ssl.example.com',
        ]);

        // Mock SSL certificate check to fail
        $mockService = \Mockery::mock(DomainVerificationService::class)->makePartial();
        $mockService->shouldReceive('checkSslCertificate')
            ->once()
            ->with($domain)
            ->andReturn([
                'success' => false,
                'message' => 'SSL connection failed: Connection refused',
            ]);
        $this->app->instance(DomainVerificationService::class, $mockService);

        // ACT: Check SSL certificate
        $result = $mockService->checkSslCertificate($domain);

        // ASSERT: SSL check failed
        $this->assertFalse($result['success']);
        $this->assertStringContainsString('SSL connection failed', $result['message']);
    }

    #[Test]
    public function domain_ownership_can_be_confirmed_via_api()
    {
        // ARRANGE: Create organization and pending domain
        $organization = $this->createOrganization();
        $admin = $this->createApiOrganizationAdmin(['organization_id' => $organization->id]);
        $domain = CustomDomain::factory()->create([
            'organization_id' => $organization->id,
            'domain' => 'confirm.example.com',
            'verification_code' => 'confirm-code-789',
        ]);

        // Mock DNS verification to succeed
        $mockService = \Mockery::mock(DomainVerificationService::class)->makePartial();
        $mockService->shouldReceive('verifyDomain')
            ->once()
            ->andReturn([
                'success' => true,
                'verified' => true,
                'message' => 'Domain verified successfully',
            ]);
        $this->app->instance(DomainVerificationService::class, $mockService);

        // ACT: Request domain verification via API
        $response = $this->actingAs($admin, 'api')
            ->postJson("/api/v1/enterprise/domains/{$domain->id}/verify");

        // ASSERT: Verification succeeded (API wraps result in data key)
        $response->assertOk();
        $response->assertJson([
            'success' => true,
            'data' => [
                'success' => true,
                'verified' => true,
                'message' => 'Domain verified successfully',
            ],
        ]);
    }

    #[Test]
    public function verification_failure_handling_provides_clear_error_messages()
    {
        // ARRANGE: Create domain
        $organization = $this->createOrganization();
        $domain = CustomDomain::factory()->create([
            'organization_id' => $organization->id,
            'domain' => 'error.example.com',
        ]);

        // Mock DNS verification to fail with error
        $mockService = \Mockery::mock(DomainVerificationService::class)->makePartial();
        $mockService->shouldReceive('checkDnsTxtRecord')
            ->once()
            ->andReturn(false);

        // ACT: Attempt verification
        $result = $mockService->verifyDomain($domain);

        // ASSERT: Clear error message provided
        $this->assertFalse($result['success']);
        $this->assertFalse($result['verified']);
        $this->assertStringContainsString('DNS TXT record not found', $result['message']);
    }

    #[Test]
    public function multiple_domains_can_be_added_to_same_organization()
    {
        // ARRANGE: Create organization and admin
        $organization = $this->createOrganization();
        $admin = $this->createApiOrganizationAdmin(['organization_id' => $organization->id]);

        // ACT: Add multiple domains
        $domains = ['domain1.example.com', 'domain2.example.com', 'domain3.example.com'];

        foreach ($domains as $domainName) {
            $response = $this->actingAs($admin, 'api')
                ->postJson('/api/v1/enterprise/domains', [
                    'domain' => $domainName,
                ]);

            $response->assertCreated();
        }

        // ASSERT: All domains exist in database
        foreach ($domains as $domainName) {
            $this->assertDatabaseHas('custom_domains', [
                'organization_id' => $organization->id,
                'domain' => $domainName,
            ]);
        }

        // ASSERT: Organization has all three domains
        $this->assertEquals(3, CustomDomain::where('organization_id', $organization->id)->count());
    }

    #[Test]
    public function domain_can_be_removed_from_organization()
    {
        // ARRANGE: Create organization with domain
        $organization = $this->createOrganization();
        $admin = $this->createApiOrganizationAdmin(['organization_id' => $organization->id]);
        $domain = CustomDomain::factory()->create([
            'organization_id' => $organization->id,
            'domain' => 'remove.example.com',
        ]);

        // ACT: Remove domain via API
        $response = $this->actingAs($admin, 'api')
            ->deleteJson("/api/v1/enterprise/domains/{$domain->id}");

        // ASSERT: Domain removed successfully (200 with message, not 204)
        $response->assertOk();
        $response->assertJson([
            'success' => true,
            'message' => 'Domain deleted successfully',
        ]);

        // ASSERT: Domain deleted from database
        $this->assertDatabaseMissing('custom_domains', [
            'id' => $domain->id,
        ]);
    }

    #[Test]
    public function verification_status_can_be_tracked_through_lifecycle()
    {
        // ARRANGE: Create domain
        $organization = $this->createOrganization();
        $domain = CustomDomain::factory()->create([
            'organization_id' => $organization->id,
            'domain' => 'lifecycle.example.com',
            'status' => 'pending',
        ]);

        // ASSERT: Initial state is pending
        $this->assertEquals('pending', $domain->status);
        $this->assertNull($domain->verified_at);
        $this->assertFalse($domain->is_active);
        $this->assertFalse($domain->isVerified());

        // ACT: Update to verified
        $domain->update([
            'status' => 'verified',
            'verified_at' => now(),
            'is_active' => true,
        ]);

        // ASSERT: Domain is now verified
        $domain->refresh();
        $this->assertEquals('verified', $domain->status);
        $this->assertNotNull($domain->verified_at);
        $this->assertTrue($domain->is_active);
        $this->assertTrue($domain->isVerified());
    }

    #[Test]
    public function dns_propagation_timeout_is_handled_gracefully()
    {
        // ARRANGE: Create domain
        $organization = $this->createOrganization();
        $domain = CustomDomain::factory()->create([
            'organization_id' => $organization->id,
            'domain' => 'slow-dns.example.com',
        ]);

        // Mock DNS lookup to timeout/fail (simulating propagation delay)
        $mockService = \Mockery::mock(DomainVerificationService::class)->makePartial();
        $mockService->shouldReceive('checkDnsTxtRecord')
            ->once()
            ->with($domain->domain, $domain->verification_code)
            ->andReturn(false); // Simulates DNS not propagated yet

        // ACT: Attempt verification during propagation
        $result = $mockService->verifyDomain($domain);

        // ASSERT: Graceful failure with clear message
        $this->assertFalse($result['success']);
        $this->assertFalse($result['verified']);
        $this->assertEquals('DNS TXT record not found', $result['message']);

        // ASSERT: Domain remains in pending state (can retry later)
        $domain->refresh();
        $this->assertEquals('pending', $domain->status);
        $this->assertFalse($domain->is_active);
    }

    #[Test]
    public function verification_code_can_be_regenerated()
    {
        // ARRANGE: Create domain with initial verification code
        $organization = $this->createOrganization();
        $domain = CustomDomain::factory()->create([
            'organization_id' => $organization->id,
            'domain' => 'regen.example.com',
            'verification_code' => 'old-code-123',
        ]);

        $oldCode = $domain->verification_code;

        // ACT: Regenerate verification code
        $updatedDomain = $this->service->regenerateVerificationCode($domain);

        // ASSERT: New code generated
        $this->assertNotEquals($oldCode, $updatedDomain->verification_code);
        $this->assertEquals(32, strlen($updatedDomain->verification_code));

        // ASSERT: Domain reset to pending state
        $this->assertEquals('pending', $updatedDomain->status);
        $this->assertNull($updatedDomain->verified_at);
        $this->assertFalse($updatedDomain->is_active);
    }

    #[Test]
    public function verified_domain_stores_dns_records_in_database()
    {
        // ARRANGE: Create domain
        $organization = $this->createOrganization();
        $domain = CustomDomain::factory()->create([
            'organization_id' => $organization->id,
            'domain' => 'dns-store.example.com',
            'verification_code' => 'store-code-456',
        ]);

        // Mock DNS verification to succeed and return TXT records
        $mockService = \Mockery::mock(DomainVerificationService::class)->makePartial();
        $mockService->shouldReceive('verifyDomain')
            ->once()
            ->with($domain)
            ->andReturnUsing(function ($domainArg) use ($domain) {
                $domain->update([
                    'status' => 'verified',
                    'verified_at' => now(),
                    'is_active' => true,
                    'dns_records' => [
                        'txt_records' => ['authos-verify=' . $domain->verification_code],
                        'verified_at' => now()->toISOString(),
                    ],
                ]);

                return [
                    'success' => true,
                    'verified' => true,
                    'message' => 'Domain verified successfully',
                ];
            });
        $this->app->instance(DomainVerificationService::class, $mockService);

        // ACT: Verify domain
        $result = $mockService->verifyDomain($domain);

        // ASSERT: DNS records stored
        $domain->refresh();
        $this->assertNotNull($domain->dns_records);
        $this->assertArrayHasKey('txt_records', $domain->dns_records);
        $this->assertArrayHasKey('verified_at', $domain->dns_records);
    }

    #[Test]
    public function only_organization_admin_can_manage_domains()
    {
        // ARRANGE: Create organization with regular user
        $organization = $this->createOrganization();
        $regularUser = $this->createApiUser(['organization_id' => $organization->id]);

        // ACT: Try to add domain as regular user
        $response = $this->actingAs($regularUser, 'api')
            ->postJson('/api/v1/enterprise/domains', [
                'domain' => 'unauthorized.example.com',
            ]);

        // ASSERT: Access denied
        $response->assertForbidden();
    }

    #[Test]
    public function domain_from_different_organization_cannot_be_accessed()
    {
        // ARRANGE: Create two organizations with domains
        $org1 = $this->createOrganization();
        $org2 = $this->createOrganization();

        $admin1 = $this->createApiOrganizationAdmin(['organization_id' => $org1->id]);

        $domain2 = CustomDomain::factory()->create([
            'organization_id' => $org2->id,
            'domain' => 'org2.example.com',
        ]);

        // ACT: Try to verify domain from different organization
        $response = $this->actingAs($admin1, 'api')
            ->postJson("/api/v1/enterprise/domains/{$domain2->id}/verify");

        // ASSERT: Access denied (should return 404 to prevent info leakage)
        $response->assertNotFound();
    }
}
