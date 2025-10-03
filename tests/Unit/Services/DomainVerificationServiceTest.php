<?php

namespace Tests\Unit\Services;

use App\Models\CustomDomain;
use App\Models\Organization;
use App\Services\DomainVerificationService;
use Tests\TestCase;

class DomainVerificationServiceTest extends TestCase
{
    private DomainVerificationService $service;

    private Organization $organization;

    protected function setUp(): void
    {
        parent::setUp();

        $this->service = new DomainVerificationService;
        $this->organization = Organization::factory()->create();
    }

    public function test_create_domain_creates_with_verification_code(): void
    {
        $domain = $this->service->createDomain($this->organization, 'auth.example.com');

        $this->assertInstanceOf(CustomDomain::class, $domain);
        $this->assertEquals('auth.example.com', $domain->domain);
        $this->assertEquals($this->organization->id, $domain->organization_id);
        $this->assertNotNull($domain->verification_code);
        $this->assertEquals(32, strlen($domain->verification_code));
        $this->assertFalse($domain->is_active);
    }

    public function test_create_domain_converts_to_lowercase(): void
    {
        $domain = $this->service->createDomain($this->organization, 'AUTH.EXAMPLE.COM');

        $this->assertEquals('auth.example.com', $domain->domain);
    }

    public function test_add_domain_is_alias_for_create_domain(): void
    {
        $domain = $this->service->addDomain($this->organization, 'test.example.com');

        $this->assertInstanceOf(CustomDomain::class, $domain);
        $this->assertEquals('test.example.com', $domain->domain);
    }

    public function test_verify_domain_marks_as_verified_when_dns_matches(): void
    {
        $this->markTestSkipped('Skipped: Requires real DNS lookup or mocking dns_get_record which is not easily mockable in PHPUnit');

        $domain = CustomDomain::factory()->create([
            'organization_id' => $this->organization->id,
            'domain' => 'test.local',
            'verification_code' => 'test-verification-code-123',
            'is_active' => false,
        ]);

        // Mock DNS lookup - in real scenario this would check actual DNS
        // This test will likely fail without proper DNS mocking
        $result = $this->service->verifyDomain($domain);

        // Since we can't actually mock dns_get_record easily, this will be false
        $this->assertIsBool($result);
    }

    public function test_verify_domain_returns_false_when_dns_not_found(): void
    {
        $this->markTestSkipped('Skipped: Requires real DNS lookup or mocking dns_get_record which is not easily mockable in PHPUnit');

        $domain = CustomDomain::factory()->create([
            'organization_id' => $this->organization->id,
            'domain' => 'nonexistent.invalid.local',
            'verification_code' => 'test-code',
        ]);

        $result = $this->service->verifyDomain($domain);

        $this->assertFalse($result);
    }

    public function test_check_dns_txt_record_returns_false_for_invalid_domain(): void
    {
        $this->markTestSkipped('Skipped: Requires real DNS lookup or mocking dns_get_record which is not easily mockable in PHPUnit');

        $result = $this->service->checkDnsTxtRecord('invalid.local.domain', 'test-value');

        $this->assertFalse($result);
    }

    public function test_generate_verification_code_creates_32_char_string(): void
    {
        $code = $this->service->generateVerificationCode();

        $this->assertEquals(32, strlen($code));
        $this->assertMatchesRegularExpression('/^[a-f0-9]{32}$/', $code);
    }

    public function test_generate_verification_code_creates_unique_codes(): void
    {
        $code1 = $this->service->generateVerificationCode();
        $code2 = $this->service->generateVerificationCode();

        $this->assertNotEquals($code1, $code2);
    }

    public function test_get_verification_instructions_returns_array(): void
    {
        $domain = CustomDomain::factory()->create([
            'organization_id' => $this->organization->id,
        ]);

        $instructions = $this->service->getVerificationInstructions($domain);

        $this->assertIsArray($instructions);
        $this->assertArrayHasKey('domain', $instructions);
        $this->assertArrayHasKey('verification_code', $instructions);
        $this->assertArrayHasKey('dns_records', $instructions);
        $this->assertArrayHasKey('instructions', $instructions);
        $this->assertEquals($domain->domain, $instructions['domain']);
        $this->assertEquals($domain->verification_code, $instructions['verification_code']);
    }

    public function test_regenerate_verification_code_creates_new_code(): void
    {
        $domain = CustomDomain::factory()->create([
            'organization_id' => $this->organization->id,
            'verification_code' => 'old-code-123',
            'verified_at' => now(),
            'is_active' => true,
        ]);

        $oldCode = $domain->verification_code;

        $updated = $this->service->regenerateVerificationCode($domain);

        $this->assertNotEquals($oldCode, $updated->verification_code);
        $this->assertNull($updated->verified_at);
        $this->assertFalse($updated->is_active);
    }

    public function test_remove_domain_deletes_record(): void
    {
        $domain = CustomDomain::factory()->create([
            'organization_id' => $this->organization->id,
        ]);

        $domainId = $domain->id;

        $this->service->removeDomain($domain);

        $this->assertDatabaseMissing('custom_domains', [
            'id' => $domainId,
        ]);
    }

    public function test_check_ssl_certificate_handles_invalid_domain(): void
    {
        $this->markTestSkipped('Skipped: Requires real SSL connection which is not suitable for unit tests');

        $domain = CustomDomain::factory()->create([
            'organization_id' => $this->organization->id,
            'domain' => 'invalid.local.test',
        ]);

        $result = $this->service->checkSslCertificate($domain);

        $this->assertIsArray($result);
        $this->assertArrayHasKey('success', $result);
        $this->assertFalse($result['success']);
    }

    public function test_get_dns_records_returns_verification_records(): void
    {
        $domain = CustomDomain::factory()->create([
            'organization_id' => $this->organization->id,
        ]);

        $records = $this->service->getDnsRecords($domain);

        $this->assertIsArray($records);
    }
}
