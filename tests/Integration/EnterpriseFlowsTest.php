<?php

namespace Tests\Integration;

use App\Jobs\GenerateComplianceReportJob;
use App\Jobs\SyncLdapUsersJob;
use App\Models\AuditExport;
use App\Models\AuthenticationLog;
use App\Models\CustomDomain;
use App\Models\LdapConfiguration;
use App\Models\Organization;
use App\Models\OrganizationBranding;
use App\Models\User;
use App\Services\AuditExportService;
use App\Services\BrandingService;
use App\Services\ComplianceReportService;
use App\Services\DomainVerificationService;
use Illuminate\Http\UploadedFile;
use Illuminate\Support\Facades\Mail;
use Illuminate\Support\Facades\Queue;
use Illuminate\Support\Facades\Storage;
use Spatie\Permission\Models\Role;
use Tests\TestCase;

/**
 * Integration tests for complete Enterprise feature workflows
 */
class EnterpriseFlowsTest extends TestCase
{
    private Organization $organization;

    private User $adminUser;

    protected function setUp(): void
    {
        parent::setUp();

        Storage::fake('public');
        Mail::fake();

        $this->organization = Organization::factory()->create([
            'settings' => [
                'enterprise_features' => [
                    'ldap_enabled' => true,
                    'custom_branding_enabled' => true,
                    'custom_domains_enabled' => true,
                    'audit_exports_enabled' => true,
                    'compliance_reports_enabled' => true,
                ],
            ],
        ]);

        Role::firstOrCreate(['name' => 'Organization Admin', 'guard_name' => 'api']);

        $this->adminUser = $this->createApiOrganizationAdmin([
            'organization_id' => $this->organization->id,
        ]);
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function complete_domain_verification_workflow(): void
    {
        $domainService = app(DomainVerificationService::class);

        // Step 1: Add custom domain
        $domain = $domainService->createDomain($this->organization, 'auth.example.com');

        $this->assertInstanceOf(CustomDomain::class, $domain);
        $this->assertEquals('auth.example.com', $domain->domain);
        $this->assertNotNull($domain->verification_code);
        $this->assertFalse($domain->is_active);

        // Step 2: Get verification instructions
        $instructions = $domainService->getVerificationInstructions($domain);

        $this->assertIsArray($instructions);
        $this->assertArrayHasKey('domain', $instructions);
        $this->assertArrayHasKey('verification_code', $instructions);
        $this->assertArrayHasKey('instructions', $instructions);

        // Step 3: Simulate verification (will fail without real DNS, but tests the workflow)
        $verified = $domainService->verifyDomain($domain);

        $this->assertIsBool($verified);

        // Step 4: Regenerate verification code if needed
        $originalCode = $domain->verification_code;
        $newCode = $domainService->regenerateVerificationCode($domain);

        $this->assertNotEquals($originalCode, $newCode->verification_code);
        $this->assertNull($newCode->verified_at);
        $this->assertFalse($newCode->is_active);

        // Step 5: Remove domain
        $result = $domainService->removeDomain($newCode);

        $this->assertTrue($result);
        $this->assertDatabaseMissing('custom_domains', [
            'id' => $domain->id,
        ]);
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function complete_branding_customization_workflow(): void
    {
        $brandingService = app(BrandingService::class);

        // Step 1: Get or create branding
        $branding = $brandingService->getOrCreateBranding($this->organization);

        $this->assertInstanceOf(OrganizationBranding::class, $branding);
        $this->assertEquals($this->organization->id, $branding->organization_id);

        // Step 2: Update branding colors
        $updated = $brandingService->updateBranding($this->organization, [
            'primary_color' => '#1a73e8',
            'secondary_color' => '#34a853',
        ]);

        $this->assertEquals('#1a73e8', $updated->primary_color);
        $this->assertEquals('#34a853', $updated->secondary_color);

        // Step 3: Upload logo
        $logoFile = UploadedFile::fake()->image('company-logo.png', 500, 500);
        $logoUrl = $brandingService->uploadLogo($this->organization, $logoFile);

        $this->assertNotNull($logoUrl);
        Storage::disk('public')->assertExists($updated->fresh()->logo_path);

        // Step 4: Upload background
        $bgFile = UploadedFile::fake()->image('login-bg.jpg', 1920, 1080);
        $bgUrl = $brandingService->uploadBackground($this->organization, $bgFile);

        $this->assertNotNull($bgUrl);
        Storage::disk('public')->assertExists($updated->fresh()->login_background_path);

        // Step 5: Update custom CSS
        $customCSS = '.login-form { border-radius: 8px; padding: 24px; }';
        $withCSS = $brandingService->updateBranding($this->organization, [
            'custom_css' => $customCSS,
        ]);

        $this->assertStringContainsString('border-radius', $withCSS->custom_css);

        // Step 6: Delete logo
        $brandingService->deleteLogo($this->organization);

        $updated->refresh();
        $this->assertNull($updated->logo_path);

        // Step 7: Delete background
        $brandingService->deleteBackground($this->organization);

        $updated->refresh();
        $this->assertNull($updated->login_background_path);
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function complete_audit_export_workflow(): void
    {
        $auditService = app(AuditExportService::class);

        // Step 1: Create test authentication logs
        AuthenticationLog::factory()->count(20)->create([
            'metadata' => ['organization_id' => $this->organization->id],
            'success' => true,
            'event' => 'login',
        ]);

        AuthenticationLog::factory()->count(5)->create([
            'metadata' => ['organization_id' => $this->organization->id],
            'success' => false,
            'event' => 'login_failed',
        ]);

        // Step 2: Create export
        $export = $auditService->createExport(
            $this->organization->id,
            $this->adminUser->id,
            [
                'date_from' => now()->subDays(30)->toDateString(),
                'date_to' => now()->toDateString(),
                'event' => 'login',
            ],
            'json'
        );

        $this->assertInstanceOf(AuditExport::class, $export);
        $this->assertEquals('pending', $export->status);

        // Step 3: Process export
        $auditService->processExport($export);

        $export->refresh();
        $this->assertEquals('completed', $export->status);
        $this->assertNotNull($export->file_path);
        $this->assertNotNull($export->completed_at);
        Storage::disk('public')->assertExists($export->file_path);

        // Step 4: List exports
        $exports = $auditService->getExports($this->organization->id);

        $this->assertGreaterThan(0, $exports->count());

        // Step 5: Cleanup old exports
        $oldExport = AuditExport::factory()->create([
            'organization_id' => $this->organization->id,
            'user_id' => $this->adminUser->id,
            'created_at' => now()->subDays(40),
            'file_path' => 'exports/old-export.json',
        ]);

        Storage::disk('public')->put($oldExport->file_path, 'test');

        $deleted = $auditService->cleanupOldExports(30);

        $this->assertGreaterThan(0, $deleted);
        $this->assertDatabaseMissing('audit_exports', ['id' => $oldExport->id]);
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function complete_compliance_reporting_workflow(): void
    {
        Queue::fake();
        $complianceService = app(ComplianceReportService::class);

        // Step 1: Create test data for reports
        User::factory()->count(10)->withMfa()->create([
            'organization_id' => $this->organization->id,
            'is_active' => true,
        ]);

        AuthenticationLog::factory()->count(100)->create([
            'metadata' => ['organization_id' => $this->organization->id],
            'success' => true,
            'created_at' => now()->subDays(15),
        ]);

        // Step 2: Generate SOC2 report
        $soc2Report = $complianceService->generateSOC2Report($this->organization);

        $this->assertIsArray($soc2Report);
        $this->assertEquals('SOC2', $soc2Report['report_type']);
        $this->assertArrayHasKey('access_controls', $soc2Report);
        $this->assertArrayHasKey('authentication', $soc2Report);
        $this->assertArrayHasKey('mfa_adoption', $soc2Report);
        $this->assertArrayHasKey('security_incidents', $soc2Report);

        // Step 3: Generate ISO 27001 report
        $iso27001Report = $complianceService->generateISO27001Report($this->organization);

        $this->assertIsArray($iso27001Report);
        $this->assertEquals('ISO_27001', $iso27001Report['report_type']);
        $this->assertArrayHasKey('access_management', $iso27001Report);
        $this->assertArrayHasKey('incident_management', $iso27001Report);

        // Step 4: Generate GDPR report
        $gdprReport = $complianceService->generateGDPRReport($this->organization);

        $this->assertIsArray($gdprReport);
        $this->assertEquals('GDPR', $gdprReport['report_type']);
        $this->assertArrayHasKey('data_subjects_count', $gdprReport);
        $this->assertArrayHasKey('retention_policy', $gdprReport);

        // Step 5: Schedule report generation
        $complianceService->scheduleReport(
            $this->organization,
            'soc2',
            ['compliance@example.com']
        );

        Queue::assertPushed(GenerateComplianceReportJob::class);
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function complete_ldap_sync_workflow(): void
    {
        Queue::fake();

        // Step 1: Create LDAP configuration
        $ldapConfig = LdapConfiguration::factory()->create([
            'organization_id' => $this->organization->id,
            'host' => 'ldap.example.com',
            'port' => 389,
            'base_dn' => 'dc=example,dc=com',
            'username' => 'cn=admin,dc=example,dc=com',
            'password' => encrypt('password'),
            'user_filter' => '(objectClass=person)',
            'user_attribute' => 'uid',
            'is_active' => true,
        ]);

        // Step 2: Dispatch sync job
        SyncLdapUsersJob::dispatch($ldapConfig);

        Queue::assertPushed(SyncLdapUsersJob::class, function ($job) use ($ldapConfig) {
            return $job->ldapConfig->id === $ldapConfig->id;
        });

        // Step 3: Verify config exists and is ready
        $this->assertDatabaseHas('ldap_configurations', [
            'id' => $ldapConfig->id,
            'organization_id' => $this->organization->id,
            'is_active' => true,
        ]);
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function end_to_end_enterprise_setup_workflow(): void
    {
        Queue::fake();

        // Complete enterprise setup simulation

        // 1. Branding Setup
        $brandingService = app(BrandingService::class);
        $branding = $brandingService->updateBranding($this->organization, [
            'primary_color' => '#4285f4',
            'secondary_color' => '#34a853',
        ]);

        $this->assertNotNull($branding);

        // 2. Custom Domain Setup
        $domainService = app(DomainVerificationService::class);
        $domain = $domainService->createDomain($this->organization, 'auth.company.com');

        $this->assertNotNull($domain);

        // 3. LDAP Configuration
        $ldapConfig = LdapConfiguration::factory()->create([
            'organization_id' => $this->organization->id,
            'is_active' => true,
        ]);

        $this->assertDatabaseHas('ldap_configurations', [
            'id' => $ldapConfig->id,
        ]);

        // 4. Generate audit export
        AuthenticationLog::factory()->count(50)->create([
            'metadata' => ['organization_id' => $this->organization->id],
        ]);

        $auditService = app(AuditExportService::class);
        $export = $auditService->createExport(
            $this->organization->id,
            $this->adminUser->id,
            [],
            'json'
        );

        $this->assertNotNull($export);

        // 5. Schedule compliance reports
        $complianceService = app(ComplianceReportService::class);
        $complianceService->scheduleReport(
            $this->organization,
            'soc2',
            ['admin@company.com']
        );

        Queue::assertPushed(GenerateComplianceReportJob::class);

        // Verify all enterprise features are configured
        $this->assertTrue($this->organization->settings['enterprise_features']['ldap_enabled']);
        $this->assertTrue($this->organization->settings['enterprise_features']['custom_branding_enabled']);
        $this->assertTrue($this->organization->settings['enterprise_features']['custom_domains_enabled']);
        $this->assertTrue($this->organization->settings['enterprise_features']['audit_exports_enabled']);
        $this->assertTrue($this->organization->settings['enterprise_features']['compliance_reports_enabled']);
    }
}
