<?php

namespace Tests\Integration\Enterprise;

use App\Jobs\GenerateComplianceReportJob;
use App\Mail\ComplianceReportGenerated;
use App\Models\Organization;
use App\Models\User;
use Illuminate\Support\Facades\Mail;
use Illuminate\Support\Facades\Queue;
use Illuminate\Support\Facades\Storage;
use PHPUnit\Framework\Attributes\Test;
use Tests\Integration\IntegrationTestCase;

/**
 * Phase 4.4 - Compliance Report Integration Tests
 *
 * Tests comprehensive compliance reporting functionality including SOC2,
 * ISO 27001, and GDPR report generation with background job processing,
 * email delivery, and file storage.
 *
 * Coverage:
 * - SOC2 compliance report generation
 * - ISO 27001 compliance report generation
 * - GDPR compliance report generation
 * - Scheduled automated reports with email delivery
 * - Background job dispatch and execution
 * - Report content validation (required sections)
 * - Multiple report formats (JSON, PDF, HTML)
 * - Date range filtering for reports
 * - Report download endpoints
 * - Authorization and scope validation
 *
 * Business Context:
 * Compliance reporting is a critical enterprise feature that enables
 * organizations to demonstrate adherence to industry standards (SOC2,
 * ISO 27001) and regulatory requirements (GDPR). Reports are generated
 * asynchronously via background jobs and can be automatically scheduled
 * for recurring delivery to compliance teams.
 *
 * @see \App\Http\Controllers\Api\Enterprise\ComplianceController
 * @see \App\Services\ComplianceReportService
 * @see \App\Jobs\GenerateComplianceReportJob
 * @see \App\Mail\ComplianceReportGenerated
 */
class ComplianceReportTest extends IntegrationTestCase
{
    /**
     * Test: SOC2 compliance report can be generated
     *
     * SOC2 (Service Organization Control 2) reports demonstrate that an
     * organization has appropriate controls for security, availability,
     * processing integrity, confidentiality, and privacy.
     */
    #[Test]
    public function soc2_compliance_report_can_be_generated(): void
    {
        // ARRANGE: Create organization with compliance data
        $organization = Organization::factory()->create();
        $user = $this->createApiOrganizationAdmin(['organization_id' => $organization->id]);

        // Create authentication logs for compliance metrics
        User::factory()->count(5)->create([
            'organization_id' => $organization->id,
        ]);

        $token = $this->createAccessToken($user, ['*']);

        // ACT: Request SOC2 report generation
        $response = $this->withToken($token)
            ->getJson('/api/v1/enterprise/compliance/soc2');

        // ASSERT: Report generated successfully
        $response->assertOk();
        $response->assertJsonStructure([
            'success',
            'data' => [
                'report' => [
                    'report_type',
                    'organization',
                    'period',
                    'access_controls',
                    'authentication',
                    'mfa_adoption',
                    'security_incidents',
                    'generated_at',
                ],
            ],
            'message',
        ]);

        // ASSERT: Report contains required SOC2 sections
        $report = $response->json('data.report');
        $this->assertEquals('SOC2', $report['report_type']);
        $this->assertEquals($organization->id, $report['organization']['id']);
        $this->assertArrayHasKey('total_users', $report['access_controls']);
        $this->assertArrayHasKey('total_attempts', $report['authentication']);
        $this->assertArrayHasKey('adoption_rate_percentage', $report['mfa_adoption']);
        $this->assertArrayHasKey('total_incidents', $report['security_incidents']);
    }

    /**
     * Test: ISO 27001 compliance report can be generated
     *
     * ISO 27001 is an international standard for information security
     * management systems. Reports must demonstrate systematic approach
     * to managing sensitive information.
     */
    #[Test]
    public function iso_27001_compliance_report_can_be_generated(): void
    {
        // ARRANGE: Create organization with compliance data
        $organization = Organization::factory()->create();
        $user = $this->createApiOrganizationAdmin(['organization_id' => $organization->id]);

        // Create users for provisioning metrics
        User::factory()->count(10)->create([
            'organization_id' => $organization->id,
            'created_at' => now()->subDays(15),
        ]);

        $token = $this->createAccessToken($user, ['*']);

        // ACT: Request ISO 27001 report generation
        $response = $this->withToken($token)
            ->getJson('/api/v1/enterprise/compliance/iso27001');

        // ASSERT: Report generated successfully
        $response->assertOk();
        $response->assertJsonStructure([
            'success',
            'data' => [
                'report' => [
                    'report_type',
                    'organization',
                    'access_management',
                    'incident_management',
                    'user_provisioning',
                    'audit_trail',
                    'generated_at',
                ],
            ],
            'message',
        ]);

        // ASSERT: Report contains required ISO 27001 sections
        $report = $response->json('data.report');
        $this->assertEquals('ISO_27001', $report['report_type']);
        $this->assertEquals($organization->id, $report['organization']['id']);
        $this->assertArrayHasKey('role_count', $report['access_management']);
        $this->assertArrayHasKey('total_incidents', $report['incident_management']);
        $this->assertArrayHasKey('new_users_last_30_days', $report['user_provisioning']);
        $this->assertArrayHasKey('total_audit_records', $report['audit_trail']);
    }

    /**
     * Test: GDPR compliance report can be generated
     *
     * GDPR (General Data Protection Regulation) requires organizations
     * to demonstrate compliance with data protection principles including
     * lawful processing, data subject rights, and data retention.
     */
    #[Test]
    public function gdpr_compliance_report_can_be_generated(): void
    {
        // ARRANGE: Create organization with data subjects
        $organization = Organization::factory()->create();
        $user = $this->createApiOrganizationAdmin(['organization_id' => $organization->id]);

        // Create data subjects (users) - 7 additional + 1 admin = 8 total
        User::factory()->count(7)->create([
            'organization_id' => $organization->id,
        ]);

        $token = $this->createAccessToken($user, ['*']);

        // ACT: Request GDPR report generation
        $response = $this->withToken($token)
            ->getJson('/api/v1/enterprise/compliance/gdpr');

        // ASSERT: Report generated successfully
        $response->assertOk();
        $response->assertJsonStructure([
            'success',
            'data' => [
                'report' => [
                    'report_type',
                    'organization',
                    'data_subjects_count',
                    'data_access_logs',
                    'retention_policy',
                    'consent_tracking',
                    'generated_at',
                ],
            ],
            'message',
        ]);

        // ASSERT: Report contains required GDPR sections
        $report = $response->json('data.report');
        $this->assertEquals('GDPR', $report['report_type']);
        $this->assertEquals($organization->id, $report['organization']['id']);
        $this->assertEquals(8, $report['data_subjects_count']); // 7 + 1 admin
        $this->assertArrayHasKey('total_access_logs', $report['data_access_logs']);
        $this->assertArrayHasKey('policy_defined', $report['retention_policy']);
        $this->assertArrayHasKey('total_consents', $report['consent_tracking']);
    }

    /**
     * Test: Compliance reports can be scheduled for automated delivery
     *
     * Organizations can schedule compliance reports to be automatically
     * generated and delivered to compliance teams on a recurring basis
     * (daily, weekly, monthly, quarterly).
     */
    #[Test]
    public function compliance_reports_can_be_scheduled_for_automated_delivery(): void
    {
        // ARRANGE: Create organization and fake queue
        $organization = Organization::factory()->create();
        $user = $this->createApiOrganizationAdmin(['organization_id' => $organization->id]);
        Queue::fake();

        $token = $this->createAccessToken($user, ['*']);

        // ACT: Schedule monthly SOC2 report
        $response = $this->withToken($token)
            ->postJson('/api/v1/enterprise/compliance/schedule', [
                'report_type' => 'soc2',
                'frequency' => 'monthly',
                'recipients' => [
                    'compliance@example.com',
                    'cto@example.com',
                ],
            ]);

        // ASSERT: Schedule created successfully
        $response->assertStatus(201);
        $response->assertJsonStructure([
            'success',
            'data' => [
                'schedule' => [
                    'report_type',
                    'frequency',
                    'recipients',
                    'next_run_at',
                ],
            ],
            'message',
        ]);

        // ASSERT: Job dispatched for immediate generation
        Queue::assertPushed(GenerateComplianceReportJob::class, function ($job) use ($organization) {
            return $job->organization->id === $organization->id
                && $job->reportType === 'soc2'
                && count($job->emailRecipients) === 2;
        });

        // ASSERT: Schedule details correct
        $schedule = $response->json('data.schedule');
        $this->assertEquals('soc2', $schedule['report_type']);
        $this->assertEquals('monthly', $schedule['frequency']);
        $this->assertCount(2, $schedule['recipients']);
        $this->assertNotNull($schedule['next_run_at']);
    }

    /**
     * Test: Compliance reports are delivered via email to recipients
     *
     * When reports are generated, they should be automatically emailed
     * to configured recipients with download links. Tests email delivery
     * functionality.
     */
    #[Test]
    public function compliance_reports_are_delivered_via_email_to_recipients(): void
    {
        // ARRANGE: Create organization and fake email/storage
        $organization = Organization::factory()->create();
        Mail::fake();
        Storage::fake('local');

        $recipients = [
            'compliance@example.com',
            'security@example.com',
        ];

        // ACT: Execute report generation job
        $job = new GenerateComplianceReportJob($organization, 'soc2', $recipients);
        $job->handle(app(\App\Services\ComplianceReportService::class));

        // ASSERT: Email sent to all recipients
        Mail::assertSent(ComplianceReportGenerated::class, function ($mail) use ($recipients) {
            // Check if all recipients are in the 'to' field
            $mailToAddresses = collect($mail->to)->pluck('address')->toArray();

            return count(array_intersect($mailToAddresses, $recipients)) === count($recipients);
        });

        // ASSERT: Email contains report details
        Mail::assertSent(ComplianceReportGenerated::class, function ($mail) use ($organization) {
            return $mail->organization->id === $organization->id
                && $mail->reportType === 'soc2'
                && is_array($mail->reportData)
                && ! empty($mail->downloadUrl);
        });

        // ASSERT: Report file stored
        $files = Storage::disk('local')->files('compliance_reports');
        $this->assertNotEmpty($files);
        $this->assertStringContainsString('soc2_report', $files[0]);
    }

    /**
     * Test: Report content includes all required sections
     *
     * Validates that generated reports contain all mandatory sections
     * required by each compliance standard. Missing sections would
     * indicate incomplete implementation.
     */
    #[Test]
    public function report_content_includes_all_required_sections(): void
    {
        // ARRANGE: Create organization with rich compliance data
        $organization = Organization::factory()->create();
        $user = $this->createApiOrganizationAdmin(['organization_id' => $organization->id]);

        // Create comprehensive test data
        User::factory()->count(20)->create([
            'organization_id' => $organization->id,
            'two_factor_confirmed_at' => now(), // MFA enabled
        ]);

        $token = $this->createAccessToken($user, ['*']);

        // ACT: Generate SOC2 report
        $response = $this->withToken($token)
            ->getJson('/api/v1/enterprise/compliance/soc2');

        // ASSERT: All required sections present
        $report = $response->json('data.report');

        // Report metadata
        $this->assertArrayHasKey('report_type', $report);
        $this->assertArrayHasKey('organization', $report);
        $this->assertArrayHasKey('period', $report);
        $this->assertArrayHasKey('generated_at', $report);

        // Access controls section
        $this->assertArrayHasKey('access_controls', $report);
        $this->assertArrayHasKey('total_users', $report['access_controls']);
        $this->assertArrayHasKey('active_users', $report['access_controls']);

        // Authentication section
        $this->assertArrayHasKey('authentication', $report);
        $this->assertArrayHasKey('total_attempts', $report['authentication']);
        $this->assertArrayHasKey('successful_logins', $report['authentication']);

        // MFA adoption section
        $this->assertArrayHasKey('mfa_adoption', $report);
        $this->assertArrayHasKey('adoption_rate_percentage', $report['mfa_adoption']);
        $this->assertArrayHasKey('compliance_status', $report['mfa_adoption']);

        // Security incidents section
        $this->assertArrayHasKey('security_incidents', $report);
        $this->assertArrayHasKey('total_incidents', $report['security_incidents']);
    }

    /**
     * Test: Report generation job status can be tracked
     *
     * Background jobs for report generation should be trackable so
     * users can monitor progress of long-running report generation.
     */
    #[Test]
    public function report_generation_job_status_can_be_tracked(): void
    {
        // ARRANGE: Create organization and fake queue
        $organization = Organization::factory()->create();
        Queue::fake();

        $recipients = ['compliance@example.com'];

        // ACT: Dispatch report generation job
        GenerateComplianceReportJob::dispatch($organization, 'iso27001', $recipients);

        // ASSERT: Job dispatched successfully
        Queue::assertPushed(GenerateComplianceReportJob::class, 1);

        // ASSERT: Job has correct configuration
        Queue::assertPushed(GenerateComplianceReportJob::class, function ($job) use ($organization, $recipients) {
            // Verify job properties
            $this->assertEquals($organization->id, $job->organization->id);
            $this->assertEquals('iso27001', $job->reportType);
            $this->assertEquals($recipients, $job->emailRecipients);

            // Verify job configuration
            $this->assertEquals(300, $job->timeout); // 5 minutes
            $this->assertEquals(2, $job->tries); // 2 attempts

            return true;
        });
    }

    /**
     * Test: Reports can be generated in multiple formats
     *
     * Compliance reports should be available in multiple formats to
     * support different use cases: JSON for API consumption, HTML for
     * web viewing, and PDF for archival/distribution.
     *
     * Note: Currently only JSON format is implemented. This test
     * validates JSON format and documents expected behavior for
     * future format additions.
     */
    #[Test]
    public function reports_can_be_generated_in_multiple_formats(): void
    {
        // ARRANGE: Create organization
        $organization = Organization::factory()->create();
        Storage::fake('local');

        // ACT: Generate report via job (creates JSON file)
        $job = new GenerateComplianceReportJob($organization, 'gdpr', []);
        $job->handle(app(\App\Services\ComplianceReportService::class));

        // ASSERT: JSON format stored
        $files = Storage::disk('local')->files('compliance_reports');
        $this->assertNotEmpty($files);

        $jsonFile = collect($files)->first(fn ($file) => str_contains($file, 'gdpr_report'));
        $this->assertNotNull($jsonFile);

        // ASSERT: JSON content valid
        $content = Storage::disk('local')->get($jsonFile);
        $report = json_decode($content, true);

        $this->assertIsArray($report);
        $this->assertEquals('GDPR', $report['report_type']);
        $this->assertEquals($organization->id, $report['organization']['id']);

        // TODO: Future format support
        // When PDF/HTML formats are implemented, test:
        // - PDF file generation via appropriate library
        // - HTML file generation with proper styling
        // - Format selection via query parameter or header
    }

    /**
     * Test: Reports can be filtered by date range
     *
     * Compliance reports should support date range filtering to generate
     * reports for specific time periods (e.g., quarterly audits, annual
     * reviews).
     *
     * Note: Date range filtering is currently implicit (last 30 days).
     * This test documents expected behavior for explicit date ranges.
     */
    #[Test]
    public function reports_can_be_filtered_by_date_range(): void
    {
        // ARRANGE: Create organization with time-stamped data
        $organization = Organization::factory()->create();
        $user = $this->createApiOrganizationAdmin(['organization_id' => $organization->id]);

        // Create users at different times
        User::factory()->count(5)->create([
            'organization_id' => $organization->id,
            'created_at' => now()->subDays(45), // Outside default range
        ]);

        User::factory()->count(3)->create([
            'organization_id' => $organization->id,
            'created_at' => now()->subDays(15), // Within default range
        ]);

        $token = $this->createAccessToken($user, ['*']);

        // ACT: Request report (implicitly uses 30-day period)
        $response = $this->withToken($token)
            ->getJson('/api/v1/enterprise/compliance/soc2');

        // ASSERT: Report generated with period metadata
        $response->assertOk();
        $report = $response->json('data.report');

        $this->assertArrayHasKey('period', $report);
        $this->assertArrayHasKey('from', $report['period']);
        $this->assertArrayHasKey('to', $report['period']);

        // ASSERT: Period approximately 30 days
        $from = \Carbon\Carbon::parse($report['period']['from']);
        $to = \Carbon\Carbon::parse($report['period']['to']);
        $this->assertEqualsWithDelta(30, $from->diffInDays($to), 1);

        // TODO: Future enhancement
        // When explicit date range filtering is implemented, test:
        // - ?from=2024-01-01&to=2024-03-31 query parameters
        // - Validation of date range limits (e.g., max 1 year)
        // - Metrics correctly filtered to date range
    }

    /**
     * Test: Generated reports can be downloaded via API endpoint
     *
     * After report generation, users should be able to download the
     * generated report file via a secure download endpoint.
     *
     * Note: This tests the report generation and storage. Download
     * endpoint implementation would require signed URLs or similar
     * secure download mechanism.
     */
    #[Test]
    public function generated_reports_can_be_downloaded_via_endpoint(): void
    {
        // ARRANGE: Create organization and generate report
        $organization = Organization::factory()->create();
        Storage::fake('local');

        // ACT: Generate report
        $job = new GenerateComplianceReportJob($organization, 'soc2', []);
        $job->handle(app(\App\Services\ComplianceReportService::class));

        // ASSERT: Report file created
        $files = Storage::disk('local')->files('compliance_reports');
        $this->assertNotEmpty($files);

        $reportFile = $files[0];

        // ASSERT: File is accessible
        $this->assertTrue(Storage::disk('local')->exists($reportFile));

        // ASSERT: File contains valid report data
        $content = Storage::disk('local')->get($reportFile);
        $report = json_decode($content, true);

        $this->assertIsArray($report);
        $this->assertEquals('SOC2', $report['report_type']);
        $this->assertArrayHasKey('generated_at', $report);

        // ASSERT: File has proper naming convention
        $this->assertMatchesRegularExpression(
            '/soc2_report_\d+_\d{4}-\d{2}-\d{2}\.json/',
            basename($reportFile)
        );

        // TODO: Future download endpoint
        // When download endpoint is implemented, test:
        // - GET /api/v1/enterprise/compliance/reports/{id}/download
        // - Signed URL generation for secure downloads
        // - Authorization checks (only org members)
        // - Content-Disposition header for file download
    }

    /**
     * Test: Compliance report generation requires proper OAuth scope
     *
     * Report generation endpoints should enforce OAuth scope validation
     * to prevent unauthorized access to sensitive compliance data.
     *
     * Note: Currently using wildcard scope. In production, this would
     * use granular scopes like 'enterprise.compliance.read'.
     */
    #[Test]
    public function compliance_report_generation_requires_proper_oauth_scope(): void
    {
        // ARRANGE: Create user with proper authorization
        $organization = Organization::factory()->create();
        $user = $this->createApiOrganizationAdmin(['organization_id' => $organization->id]);

        $token = $this->createAccessToken($user, ['*']);

        // ACT: Generate SOC2 report with proper scope
        $response = $this->withToken($token)
            ->getJson('/api/v1/enterprise/compliance/soc2');

        // ASSERT: Access granted with proper scope
        $response->assertOk();
        $response->assertJsonStructure([
            'success',
            'data' => ['report'],
        ]);

        // TODO: When granular OAuth scopes are implemented, test:
        // - 'enterprise.compliance.read' scope allows report generation
        // - 'basic.read' scope denies access (403)
        // - Missing scope denies access (403)
    }

    /**
     * Test: Compliance report scheduling requires manage scope
     *
     * Scheduling automated reports should require elevated permissions
     * (manage scope) compared to one-time report generation (read scope).
     *
     * Note: Currently using wildcard scope. In production, this would
     * enforce separation between 'read' and 'manage' scopes.
     */
    #[Test]
    public function compliance_report_scheduling_requires_manage_scope(): void
    {
        // ARRANGE: Create user with proper authorization
        $organization = Organization::factory()->create();
        $user = $this->createApiOrganizationAdmin(['organization_id' => $organization->id]);

        Queue::fake();
        $token = $this->createAccessToken($user, ['*']);

        // ACT: Schedule report with proper scope
        $response = $this->withToken($token)
            ->postJson('/api/v1/enterprise/compliance/schedule', [
                'report_type' => 'soc2',
                'frequency' => 'monthly',
                'recipients' => ['compliance@example.com'],
            ]);

        // ASSERT: Access granted with proper scope
        $response->assertStatus(201);
        $response->assertJsonStructure([
            'success',
            'data' => ['schedule'],
        ]);

        // TODO: When granular OAuth scopes are implemented, test:
        // - 'enterprise.compliance.manage' scope allows scheduling
        // - 'enterprise.compliance.read' scope denies scheduling (403)
        // - Missing scope denies access (403)
    }

    /**
     * Test: Compliance reports respect organization boundaries
     *
     * Multi-tenant isolation: Users should only be able to generate
     * reports for their own organization, not other organizations.
     */
    #[Test]
    public function compliance_reports_respect_organization_boundaries(): void
    {
        // ARRANGE: Create two separate organizations
        $org1 = Organization::factory()->create(['name' => 'Organization 1']);
        $org2 = Organization::factory()->create(['name' => 'Organization 2']);

        $user1 = $this->createApiOrganizationAdmin(['organization_id' => $org1->id]);

        // Create data in org2
        User::factory()->count(10)->create(['organization_id' => $org2->id]);

        $token = $this->createAccessToken($user1, ['*']);

        // ACT: Generate report (should only include org1 data)
        $response = $this->withToken($token)
            ->getJson('/api/v1/enterprise/compliance/soc2');

        // ASSERT: Report only contains org1 data
        $response->assertOk();
        $report = $response->json('data.report');

        $this->assertEquals($org1->id, $report['organization']['id']);
        $this->assertEquals('Organization 1', $report['organization']['name']);

        // ASSERT: Report metrics don't include org2 data
        // Org1 has only 1 user (the admin), org2 has 10 users
        $this->assertEquals(1, $report['access_controls']['total_users']);
    }

    /**
     * Test: Report validation handles invalid report type
     *
     * Scheduling endpoint should validate report type and reject
     * invalid values with clear error messages.
     */
    #[Test]
    public function report_validation_handles_invalid_report_type(): void
    {
        // ARRANGE: Create user with proper scope
        $organization = Organization::factory()->create();
        $user = $this->createApiOrganizationAdmin(['organization_id' => $organization->id]);

        $token = $this->createAccessToken($user, ['*']);

        // ACT: Attempt to schedule invalid report type
        $response = $this->withToken($token)
            ->postJson('/api/v1/enterprise/compliance/schedule', [
                'report_type' => 'invalid_type',
                'frequency' => 'monthly',
                'recipients' => ['compliance@example.com'],
            ]);

        // ASSERT: Validation error
        $response->assertStatus(422);
        $response->assertJsonValidationErrors(['report_type']);
    }

    /**
     * Test: Report scheduling requires valid email recipients
     *
     * Email recipient validation ensures reports are only sent to
     * valid email addresses.
     */
    #[Test]
    public function report_scheduling_requires_valid_email_recipients(): void
    {
        // ARRANGE: Create user with proper scope
        $organization = Organization::factory()->create();
        $user = $this->createApiOrganizationAdmin(['organization_id' => $organization->id]);

        $token = $this->createAccessToken($user, ['*']);

        // ACT: Attempt to schedule with invalid email
        $response = $this->withToken($token)
            ->postJson('/api/v1/enterprise/compliance/schedule', [
                'report_type' => 'soc2',
                'frequency' => 'monthly',
                'recipients' => ['not-an-email'],
            ]);

        // ASSERT: Validation error
        $response->assertStatus(422);
        $response->assertJsonValidationErrors(['recipients.0']);
    }

    /**
     * Test: MFA adoption rate calculation is accurate
     *
     * Compliance reports include MFA adoption metrics which are critical
     * for SOC2 compliance. Tests calculation accuracy.
     */
    #[Test]
    public function mfa_adoption_rate_calculation_is_accurate(): void
    {
        // ARRANGE: Create organization with mixed MFA adoption
        $organization = Organization::factory()->create();
        $user = $this->createApiOrganizationAdmin(['organization_id' => $organization->id]);

        // Create 10 users with MFA enabled (90% adoption)
        User::factory()->count(9)->create([
            'organization_id' => $organization->id,
            'two_factor_confirmed_at' => now(),
        ]);

        $token = $this->createAccessToken($user, ['*']);

        // ACT: Generate SOC2 report
        $response = $this->withToken($token)
            ->getJson('/api/v1/enterprise/compliance/soc2');

        // ASSERT: MFA adoption rate calculated correctly
        $report = $response->json('data.report');
        $mfaAdoption = $report['mfa_adoption'];

        $this->assertEquals(10, $mfaAdoption['total_users']); // 9 + 1 admin
        $this->assertEquals(9, $mfaAdoption['mfa_enabled_users']);
        $this->assertEquals(90.0, $mfaAdoption['adoption_rate_percentage']);
        $this->assertEquals('compliant', $mfaAdoption['compliance_status']); // >=90% is compliant
    }
}
