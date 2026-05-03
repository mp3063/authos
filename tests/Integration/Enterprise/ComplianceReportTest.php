<?php

namespace Tests\Integration\Enterprise;

use App\Http\Controllers\Api\Enterprise\ComplianceController;
use App\Jobs\GenerateComplianceReportJob;
use App\Mail\ComplianceReportGenerated;
use App\Models\ComplianceReport;
use App\Models\DataSubjectRequest;
use App\Models\LdapConfiguration;
use App\Models\Organization;
use App\Models\User;
use App\Models\UserConsent;
use App\Services\ComplianceReportService;
use Carbon\Carbon;
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
 * @see ComplianceController
 * @see ComplianceReportService
 * @see GenerateComplianceReportJob
 * @see ComplianceReportGenerated
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
        $this->assertArrayHasKey('new_users_in_period', $report['user_provisioning']);
        $this->assertArrayHasKey('automated_provisioning', $report['user_provisioning']);
        $this->assertArrayHasKey('deprovisioning_process', $report['user_provisioning']);
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
        $this->assertArrayHasKey('total_consents_active', $report['consent_tracking']);
        $this->assertArrayHasKey('total_consents_withdrawn', $report['consent_tracking']);
        $this->assertArrayHasKey('consent_coverage_percentage', $report['consent_tracking']);
        $this->assertArrayHasKey('data_subject_requests', $report['consent_tracking']);
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

        // ASSERT: Schedule created successfully (full Step-3 response shape)
        $response->assertStatus(201);
        $response->assertJsonStructure([
            'success',
            'data' => [
                'schedule' => [
                    'id',
                    'report_type',
                    'frequency',
                    'recipients',
                    'is_active',
                    'next_run_at',
                    'last_run_at',
                    'created_at',
                ],
            ],
            'message',
        ]);

        // ASSERT: Persisted to scheduled_compliance_reports (Step 3 fixed the silent-drop)
        $this->assertDatabaseHas('scheduled_compliance_reports', [
            'organization_id' => $organization->id,
            'report_type' => 'soc2',
            'frequency' => 'monthly',
            'is_active' => true,
        ]);

        // ASSERT: Job dispatched for immediate generation (current controller behavior)
        Queue::assertPushed(GenerateComplianceReportJob::class, function ($job) use ($organization) {
            return $job->organization->id === $organization->id
                && $job->reportType === 'soc2'
                && count($job->emailRecipients) === 2;
        });

        // ASSERT: Schedule details correct
        $schedule = $response->json('data.schedule');
        $this->assertNotNull($schedule['id']);
        $this->assertEquals('soc2', $schedule['report_type']);
        $this->assertEquals('monthly', $schedule['frequency']);
        $this->assertCount(2, $schedule['recipients']);
        $this->assertTrue($schedule['is_active']);
        $this->assertNotNull($schedule['next_run_at']);
        $this->assertNull($schedule['last_run_at']);
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
        $job->handle(app(ComplianceReportService::class));

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

        // ASSERT: Report files stored (now in per-org subdirs)
        $files = Storage::disk('local')->allFiles('compliance_reports');
        $this->assertNotEmpty($files);
        $this->assertContains(true, array_map(fn ($f) => str_contains($f, '/soc2_'), $files));
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
     * Test: Reports are generated as both JSON and PDF
     *
     * Step 4 added DomPDF rendering. Each generation now produces a
     * sibling PDF file alongside the JSON for auditor distribution.
     */
    #[Test]
    public function reports_can_be_generated_in_multiple_formats(): void
    {
        // ARRANGE: Create organization
        $organization = Organization::factory()->create();
        Storage::fake('local');

        // ACT: Generate report via job (creates JSON + PDF in per-org subdir)
        $job = new GenerateComplianceReportJob($organization, 'gdpr', []);
        $job->handle(app(ComplianceReportService::class));

        // ASSERT: Both formats stored under compliance_reports/{org_id}/
        $files = Storage::disk('local')->allFiles("compliance_reports/{$organization->id}");
        $this->assertNotEmpty($files);

        $jsonFile = collect($files)->first(fn ($file) => str_contains($file, '/gdpr_') && str_ends_with($file, '.json'));
        $pdfFile = collect($files)->first(fn ($file) => str_contains($file, '/gdpr_') && str_ends_with($file, '.pdf'));

        $this->assertNotNull($jsonFile, 'JSON report file should exist');
        $this->assertNotNull($pdfFile, 'PDF report file should exist');

        // ASSERT: JSON content valid
        $content = Storage::disk('local')->get($jsonFile);
        $report = json_decode($content, true);

        $this->assertIsArray($report);
        $this->assertEquals('GDPR', $report['report_type']);
        $this->assertEquals($organization->id, $report['organization']['id']);

        // ASSERT: PDF starts with the magic bytes and is not trivially empty
        $pdfContent = Storage::disk('local')->get($pdfFile);
        $this->assertStringStartsWith('%PDF-', $pdfContent);
        $this->assertGreaterThan(1024, strlen($pdfContent));
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
        $from = Carbon::parse($report['period']['from']);
        $to = Carbon::parse($report['period']['to']);
        $this->assertEqualsWithDelta(30, $from->diffInDays($to), 1);

        // TODO: Future enhancement
        // When explicit date range filtering is implemented, test:
        // - ?from=2024-01-01&to=2024-03-31 query parameters
        // - Validation of date range limits (e.g., max 1 year)
        // - Metrics correctly filtered to date range
    }

    /**
     * Test: Generated reports can be downloaded via the API endpoint
     *
     * Step 5 added GET /api/v1/enterprise/compliance/reports/{id}/download
     * with org-scoped lookup, format selection, expiry checks, and
     * defense-in-depth path validation.
     */
    #[Test]
    public function generated_reports_can_be_downloaded_via_endpoint(): void
    {
        // ARRANGE: Create org + generate report (Job persists ComplianceReport row)
        $organization = Organization::factory()->create();
        $user = $this->createApiOrganizationAdmin(['organization_id' => $organization->id]);
        Storage::fake('local');

        $job = new GenerateComplianceReportJob($organization, 'soc2', []);
        $job->handle(app(ComplianceReportService::class));

        $report = ComplianceReport::query()
            ->where('organization_id', $organization->id)
            ->where('report_type', 'soc2')
            ->firstOrFail();

        $this->assertEquals('completed', $report->status);
        $this->assertNotNull($report->file_path_pdf);
        $this->assertNotNull($report->file_path_json);

        $token = $this->createAccessToken($user, ['*']);

        // ACT + ASSERT: PDF download
        $pdfResponse = $this->withToken($token)
            ->get("/api/v1/enterprise/compliance/reports/{$report->id}/download?format=pdf");

        $pdfResponse->assertOk();
        $pdfResponse->assertHeader('Content-Type', 'application/pdf');
        $this->assertStringStartsWith('%PDF-', $pdfResponse->streamedContent());

        // ACT + ASSERT: JSON download
        $jsonResponse = $this->withToken($token)
            ->get("/api/v1/enterprise/compliance/reports/{$report->id}/download?format=json");

        $jsonResponse->assertOk();
        $jsonResponse->assertHeader('Content-Type', 'application/json');
        $this->assertNotEmpty($jsonResponse->streamedContent());

        // ASSERT: Defense-in-depth namespace prefix held by Step 5's controller check
        $this->assertStringStartsWith("compliance_reports/{$organization->id}/", $report->file_path_pdf);
        $this->assertStringStartsWith("compliance_reports/{$organization->id}/", $report->file_path_json);
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

    /**
     * Test: GenerateComplianceReportJob persists a ComplianceReport row
     *
     * Step 4 changed the job from "render JSON to disk" to "create row,
     * render JSON+PDF, update row to completed with file paths and
     * top-line summary."
     */
    #[Test]
    public function generate_compliance_report_job_persists_a_completed_report_row(): void
    {
        // ARRANGE
        $organization = Organization::factory()->create();
        Storage::fake('local');

        // ACT
        GenerateComplianceReportJob::dispatchSync($organization, 'soc2', []);

        // ASSERT: row written with status=completed and file paths
        $report = ComplianceReport::query()
            ->where('organization_id', $organization->id)
            ->latest('id')
            ->first();

        $this->assertNotNull($report);
        $this->assertEquals('soc2', $report->report_type);
        $this->assertEquals('completed', $report->status);
        $this->assertNotNull($report->file_path_pdf);
        $this->assertNotNull($report->file_path_json);
        $this->assertNotNull($report->generated_at);
        $this->assertNotNull($report->expires_at);
        $this->assertIsArray($report->summary);
        $this->assertArrayHasKey('mfa_adoption_rate', $report->summary);

        // ASSERT: physical files exist on the fake disk
        $this->assertTrue(Storage::disk('local')->exists($report->file_path_pdf));
        $this->assertTrue(Storage::disk('local')->exists($report->file_path_json));
    }

    /**
     * Test: GDPR consent metrics reflect persisted UserConsent rows
     *
     * Step 7 introduced the user_consents table. The service now counts
     * actual rows instead of returning the placeholder string 'available'.
     */
    #[Test]
    public function gdpr_consent_metrics_reflect_persisted_user_consents(): void
    {
        // ARRANGE: 5 users in org. 3 active consents, 2 withdrawn.
        $organization = Organization::factory()->create();
        $users = User::factory()->count(5)->create(['organization_id' => $organization->id]);

        foreach ($users->take(3) as $u) {
            UserConsent::factory()->create([
                'organization_id' => $organization->id,
                'user_id' => $u->id,
            ]);
        }
        foreach ($users->slice(3, 2) as $u) {
            UserConsent::factory()->withdrawn()->create([
                'organization_id' => $organization->id,
                'user_id' => $u->id,
            ]);
        }

        // ACT
        $report = app(ComplianceReportService::class)->generateGDPRReport($organization);

        // ASSERT: real counts (no placeholder strings)
        $consent = $report['consent_tracking'];
        $this->assertEquals(3, $consent['total_consents_active']);
        $this->assertEquals(2, $consent['total_consents_withdrawn']);
        // 3 active / 5 total users = 60.0
        $this->assertEqualsWithDelta(60.0, $consent['consent_coverage_percentage'], 0.01);
    }

    /**
     * Test: GDPR report bucket-counts data subject requests by type
     */
    #[Test]
    public function gdpr_report_includes_data_subject_request_counts_by_type(): void
    {
        // ARRANGE
        $organization = Organization::factory()->create();
        $users = User::factory()->count(3)->create(['organization_id' => $organization->id]);

        DataSubjectRequest::factory()
            ->count(2)
            ->ofType(DataSubjectRequest::TYPE_ACCESS)
            ->create(['organization_id' => $organization->id, 'user_id' => $users->first()->id]);

        DataSubjectRequest::factory()
            ->ofType(DataSubjectRequest::TYPE_DELETION)
            ->create(['organization_id' => $organization->id, 'user_id' => $users->first()->id]);

        // ACT
        $report = app(ComplianceReportService::class)->generateGDPRReport($organization);

        // ASSERT
        $dsr = $report['consent_tracking']['data_subject_requests'];
        $this->assertEquals(2, $dsr['access']);
        $this->assertEquals(1, $dsr['deletion']);
        $this->assertEquals(0, $dsr['rectification']);
        $this->assertEquals(0, $dsr['portability']);
        $this->assertEquals(0, $dsr['restriction']);
    }

    /**
     * Test: ISO 27001 user provisioning detects active LDAP configuration
     *
     * Step 2 replaced hardcoded 'manual' with a dynamic check against
     * the organization's active LDAP configurations.
     */
    #[Test]
    public function iso27001_user_provisioning_reports_automated_via_ldap_when_configured(): void
    {
        // ARRANGE: org with an active LDAP config
        $organization = Organization::factory()->create();
        LdapConfiguration::factory()->create([
            'organization_id' => $organization->id,
            'is_active' => true,
        ]);

        // ACT
        $report = app(ComplianceReportService::class)->generateISO27001Report($organization);

        // ASSERT
        $this->assertTrue($report['user_provisioning']['automated_provisioning']);
        $this->assertEquals('automated_via_ldap', $report['user_provisioning']['deprovisioning_process']);
    }

    /**
     * Test: ISO 27001 user provisioning falls back to manual without LDAP
     */
    #[Test]
    public function iso27001_user_provisioning_reports_manual_without_ldap(): void
    {
        // ARRANGE: org with no LDAP config
        $organization = Organization::factory()->create();

        // ACT
        $report = app(ComplianceReportService::class)->generateISO27001Report($organization);

        // ASSERT
        $this->assertFalse($report['user_provisioning']['automated_provisioning']);
        $this->assertEquals('manual', $report['user_provisioning']['deprovisioning_process']);
    }

    /**
     * Test: GDPR retention policy reflects organization security settings
     *
     * Step 2 made retention values read from organization.settings.security
     * instead of the hardcoded 365/false placeholders.
     */
    #[Test]
    public function gdpr_retention_policy_reflects_organization_security_settings(): void
    {
        // ARRANGE: org with explicit retention settings
        $organization = Organization::factory()->create([
            'settings' => [
                'security' => [
                    'retention_period_days' => 720,
                    'auto_pruning_enabled' => true,
                    'last_pruned_at' => '2026-04-01T00:00:00Z',
                ],
            ],
        ]);

        // ACT
        $report = app(ComplianceReportService::class)->generateGDPRReport($organization);

        // ASSERT
        $retention = $report['retention_policy'];
        $this->assertTrue($retention['policy_defined']);
        $this->assertEquals(720, $retention['retention_period_days']);
        $this->assertTrue($retention['auto_deletion']);
        $this->assertEquals('2026-04-01T00:00:00Z', $retention['last_enforced_at']);
    }

    /**
     * Test: Cross-org download attempts are rejected
     *
     * Step 5's downloadReport uses forOrganization(...)->findOrFail, so
     * org B cannot read org A's reports even with a known report id.
     */
    #[Test]
    public function download_endpoint_rejects_cross_organization_report_access(): void
    {
        // ARRANGE: report owned by org1; admin token is for org2
        $org1 = Organization::factory()->create();
        $org2 = Organization::factory()->create();
        $org2Admin = $this->createApiOrganizationAdmin(['organization_id' => $org2->id]);
        Storage::fake('local');

        $job = new GenerateComplianceReportJob($org1, 'gdpr', []);
        $job->handle(app(ComplianceReportService::class));

        $org1Report = ComplianceReport::query()
            ->where('organization_id', $org1->id)
            ->firstOrFail();

        $token = $this->createAccessToken($org2Admin, ['*']);

        // ACT: org2 admin attempts to download org1's report
        $response = $this->withToken($token)
            ->getJson("/api/v1/enterprise/compliance/reports/{$org1Report->id}/download?format=pdf");

        // ASSERT
        $response->assertNotFound();
    }
}
