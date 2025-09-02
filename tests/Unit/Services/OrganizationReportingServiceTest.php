<?php

namespace Tests\Unit\Services;

use App\Models\Application;
use App\Models\AuthenticationLog;
use App\Models\Organization;
use App\Models\User;
use App\Services\OrganizationReportingService;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\Storage;
use Tests\TestCase;
use Carbon\Carbon;

class OrganizationReportingServiceTest extends TestCase
{
    use RefreshDatabase;

    private OrganizationReportingService $reportingService;
    private Organization $organization;
    private User $user;
    private Application $application;

    protected function setUp(): void
    {
        parent::setUp();
        
        $this->reportingService = app(OrganizationReportingService::class);
        $this->organization = Organization::factory()->create();
        $this->user = User::factory()->forOrganization($this->organization)->create();
        $this->application = Application::factory()->forOrganization($this->organization)->create();
        
        Storage::fake('local');
    }

    public function test_generate_user_activity_report_creates_comprehensive_report(): void
    {
        // Create authentication logs
        AuthenticationLog::factory()
            ->count(5)
            ->forUser($this->user)
            ->successfulLogin()
            ->create();

        AuthenticationLog::factory()
            ->count(2)
            ->forUser($this->user)
            ->failedLogin()
            ->create();

        AuthenticationLog::factory()
            ->forUser($this->user)
            ->mfaEvent('mfa_enabled')
            ->create();

        $report = $this->reportingService->generateUserActivityReport(
            $this->organization->id,
            Carbon::now()->subDays(30),
            Carbon::now()
        );

        $this->assertArrayHasKey('summary', $report);
        $this->assertArrayHasKey('users', $report);
        $this->assertArrayHasKey('activity_timeline', $report);
        $this->assertArrayHasKey('security_events', $report);

        $summary = $report['summary'];
        $this->assertEquals(1, $summary['total_users']);
        $this->assertEquals(5, $summary['successful_logins']);
        $this->assertEquals(2, $summary['failed_logins']);
        $this->assertEquals(1, $summary['mfa_events']);

        $this->assertCount(1, $report['users']);
        $userReport = $report['users'][0];
        $this->assertEquals($this->user->id, $userReport['user_id']);
        $this->assertEquals(5, $userReport['successful_logins']);
        $this->assertEquals(2, $userReport['failed_logins']);
    }

    public function test_generate_application_usage_report_tracks_application_metrics(): void
    {
        // Create user-application relationships
        $this->user->applications()->attach($this->application->id, [
            'permissions' => ['read', 'write'],
            'last_accessed_at' => Carbon::now()->subDays(1),
            'access_count' => 10,
        ]);

        // Create authentication logs for the application context
        AuthenticationLog::factory()
            ->count(8)
            ->forUser($this->user)
            ->successfulLogin()
            ->create([
                'details' => ['application_id' => $this->application->id]
            ]);

        $report = $this->reportingService->generateApplicationUsageReport(
            $this->organization->id,
            Carbon::now()->subDays(30),
            Carbon::now()
        );

        $this->assertArrayHasKey('summary', $report);
        $this->assertArrayHasKey('applications', $report);
        $this->assertArrayHasKey('usage_trends', $report);
        $this->assertArrayHasKey('top_applications', $report);

        $summary = $report['summary'];
        $this->assertEquals(1, $summary['total_applications']);
        $this->assertEquals(1, $summary['active_applications']);

        $this->assertCount(1, $report['applications']);
        $appReport = $report['applications'][0];
        $this->assertEquals($this->application->id, $appReport['application_id']);
        $this->assertEquals(1, $appReport['user_count']);
    }

    public function test_generate_security_audit_report_identifies_security_events(): void
    {
        // Create various security-related events
        AuthenticationLog::factory()
            ->count(3)
            ->forUser($this->user)
            ->failedLogin()
            ->create();

        AuthenticationLog::factory()
            ->forUser($this->user)
            ->highRisk()
            ->create(['event' => 'login']);

        AuthenticationLog::factory()
            ->forUser($this->user)
            ->create(['event' => 'account_locked']);

        $report = $this->reportingService->generateSecurityAuditReport(
            $this->organization->id,
            Carbon::now()->subDays(30),
            Carbon::now()
        );

        $this->assertArrayHasKey('summary', $report);
        $this->assertArrayHasKey('security_events', $report);
        $this->assertArrayHasKey('risk_analysis', $report);
        $this->assertArrayHasKey('failed_login_analysis', $report);
        $this->assertArrayHasKey('recommendations', $report);

        $summary = $report['summary'];
        $this->assertEquals(3, $summary['failed_login_attempts']);
        $this->assertEquals(1, $summary['high_risk_events']);
        $this->assertEquals(1, $summary['account_lockouts']);

        $this->assertNotEmpty($report['recommendations']);
    }

    public function test_export_report_to_pdf_creates_pdf_file(): void
    {
        $reportData = [
            'title' => 'Test Report',
            'organization' => $this->organization,
            'generated_at' => Carbon::now(),
            'summary' => ['total_users' => 1],
            'data' => ['test' => 'data'],
        ];

        $pdfPath = $this->reportingService->exportReportToPDF(
            $reportData,
            'user_activity',
            $this->organization->id
        );

        $this->assertNotNull($pdfPath);
        Storage::disk('local')->assertExists($pdfPath);
        $this->assertStringContains('.pdf', $pdfPath);
        $this->assertStringContains('user_activity', $pdfPath);
        $this->assertStringContains((string) $this->organization->id, $pdfPath);
    }

    public function test_export_report_to_excel_creates_excel_file(): void
    {
        $reportData = [
            'summary' => ['total_users' => 1, 'successful_logins' => 10],
            'users' => [
                ['name' => $this->user->name, 'email' => $this->user->email, 'login_count' => 10],
            ],
        ];

        $excelPath = $this->reportingService->exportReportToExcel(
            $reportData,
            'user_activity',
            $this->organization->id
        );

        $this->assertNotNull($excelPath);
        Storage::disk('local')->assertExists($excelPath);
        $this->assertStringContains('.xlsx', $excelPath);
    }

    public function test_get_activity_trends_calculates_time_series_data(): void
    {
        // Create login events across different days
        $dates = [
            Carbon::now()->subDays(5),
            Carbon::now()->subDays(4),
            Carbon::now()->subDays(3),
            Carbon::now()->subDays(1),
        ];

        foreach ($dates as $date) {
            AuthenticationLog::factory()
                ->forUser($this->user)
                ->successfulLogin()
                ->create(['created_at' => $date]);
        }

        $trends = $this->reportingService->getActivityTrends(
            $this->organization->id,
            Carbon::now()->subDays(7),
            Carbon::now()
        );

        $this->assertArrayHasKey('daily_logins', $trends);
        $this->assertArrayHasKey('hourly_distribution', $trends);
        $this->assertArrayHasKey('day_of_week_distribution', $trends);

        $this->assertCount(8, $trends['daily_logins']); // 7 days + today
        $this->assertEquals(4, array_sum(array_column($trends['daily_logins'], 'count')));
    }

    public function test_get_user_engagement_metrics_calculates_user_statistics(): void
    {
        // Create users with different activity levels
        $activeUser = User::factory()->forOrganization($this->organization)->create();
        $inactiveUser = User::factory()->forOrganization($this->organization)->create();

        // Active user logs
        AuthenticationLog::factory()
            ->count(10)
            ->forUser($activeUser)
            ->recent()
            ->create();

        // Inactive user has old logs
        AuthenticationLog::factory()
            ->forUser($inactiveUser)
            ->create(['created_at' => Carbon::now()->subDays(35)]);

        $metrics = $this->reportingService->getUserEngagementMetrics(
            $this->organization->id,
            Carbon::now()->subDays(30),
            Carbon::now()
        );

        $this->assertArrayHasKey('active_users', $metrics);
        $this->assertArrayHasKey('inactive_users', $metrics);
        $this->assertArrayHasKey('engagement_score', $metrics);
        $this->assertArrayHasKey('user_segments', $metrics);

        $this->assertEquals(1, $metrics['active_users']);
        $this->assertEquals(1, $metrics['inactive_users']);
        $this->assertGreaterThan(0, $metrics['engagement_score']);
    }

    public function test_get_risk_analysis_identifies_security_patterns(): void
    {
        // Create high-risk events
        AuthenticationLog::factory()
            ->count(2)
            ->forUser($this->user)
            ->highRisk()
            ->fromIp('192.168.1.100')
            ->create();

        // Create failed login attempts
        AuthenticationLog::factory()
            ->count(5)
            ->forUser($this->user)
            ->failedLogin()
            ->fromIp('10.0.0.1')
            ->create();

        $riskAnalysis = $this->reportingService->getRiskAnalysis(
            $this->organization->id,
            Carbon::now()->subDays(7),
            Carbon::now()
        );

        $this->assertArrayHasKey('high_risk_events', $riskAnalysis);
        $this->assertArrayHasKey('suspicious_ips', $riskAnalysis);
        $this->assertArrayHasKey('failed_login_patterns', $riskAnalysis);
        $this->assertArrayHasKey('risk_score', $riskAnalysis);

        $this->assertEquals(2, $riskAnalysis['high_risk_events']);
        $this->assertContains('10.0.0.1', array_column($riskAnalysis['suspicious_ips'], 'ip'));
        $this->assertGreaterThan(0, $riskAnalysis['risk_score']);
    }

    public function test_schedule_recurring_report_creates_scheduled_task(): void
    {
        $scheduleId = $this->reportingService->scheduleRecurringReport([
            'organization_id' => $this->organization->id,
            'report_type' => 'user_activity',
            'frequency' => 'weekly',
            'recipients' => ['admin@example.com'],
            'format' => 'pdf',
        ]);

        $this->assertNotNull($scheduleId);
        $this->assertDatabaseHas('report_schedules', [
            'id' => $scheduleId,
            'organization_id' => $this->organization->id,
            'report_type' => 'user_activity',
            'frequency' => 'weekly',
        ]);
    }

    public function test_get_comparative_report_compares_time_periods(): void
    {
        // Create data for current period
        AuthenticationLog::factory()
            ->count(10)
            ->forUser($this->user)
            ->create(['created_at' => Carbon::now()->subDays(7)]);

        // Create data for previous period
        AuthenticationLog::factory()
            ->count(5)
            ->forUser($this->user)
            ->create(['created_at' => Carbon::now()->subDays(14)]);

        $comparison = $this->reportingService->getComparativeReport(
            $this->organization->id,
            Carbon::now()->subDays(14),
            Carbon::now()->subDays(7),
            Carbon::now()->subDays(7),
            Carbon::now()
        );

        $this->assertArrayHasKey('current_period', $comparison);
        $this->assertArrayHasKey('previous_period', $comparison);
        $this->assertArrayHasKey('comparison', $comparison);

        $this->assertEquals(10, $comparison['current_period']['total_events']);
        $this->assertEquals(5, $comparison['previous_period']['total_events']);
        $this->assertEquals(100, $comparison['comparison']['change_percentage']); // 100% increase
    }

    public function test_get_custom_metrics_applies_filters_and_grouping(): void
    {
        // Create diverse authentication logs
        AuthenticationLog::factory()
            ->forUser($this->user)
            ->successfulLogin()
            ->create(['details' => ['method' => 'password']]);

        AuthenticationLog::factory()
            ->forUser($this->user)
            ->successfulLogin()
            ->create(['details' => ['method' => 'oauth']]);

        $metrics = $this->reportingService->getCustomMetrics([
            'organization_id' => $this->organization->id,
            'date_range' => [Carbon::now()->subDays(1), Carbon::now()],
            'filters' => ['event' => 'login', 'success' => true],
            'group_by' => 'details->method',
            'metrics' => ['count', 'unique_users'],
        ]);

        $this->assertArrayHasKey('results', $metrics);
        $this->assertArrayHasKey('summary', $metrics);
        
        $results = $metrics['results'];
        $this->assertCount(2, $results); // password and oauth methods
        
        foreach ($results as $result) {
            $this->assertArrayHasKey('group_value', $result);
            $this->assertArrayHasKey('count', $result);
            $this->assertArrayHasKey('unique_users', $result);
        }
    }
}