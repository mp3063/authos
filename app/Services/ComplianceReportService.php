<?php

namespace App\Services;

use App\Jobs\GenerateComplianceReportJob;
use App\Models\AuthenticationLog;
use App\Models\DataSubjectRequest;
use App\Models\Organization;
use App\Models\ScheduledComplianceReport;
use App\Models\SecurityIncident;
use App\Models\User;
use App\Models\UserConsent;
use Carbon\CarbonImmutable;
use Carbon\CarbonInterface;

class ComplianceReportService
{
    public function __construct(
        private readonly BrandingService $branding,
    ) {}

    /**
     * Schedule compliance report generation asynchronously
     */
    public function scheduleReport(Organization $organization, string $reportType, array $emailRecipients = []): void
    {
        GenerateComplianceReportJob::dispatch($organization, $reportType, $emailRecipients);
    }

    /**
     * Persist a recurring compliance report schedule.
     */
    public function createSchedule(
        Organization $organization,
        ?User $createdBy,
        string $reportType,
        string $frequency,
        array $recipients,
        bool $isActive = true,
    ): ScheduledComplianceReport {
        $schedule = new ScheduledComplianceReport([
            'organization_id' => $organization->id,
            'created_by_user_id' => $createdBy?->id,
            'report_type' => $reportType,
            'frequency' => $frequency,
            'recipients' => array_values(array_unique($recipients)),
            'is_active' => $isActive,
        ]);

        $schedule->next_run_at = $schedule->computeNextRunAt(CarbonImmutable::now());
        $schedule->save();

        return $schedule;
    }

    /**
     * Update an existing schedule. Only frequency / recipients / type / activation
     * may be changed; created_by stays fixed.
     */
    public function updateSchedule(ScheduledComplianceReport $schedule, array $attributes): ScheduledComplianceReport
    {
        $allowed = array_intersect_key($attributes, array_flip([
            'report_type', 'frequency', 'recipients', 'is_active',
        ]));

        if (isset($allowed['recipients'])) {
            $allowed['recipients'] = array_values(array_unique($allowed['recipients']));
        }

        $frequencyChanged = isset($allowed['frequency']) && $allowed['frequency'] !== $schedule->frequency;

        $schedule->fill($allowed);

        if ($frequencyChanged) {
            $schedule->next_run_at = $schedule->computeNextRunAt(CarbonImmutable::now());
        }

        $schedule->save();

        return $schedule;
    }

    /**
     * Cancel a schedule by deactivating it. We never hard-delete so audit trails
     * still link historical reports back to the schedule that produced them.
     */
    public function cancelSchedule(ScheduledComplianceReport $schedule): void
    {
        $schedule->update(['is_active' => false]);
    }

    /**
     * Generate SOC2 compliance report for the given period
     * (defaults to the last 30 days)
     */
    public function generateSOC2Report(
        Organization $organization,
        ?CarbonInterface $start = null,
        ?CarbonInterface $end = null,
    ): array {
        [$start, $end] = $this->normalizePeriod($start, $end);

        return [
            'report_type' => 'SOC2',
            'organization' => $this->organizationSummary($organization),
            'period' => $this->periodSummary($start, $end),
            'access_controls' => $this->getAccessControlMetrics($organization),
            'authentication' => $this->getAuthenticationMetrics($organization, $start, $end),
            'mfa_adoption' => $this->getMFAAdoptionRate($organization),
            'security_incidents' => $this->getSecurityIncidents($organization, $start, $end),
            'incident_management' => $this->getIncidentManagementMetrics($organization, $start, $end),
            'generated_at' => now()->toISOString(),
        ];
    }

    /**
     * Generate ISO 27001 compliance report for the given period
     */
    public function generateISO27001Report(
        Organization $organization,
        ?CarbonInterface $start = null,
        ?CarbonInterface $end = null,
    ): array {
        [$start, $end] = $this->normalizePeriod($start, $end);

        return [
            'report_type' => 'ISO_27001',
            'organization' => $this->organizationSummary($organization),
            'period' => $this->periodSummary($start, $end),
            'access_management' => $this->getAccessManagementMetrics($organization),
            'incident_management' => $this->getIncidentManagementMetrics($organization, $start, $end),
            'user_provisioning' => $this->getUserProvisioningMetrics($organization, $start, $end),
            'audit_trail' => $this->getAuditTrailMetrics($organization, $start, $end),
            'generated_at' => now()->toISOString(),
        ];
    }

    /**
     * Generate GDPR compliance report for the given period
     */
    public function generateGDPRReport(
        Organization $organization,
        ?CarbonInterface $start = null,
        ?CarbonInterface $end = null,
    ): array {
        [$start, $end] = $this->normalizePeriod($start, $end);

        return [
            'report_type' => 'GDPR',
            'organization' => $this->organizationSummary($organization),
            'period' => $this->periodSummary($start, $end),
            'data_subjects_count' => User::query()
                ->where('organization_id', $organization->id)
                ->count(),
            'data_access_logs' => $this->getDataAccessLogs($organization, $start, $end),
            'retention_policy' => $this->getRetentionPolicyStatus($organization),
            'consent_tracking' => $this->getConsentMetrics($organization, $start, $end),
            'generated_at' => now()->toISOString(),
        ];
    }

    public function getBrandingFor(Organization $organization)
    {
        return $this->branding->getBranding($organization);
    }

    /**
     * @return array{0: CarbonImmutable, 1: CarbonImmutable}
     */
    private function normalizePeriod(?CarbonInterface $start, ?CarbonInterface $end): array
    {
        $end = $end ? CarbonImmutable::instance($end) : CarbonImmutable::now();
        $start = $start ? CarbonImmutable::instance($start) : $end->subDays(30);

        return [$start, $end];
    }

    private function organizationSummary(Organization $organization): array
    {
        return [
            'id' => $organization->id,
            'name' => $organization->name,
        ];
    }

    private function periodSummary(CarbonImmutable $start, CarbonImmutable $end): array
    {
        return [
            'from' => $start->toDateString(),
            'to' => $end->toDateString(),
            'days' => $start->diffInDays($end) + 1,
        ];
    }

    private function getAccessControlMetrics(Organization $organization): array
    {
        $userQuery = User::query()->where('organization_id', $organization->id);
        $totalUsers = (clone $userQuery)->count();
        $activeUsers = (clone $userQuery)->where('is_active', true)->count();

        return [
            'total_users' => $totalUsers,
            'active_users' => $activeUsers,
            'role_based_access' => true,
            'applications_count' => $organization->applications()->count(),
        ];
    }

    private function getAuthenticationMetrics(
        Organization $organization,
        CarbonImmutable $start,
        CarbonImmutable $end,
    ): array {
        $userIds = User::query()
            ->where('organization_id', $organization->id)
            ->pluck('id');

        $base = AuthenticationLog::query()
            ->whereIn('user_id', $userIds)
            ->whereBetween('created_at', [$start, $end]);

        $total = (clone $base)->count();
        $successful = (clone $base)->where('success', true)->count();
        $failed = $total - $successful;
        $uniqueUsers = (clone $base)->distinct('user_id')->count('user_id');
        $days = max(1, (int) $start->diffInDays($end));

        return [
            'total_attempts' => $total,
            'successful_logins' => $successful,
            'failed_logins' => $failed,
            'unique_users' => $uniqueUsers,
            'average_daily_logins' => round($total / $days, 2),
        ];
    }

    private function getMFAAdoptionRate(Organization $organization): array
    {
        $totalUsers = User::query()
            ->where('organization_id', $organization->id)
            ->count();

        $mfaEnabled = User::query()
            ->where('organization_id', $organization->id)
            ->whereNotNull('two_factor_confirmed_at')
            ->count();

        $rate = $totalUsers > 0 ? ($mfaEnabled / $totalUsers) * 100 : 0;

        return [
            'total_users' => $totalUsers,
            'mfa_enabled_users' => $mfaEnabled,
            'adoption_rate_percentage' => round($rate, 2),
            'compliance_status' => $rate >= 90 ? 'compliant' : 'non_compliant',
        ];
    }

    private function getSecurityIncidents(
        Organization $organization,
        CarbonImmutable $start,
        CarbonImmutable $end,
    ): array {
        $userIds = User::query()
            ->where('organization_id', $organization->id)
            ->pluck('id');

        $base = AuthenticationLog::query()
            ->whereIn('user_id', $userIds)
            ->whereBetween('created_at', [$start, $end])
            ->where('success', false);

        $total = (clone $base)->count();
        $failedLogins = (clone $base)->where('event', 'login_failed')->count();
        $suspicious = (clone $base)->where('event', 'suspicious_activity')->count();
        $details = (clone $base)
            ->orderByDesc('created_at')
            ->limit(10)
            ->get(['event', 'ip_address', 'created_at'])
            ->map(fn (AuthenticationLog $log): array => [
                'event' => $log->event,
                'ip_address' => $log->ip_address,
                'created_at' => $log->created_at?->toISOString(),
            ])
            ->all();

        return [
            'total_incidents' => $total,
            'failed_login_attempts' => $failedLogins,
            'suspicious_activities' => $suspicious,
            'incident_details' => $details,
        ];
    }

    private function getAccessManagementMetrics(Organization $organization): array
    {
        return [
            'role_count' => $organization->roles()->count(),
            'permission_count' => $organization->permissions()->count(),
            'custom_roles' => $organization->customRoles()->count(),
        ];
    }

    private function getIncidentManagementMetrics(
        Organization $organization,
        CarbonImmutable $start,
        CarbonImmutable $end,
    ): array {
        $base = SecurityIncident::query()
            ->forOrganization($organization->id)
            ->whereBetween('detected_at', [$start, $end]);

        $total = (clone $base)->count();
        $resolved = (clone $base)->whereNotNull('resolved_at')->count();
        $openCritical = (clone $base)->where('severity', 'critical')->where('status', 'open')->count();

        // Compute average response time in PHP for portability across PostgreSQL/SQLite/MySQL.
        // Bounded by `limit()` plus the period filter; per-org incident counts are small.
        $resolvedRows = (clone $base)
            ->whereNotNull('resolved_at')
            ->limit(5000)
            ->get(['detected_at', 'resolved_at']);

        $avgResponseMinutes = null;
        if ($resolvedRows->isNotEmpty()) {
            $totalSeconds = $resolvedRows->sum(
                fn (SecurityIncident $i): int => $i->resolved_at->diffInSeconds($i->detected_at, true),
            );
            $avgResponseMinutes = round(($totalSeconds / $resolvedRows->count()) / 60, 2);
        }

        return [
            'total_incidents' => $total,
            'resolved_incidents' => $resolved,
            'open_critical_count' => $openCritical,
            'response_time_avg_minutes' => $avgResponseMinutes,
            'resolution_rate_percentage' => $total > 0 ? round(($resolved / $total) * 100, 2) : null,
        ];
    }

    private function getUserProvisioningMetrics(
        Organization $organization,
        CarbonImmutable $start,
        CarbonImmutable $end,
    ): array {
        $newUsers = User::query()
            ->where('organization_id', $organization->id)
            ->whereBetween('created_at', [$start, $end])
            ->count();

        $hasLdap = $organization->ldapConfigurations()->active()->exists();

        return [
            'new_users_in_period' => $newUsers,
            'automated_provisioning' => $hasLdap,
            'deprovisioning_process' => $hasLdap ? 'automated_via_ldap' : 'manual',
        ];
    }

    private function getAuditTrailMetrics(
        Organization $organization,
        CarbonImmutable $start,
        CarbonImmutable $end,
    ): array {
        $userIds = User::query()
            ->where('organization_id', $organization->id)
            ->pluck('id');

        $totalRecords = AuthenticationLog::query()->whereIn('user_id', $userIds)->count();
        $recordsInPeriod = AuthenticationLog::query()
            ->whereIn('user_id', $userIds)
            ->whereBetween('created_at', [$start, $end])
            ->count();

        $securitySettings = (array) ($organization->settings['security'] ?? []);
        $retentionDays = (int) ($securitySettings['retention_period_days']
            ?? config('compliance.default_retention_days'));
        $autoPruning = (bool) ($securitySettings['auto_pruning_enabled'] ?? false);
        $lastPrunedAt = $securitySettings['last_pruned_at'] ?? null;

        return [
            'total_audit_records' => $totalRecords,
            'records_in_period' => $recordsInPeriod,
            'retention_period_days' => $retentionDays,
            'auto_pruning_enabled' => $autoPruning,
            'last_pruned_at' => $lastPrunedAt,
        ];
    }

    private function getDataAccessLogs(
        Organization $organization,
        CarbonImmutable $start,
        CarbonImmutable $end,
    ): array {
        $userIds = User::query()
            ->where('organization_id', $organization->id)
            ->pluck('id');

        $accessLogs = AuthenticationLog::query()
            ->whereIn('user_id', $userIds)
            ->whereBetween('created_at', [$start, $end])
            ->count();

        return [
            'total_access_logs' => $accessLogs,
            'data_export_requests' => $organization->auditExports()->count(),
        ];
    }

    private function getRetentionPolicyStatus(Organization $organization): array
    {
        $securitySettings = (array) ($organization->settings['security'] ?? []);
        $hasExplicitPolicy = isset($securitySettings['retention_period_days']);
        $retentionDays = (int) ($securitySettings['retention_period_days']
            ?? config('compliance.default_retention_days'));
        $autoDeletion = (bool) ($securitySettings['auto_pruning_enabled'] ?? false);
        $lastEnforcedAt = $securitySettings['last_pruned_at'] ?? null;

        return [
            'policy_defined' => $hasExplicitPolicy,
            'retention_period_days' => $retentionDays,
            'auto_deletion' => $autoDeletion,
            'last_enforced_at' => $lastEnforcedAt,
        ];
    }

    private function getConsentMetrics(
        Organization $organization,
        CarbonImmutable $start,
        CarbonImmutable $end,
    ): array {
        $consentBase = UserConsent::query()->forOrganization($organization->id);

        $activeConsents = (clone $consentBase)->active()->count();
        $withdrawnConsents = (clone $consentBase)->withdrawn()->count();
        $totalUsers = User::query()->where('organization_id', $organization->id)->count();
        $coverage = $totalUsers > 0 ? round(($activeConsents / $totalUsers) * 100, 2) : 0.0;

        $dsrCounts = DataSubjectRequest::query()
            ->forOrganization($organization->id)
            ->whereBetween('requested_at', [$start, $end])
            ->selectRaw('request_type, COUNT(*) as count')
            ->groupBy('request_type')
            ->pluck('count', 'request_type')
            ->all();

        return [
            'total_consents_active' => $activeConsents,
            'total_consents_withdrawn' => $withdrawnConsents,
            'consent_coverage_percentage' => $coverage,
            'data_subject_requests' => [
                'access' => (int) ($dsrCounts['access'] ?? 0),
                'rectification' => (int) ($dsrCounts['rectification'] ?? 0),
                'deletion' => (int) ($dsrCounts['deletion'] ?? 0),
                'portability' => (int) ($dsrCounts['portability'] ?? 0),
                'restriction' => (int) ($dsrCounts['restriction'] ?? 0),
            ],
        ];
    }
}
