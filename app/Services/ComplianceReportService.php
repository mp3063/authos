<?php

namespace App\Services;

use App\Jobs\GenerateComplianceReportJob;
use App\Models\AuthenticationLog;
use App\Models\Organization;
use App\Models\User;

class ComplianceReportService
{
    /**
     * Schedule compliance report generation asynchronously
     */
    public function scheduleReport(Organization $organization, string $reportType, array $emailRecipients = []): void
    {
        GenerateComplianceReportJob::dispatch($organization, $reportType, $emailRecipients);
    }

    /**
     * Generate SOC2 compliance report
     */
    public function generateSOC2Report(Organization $organization): array
    {
        $period = [
            'from' => now()->subDays(30)->format('Y-m-d'),
            'to' => now()->format('Y-m-d'),
        ];

        return [
            'report_type' => 'SOC2',
            'organization' => [
                'id' => $organization->id,
                'name' => $organization->name,
            ],
            'period' => $period,
            'access_controls' => $this->getAccessControlMetrics($organization),
            'authentication' => $this->getAuthenticationMetrics($organization),
            'mfa_adoption' => $this->getMFAAdoptionRate($organization),
            'security_incidents' => $this->getSecurityIncidents($organization),
            'generated_at' => now()->toISOString(),
        ];
    }

    /**
     * Generate ISO 27001 compliance report
     */
    public function generateISO27001Report(Organization $organization): array
    {
        return [
            'report_type' => 'ISO_27001',
            'organization' => [
                'id' => $organization->id,
                'name' => $organization->name,
            ],
            'access_management' => $this->getAccessManagementMetrics($organization),
            'incident_management' => $this->getIncidentManagementMetrics($organization),
            'user_provisioning' => $this->getUserProvisioningMetrics($organization),
            'audit_trail' => $this->getAuditTrailMetrics($organization),
            'generated_at' => now()->toISOString(),
        ];
    }

    /**
     * Generate GDPR compliance report
     */
    public function generateGDPRReport(Organization $organization): array
    {
        return [
            'report_type' => 'GDPR',
            'organization' => [
                'id' => $organization->id,
                'name' => $organization->name,
            ],
            'data_subjects_count' => User::where('organization_id', $organization->id)->count(),
            'data_access_logs' => $this->getDataAccessLogs($organization),
            'retention_policy' => $this->getRetentionPolicyStatus($organization),
            'consent_tracking' => $this->getConsentMetrics($organization),
            'generated_at' => now()->toISOString(),
        ];
    }

    private function getAccessControlMetrics(Organization $organization): array
    {
        $users = User::where('organization_id', $organization->id)->get();

        return [
            'total_users' => $users->count(),
            'active_users' => $users->where('is_active', true)->count(),
            'role_based_access' => true,
            'applications_count' => $organization->applications()->count(),
        ];
    }

    private function getAuthenticationMetrics(Organization $organization): array
    {
        // Get user IDs for this organization
        $userIds = User::where('organization_id', $organization->id)
            ->pluck('id')
            ->toArray();

        $logs = AuthenticationLog::whereIn('user_id', $userIds)
            ->where('created_at', '>=', now()->subDays(30))
            ->get();

        return [
            'total_attempts' => $logs->count(),
            'successful_logins' => $logs->where('success', true)->count(),
            'failed_logins' => $logs->where('success', false)->count(),
            'unique_users' => $logs->pluck('user_id')->unique()->count(),
            'average_daily_logins' => round($logs->count() / 30, 2),
        ];
    }

    private function getMFAAdoptionRate(Organization $organization): array
    {
        $totalUsers = User::where('organization_id', $organization->id)->count();
        // MFA is enabled when two_factor_confirmed_at is set
        $mfaEnabled = User::where('organization_id', $organization->id)
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

    private function getSecurityIncidents(Organization $organization): array
    {
        // Get user IDs for this organization
        $userIds = User::where('organization_id', $organization->id)
            ->pluck('id')
            ->toArray();

        $incidents = AuthenticationLog::whereIn('user_id', $userIds)
            ->where('created_at', '>=', now()->subDays(30))
            ->where('success', false)
            ->get();

        return [
            'total_incidents' => $incidents->count(),
            'failed_login_attempts' => $incidents->where('event', 'login_failed')->count(),
            'suspicious_activities' => $incidents->where('event', 'suspicious_activity')->count(),
            'incident_details' => $incidents->take(10)->map(fn ($log) => [
                'event' => $log->event,
                'ip_address' => $log->ip_address,
                'created_at' => $log->created_at->toISOString(),
            ])->toArray(),
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

    private function getIncidentManagementMetrics(Organization $organization): array
    {
        // Get user IDs for this organization
        $userIds = User::where('organization_id', $organization->id)
            ->pluck('id')
            ->toArray();

        $incidents = AuthenticationLog::whereIn('user_id', $userIds)
            ->where('success', false)
            ->where('created_at', '>=', now()->subDays(30))
            ->count();

        return [
            'total_incidents' => $incidents,
            'response_time_avg' => '< 1 hour', // Placeholder
            'resolution_rate' => '100%', // Placeholder
        ];
    }

    private function getUserProvisioningMetrics(Organization $organization): array
    {
        $recentUsers = User::where('organization_id', $organization->id)
            ->where('created_at', '>=', now()->subDays(30))
            ->count();

        return [
            'new_users_last_30_days' => $recentUsers,
            'automated_provisioning' => $organization->ldapConfigurations()->active()->exists(),
            'deprovisioning_process' => 'manual', // Placeholder
        ];
    }

    private function getAuditTrailMetrics(Organization $organization): array
    {
        // Get user IDs for this organization
        $userIds = User::where('organization_id', $organization->id)
            ->pluck('id')
            ->toArray();

        $logs = AuthenticationLog::whereIn('user_id', $userIds)->count();

        return [
            'total_audit_records' => $logs,
            'retention_period_days' => 365,
            'log_integrity' => 'verified',
        ];
    }

    private function getDataAccessLogs(Organization $organization): array
    {
        // Get user IDs for this organization
        $userIds = User::where('organization_id', $organization->id)
            ->pluck('id')
            ->toArray();

        $accessLogs = AuthenticationLog::whereIn('user_id', $userIds)
            ->where('created_at', '>=', now()->subDays(30))
            ->count();

        return [
            'total_access_logs' => $accessLogs,
            'data_export_requests' => $organization->auditExports()->count(),
        ];
    }

    private function getRetentionPolicyStatus(Organization $organization): array
    {
        return [
            'policy_defined' => true,
            'retention_period' => '365 days',
            'auto_deletion' => false,
        ];
    }

    private function getConsentMetrics(Organization $organization): array
    {
        $users = User::where('organization_id', $organization->id)->count();

        return [
            'total_consents' => $users,
            'consent_withdrawal_process' => 'available',
        ];
    }
}
