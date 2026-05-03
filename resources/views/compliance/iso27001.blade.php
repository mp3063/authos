@php
    $reportLabel = 'ISO/IEC 27001 Compliance Report';
    $access = $report['access_management'] ?? [];
    $mgmt = $report['incident_management'] ?? [];
    $provisioning = $report['user_provisioning'] ?? [];
    $audit = $report['audit_trail'] ?? [];
@endphp
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>{{ $reportLabel }} — {{ $organization->name }}</title>
    @include('compliance._styles')
</head>
<body>
@include('compliance._header')

<h1>{{ $reportLabel }}</h1>
<p class="meta">Reporting period: <strong>{{ $report['period']['from'] ?? '?' }}</strong> to <strong>{{ $report['period']['to'] ?? '?' }}</strong> ({{ $report['period']['days'] ?? 0 }} days)</p>

<h2>Executive Summary</h2>
<table class="summary-grid">
    <tr>
        <td><div class="num">{{ $access['role_count'] ?? 0 }}</div><div class="lbl">Roles defined</div></td>
        <td><div class="num">{{ $access['permission_count'] ?? 0 }}</div><div class="lbl">Permissions</div></td>
        <td><div class="num">{{ $mgmt['total_incidents'] ?? 0 }}</div><div class="lbl">Incidents in period</div></td>
        <td><div class="num">{{ $audit['retention_period_days'] ?? 0 }}</div><div class="lbl">Retention days</div></td>
    </tr>
</table>

<h2>A.5 — Information Security Policies</h2>
<table class="kv">
    <tr><td class="label">Policy enforcement</td><td>Authentication, MFA, RBAC enforced via platform</td></tr>
    <tr><td class="label">Custom roles defined</td><td>{{ $access['custom_roles'] ?? 0 }}</td></tr>
</table>

<h2>A.8 — Asset Management &amp; A.9 — Access Control</h2>
<table class="kv">
    <tr><td class="label">Roles in use</td><td>{{ $access['role_count'] ?? 0 }}</td></tr>
    <tr><td class="label">Permissions assigned</td><td>{{ $access['permission_count'] ?? 0 }}</td></tr>
    <tr><td class="label">Custom roles</td><td>{{ $access['custom_roles'] ?? 0 }}</td></tr>
</table>

<h3>A.9.2 — User Access Lifecycle</h3>
<table class="kv">
    <tr><td class="label">New users provisioned in period</td><td>{{ $provisioning['new_users_in_period'] ?? $provisioning['new_users_last_30_days'] ?? 0 }}</td></tr>
    <tr><td class="label">Automated provisioning</td><td>{{ ($provisioning['automated_provisioning'] ?? false) ? 'Yes (LDAP)' : 'No' }}</td></tr>
    <tr><td class="label">Deprovisioning process</td><td>{{ str_replace('_', ' ', $provisioning['deprovisioning_process'] ?? 'manual') }}</td></tr>
</table>

<h2>A.16 — Information Security Incident Management</h2>
<table class="kv">
    <tr><td class="label">Total incidents</td><td>{{ $mgmt['total_incidents'] ?? 0 }}</td></tr>
    <tr><td class="label">Resolved incidents</td><td>{{ $mgmt['resolved_incidents'] ?? 0 }}</td></tr>
    <tr><td class="label">Open critical</td><td>{{ $mgmt['open_critical_count'] ?? 0 }}</td></tr>
    <tr><td class="label">Mean response time</td>
        <td>{{ ! empty($mgmt['response_time_avg_minutes']) ? round($mgmt['response_time_avg_minutes']) . ' minutes' : 'No resolved incidents in period' }}</td></tr>
    <tr><td class="label">Resolution rate</td>
        <td>{{ ! empty($mgmt['resolution_rate_percentage']) ? number_format($mgmt['resolution_rate_percentage'], 1) . '%' : 'N/A' }}</td></tr>
</table>

<h2>A.12.4 — Audit Logging</h2>
<table class="kv">
    <tr><td class="label">Total audit records (lifetime)</td><td>{{ $audit['total_audit_records'] ?? 0 }}</td></tr>
    <tr><td class="label">Records in period</td><td>{{ $audit['records_in_period'] ?? 0 }}</td></tr>
    <tr><td class="label">Retention period</td><td>{{ $audit['retention_period_days'] ?? 0 }} days</td></tr>
    <tr><td class="label">Auto-pruning enabled</td><td>{{ ($audit['auto_pruning_enabled'] ?? false) ? 'Yes' : 'No (manual review only)' }}</td></tr>
    <tr><td class="label">Last enforcement</td><td>{{ $audit['last_pruned_at'] ?? 'Not yet enforced' }}</td></tr>
</table>

<p class="small text-muted">Aggregate metrics derived from authentication_logs and security_incidents for organization #{{ $organization->id }}. Full machine-readable evidence is provided in the JSON appendix delivered alongside this PDF.</p>

@include('compliance._footer')
</body>
</html>
