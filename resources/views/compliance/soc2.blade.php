@php
    $reportLabel = 'SOC 2 Compliance Report';
    $access = $report['access_controls'] ?? [];
    $auth = $report['authentication'] ?? [];
    $mfa = $report['mfa_adoption'] ?? [];
    $incidents = $report['security_incidents'] ?? [];
    $mgmt = $report['incident_management'] ?? [];
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
        <td><div class="num">{{ $access['total_users'] ?? 0 }}</div><div class="lbl">Total users</div></td>
        <td><div class="num">{{ number_format($mfa['adoption_rate_percentage'] ?? 0, 1) }}%</div><div class="lbl">MFA adoption</div></td>
        <td><div class="num">{{ $incidents['total_incidents'] ?? 0 }}</div><div class="lbl">Failed-auth events</div></td>
        <td><div class="num">{{ $mgmt['open_critical_count'] ?? 0 }}</div><div class="lbl">Open critical</div></td>
    </tr>
</table>

<h2>CC6 — Logical and Physical Access Controls</h2>
<table class="kv">
    <tr><td class="label">Total users</td><td>{{ $access['total_users'] ?? 0 }}</td></tr>
    <tr><td class="label">Active users</td><td>{{ $access['active_users'] ?? 0 }}</td></tr>
    <tr><td class="label">Role-based access enforced</td><td>{{ ($access['role_based_access'] ?? false) ? 'Yes' : 'No' }}</td></tr>
    <tr><td class="label">Applications under management</td><td>{{ $access['applications_count'] ?? 0 }}</td></tr>
</table>

<h2>CC6.1 — Authentication Activity (period)</h2>
<table class="kv">
    <tr><td class="label">Total attempts</td><td>{{ $auth['total_attempts'] ?? 0 }}</td></tr>
    <tr><td class="label">Successful logins</td><td>{{ $auth['successful_logins'] ?? 0 }}</td></tr>
    <tr><td class="label">Failed logins</td><td>{{ $auth['failed_logins'] ?? 0 }}</td></tr>
    <tr><td class="label">Unique users</td><td>{{ $auth['unique_users'] ?? 0 }}</td></tr>
    <tr><td class="label">Average daily logins</td><td>{{ $auth['average_daily_logins'] ?? 0 }}</td></tr>
</table>

<h2>CC6.6 — Multi-Factor Authentication</h2>
<table class="kv">
    <tr><td class="label">Users with MFA enabled</td><td>{{ $mfa['mfa_enabled_users'] ?? 0 }} of {{ $mfa['total_users'] ?? 0 }}</td></tr>
    <tr><td class="label">Adoption rate</td><td>{{ number_format($mfa['adoption_rate_percentage'] ?? 0, 2) }}%</td></tr>
    <tr><td class="label">Compliance status</td><td><span class="badge">{{ strtoupper($mfa['compliance_status'] ?? 'unknown') }}</span></td></tr>
</table>

<h2>CC7.3 — Security Incident Detection &amp; Response</h2>
<table class="kv">
    <tr><td class="label">Total incidents in period</td><td>{{ $mgmt['total_incidents'] ?? 0 }}</td></tr>
    <tr><td class="label">Resolved incidents</td><td>{{ $mgmt['resolved_incidents'] ?? 0 }}</td></tr>
    <tr><td class="label">Open critical incidents</td><td>{{ $mgmt['open_critical_count'] ?? 0 }}</td></tr>
    <tr><td class="label">Average response time</td>
        <td>{{ ! empty($mgmt['response_time_avg_minutes']) ? round($mgmt['response_time_avg_minutes']) . ' minutes' : 'No resolved incidents in period' }}</td></tr>
    <tr><td class="label">Resolution rate</td>
        <td>{{ ! empty($mgmt['resolution_rate_percentage']) ? number_format($mgmt['resolution_rate_percentage'], 1) . '%' : 'N/A' }}</td></tr>
</table>

<h3>Recent Failed-Authentication Events (top 10)</h3>
<table>
    <thead><tr><th>Event</th><th>IP Address</th><th>Detected</th></tr></thead>
    <tbody>
        @forelse ($incidents['incident_details'] ?? [] as $item)
            <tr>
                <td>{{ $item['event'] ?? '-' }}</td>
                <td>{{ $redactPii ? \Illuminate\Support\Str::mask($item['ip_address'] ?? '', '*', 4) : ($item['ip_address'] ?? '-') }}</td>
                <td class="small">{{ $item['created_at'] ?? '-' }}</td>
            </tr>
        @empty
            <tr><td colspan="3" class="text-muted small">No failed-authentication events in the reporting period.</td></tr>
        @endforelse
    </tbody>
</table>

<h2>Evidence Appendix</h2>
<p class="small text-muted">A full machine-readable JSON appendix is delivered alongside this PDF. Aggregate metrics in this report were computed from authentication_logs and security_incidents tables for organization #{{ $organization->id }} over the period above.</p>

@include('compliance._footer')
</body>
</html>
