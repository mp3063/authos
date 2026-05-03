@php
    $reportLabel = 'GDPR Compliance Report';
    $access = $report['data_access_logs'] ?? [];
    $retention = $report['retention_policy'] ?? [];
    $consent = $report['consent_tracking'] ?? [];
    $dsr = $consent['data_subject_requests'] ?? [];
    $dsrTotal = array_sum($dsr);
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
        <td><div class="num">{{ $report['data_subjects_count'] ?? 0 }}</div><div class="lbl">Data subjects</div></td>
        <td><div class="num">{{ $consent['total_consents_active'] ?? $consent['total_consents'] ?? 0 }}</div><div class="lbl">Active consents</div></td>
        <td><div class="num">{{ number_format($consent['consent_coverage_percentage'] ?? 0, 1) }}%</div><div class="lbl">Coverage</div></td>
        <td><div class="num">{{ $dsrTotal }}</div><div class="lbl">DSRs in period</div></td>
    </tr>
</table>

<h2>Article 5 — Lawfulness, Fairness, Transparency</h2>
<table class="kv">
    <tr><td class="label">Active consents</td><td>{{ $consent['total_consents_active'] ?? $consent['total_consents'] ?? 0 }}</td></tr>
    <tr><td class="label">Withdrawn consents</td><td>{{ $consent['total_consents_withdrawn'] ?? 0 }}</td></tr>
    <tr><td class="label">Coverage of data subjects</td><td>{{ number_format($consent['consent_coverage_percentage'] ?? 0, 2) }}%</td></tr>
</table>

<h2>Articles 15–22 — Data Subject Rights (period)</h2>
<table class="kv">
    <tr><td class="label">Article 15 — Right of Access</td><td>{{ $dsr['access'] ?? 0 }}</td></tr>
    <tr><td class="label">Article 16 — Right to Rectification</td><td>{{ $dsr['rectification'] ?? 0 }}</td></tr>
    <tr><td class="label">Article 17 — Right to Erasure</td><td>{{ $dsr['deletion'] ?? 0 }}</td></tr>
    <tr><td class="label">Article 18 — Right to Restriction</td><td>{{ $dsr['restriction'] ?? 0 }}</td></tr>
    <tr><td class="label">Article 20 — Right to Portability</td><td>{{ $dsr['portability'] ?? 0 }}</td></tr>
</table>

<h2>Article 32 — Security of Processing</h2>
<table class="kv">
    <tr><td class="label">Total access logs in period</td><td>{{ $access['total_access_logs'] ?? 0 }}</td></tr>
    <tr><td class="label">Data export requests issued</td><td>{{ $access['data_export_requests'] ?? 0 }}</td></tr>
</table>

<h2>Article 5(1)(e) — Storage Limitation (Retention)</h2>
<table class="kv">
    <tr><td class="label">Retention policy explicitly defined</td><td>{{ ($retention['policy_defined'] ?? false) ? 'Yes' : 'No (default applied)' }}</td></tr>
    <tr><td class="label">Retention period</td><td>{{ $retention['retention_period_days'] ?? 0 }} days</td></tr>
    <tr><td class="label">Automatic deletion</td><td>{{ ($retention['auto_deletion'] ?? false) ? 'Enabled' : 'Disabled (manual review)' }}</td></tr>
    <tr><td class="label">Last enforcement</td><td>{{ $retention['last_enforced_at'] ?? 'Not yet enforced' }}</td></tr>
</table>

<p class="small text-muted">Consent and DSR figures sourced from user_consents and data_subject_requests tables for organization #{{ $organization->id }}. The full record-level breakdown is in the JSON appendix delivered alongside this PDF.</p>

@include('compliance._footer')
</body>
</html>
