<!DOCTYPE html>
<html>
<head>
    <title>Security Audit Report</title>
    <style>
        body { font-family: Arial, sans-serif; font-size: 12px; }
        h1 { color: #333; }
        table { border-collapse: collapse; width: 100%; }
        th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
        th { background-color: #f2f2f2; }
        .warning { color: #e74c3c; }
        .success { color: #27ae60; }
    </style>
</head>
<body>
    <h1>Security Audit Report - {{ $report['organization']['name'] }}</h1>
    
    <h2>Security Summary</h2>
    <p>Failed Logins: {{ $report['security_summary']['total_failed_logins'] ?? 0 }}</p>
    <p>Suspicious IPs: {{ $report['security_summary']['suspicious_ips'] ?? 0 }}</p>
    <p>Users without MFA: <span class="{{ ($report['security_summary']['users_without_mfa'] ?? 0) > 0 ? 'warning' : 'success' }}">{{ $report['security_summary']['users_without_mfa'] ?? 0 }}</span></p>
    <p>Compliance Score: <span class="{{ ($report['security_summary']['compliance_score'] ?? 0) < 70 ? 'warning' : 'success' }}">{{ $report['security_summary']['compliance_score'] ?? 0 }}%</span></p>
    
    <h2>Audit Period</h2>
    <p>From: {{ $report['audit_period']['start'] ?? 'N/A' }}</p>
    <p>To: {{ $report['audit_period']['end'] ?? 'N/A' }}</p>
    
    <h2>Recommendations</h2>
    @if(isset($report['recommendations']) && count($report['recommendations']) > 0)
        <ul>
            @foreach($report['recommendations'] as $recommendation)
                <li>{{ $recommendation }}</li>
            @endforeach
        </ul>
    @endif
    
    <p>Generated: {{ $report['generated_at'] ?? now()->toISOString() }}</p>
</body>
</html>