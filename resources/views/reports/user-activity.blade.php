<!DOCTYPE html>
<html>
<head>
    <title>User Activity Report</title>
    <style>
        body { font-family: Arial, sans-serif; font-size: 12px; }
        h1 { color: #333; }
        table { border-collapse: collapse; width: 100%; }
        th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
        th { background-color: #f2f2f2; }
    </style>
</head>
<body>
    <h1>User Activity Report - {{ $report['organization']['name'] }}</h1>
    
    <h2>Summary</h2>
    <p>Total Users: {{ $report['user_statistics']['total_users'] ?? 0 }}</p>
    <p>Active Users: {{ $report['user_statistics']['active_users'] ?? 0 }}</p>
    <p>New Users: {{ $report['user_statistics']['new_users'] ?? 0 }}</p>
    
    <h2>Date Range</h2>
    <p>From: {{ $report['date_range']['start'] ?? 'N/A' }}</p>
    <p>To: {{ $report['date_range']['end'] ?? 'N/A' }}</p>
    
    <p>Generated: {{ $report['generated_at'] ?? now()->toISOString() }}</p>
</body>
</html>