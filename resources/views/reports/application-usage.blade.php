<!DOCTYPE html>
<html>
<head>
    <title>Application Usage Report</title>
    <style>
        body { font-family: Arial, sans-serif; font-size: 12px; }
        h1 { color: #333; }
        table { border-collapse: collapse; width: 100%; }
        th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
        th { background-color: #f2f2f2; }
    </style>
</head>
<body>
    <h1>Application Usage Report - {{ $report['organization']['name'] }}</h1>
    
    <h2>Summary</h2>
    <p>Total Applications: {{ $report['summary']['total_applications'] ?? 0 }}</p>
    <p>Active Applications: {{ $report['summary']['active_applications'] ?? 0 }}</p>
    <p>Total Users: {{ $report['summary']['total_users_across_apps'] ?? 0 }}</p>
    
    <h2>Applications</h2>
    @if(isset($report['applications']) && count($report['applications']) > 0)
        <table>
            <thead>
                <tr>
                    <th>Name</th>
                    <th>Users</th>
                    <th>Status</th>
                </tr>
            </thead>
            <tbody>
                @foreach($report['applications'] as $app)
                    <tr>
                        <td>{{ $app['name'] }}</td>
                        <td>{{ $app['total_users'] ?? 0 }}</td>
                        <td>{{ $app['is_active'] ? 'Active' : 'Inactive' }}</td>
                    </tr>
                @endforeach
            </tbody>
        </table>
    @endif
    
    <p>Generated: {{ $report['generated_at'] ?? now()->toISOString() }}</p>
</body>
</html>