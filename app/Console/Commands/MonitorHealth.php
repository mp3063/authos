<?php

namespace App\Console\Commands;

use App\Services\AlertingService;
use Exception;
use Illuminate\Console\Command;
use Illuminate\Support\Facades\Log;

class MonitorHealth extends Command
{
    /**
     * The name and signature of the console command.
     */
    protected $signature = 'monitor:health
                          {--send-alerts : Send alerts if issues are detected}
                          {--output-format=table : Output format (table, json)}';

    /**
     * The console command description.
     */
    protected $description = 'Monitor system health and optionally send alerts';

    protected AlertingService $alertingService;

    public function __construct(AlertingService $alertingService)
    {
        parent::__construct();
        $this->alertingService = $alertingService;
    }

    /**
     * Execute the console command.
     */
    public function handle(): int
    {
        $this->info('🏥 Checking system health...');

        try {
            if ($this->option('send-alerts')) {
                $this->alertingService->checkHealthAlerts();
                $this->info('✅ Health alerts check completed');
            }

            $statusSummary = $this->alertingService->getSystemStatusSummary();

            if ($this->option('output-format') === 'json') {
                $this->line(json_encode($statusSummary, JSON_PRETTY_PRINT));
            } else {
                $this->displayStatusTable($statusSummary);
            }

            return $statusSummary['overall_status'] === 'healthy' ? 0 : 1;

        } catch (Exception $e) {
            $this->error('❌ Health monitoring failed: '.$e->getMessage());
            Log::error('Health monitoring command failed', [
                'error' => $e->getMessage(),
                'trace' => $e->getTraceAsString(),
            ]);

            return 1;
        }
    }

    /**
     * Display status summary as a table.
     */
    private function displayStatusTable(array $statusSummary): void
    {
        $this->line('');
        $this->info('📊 System Status Summary');
        $this->line('');

        // Overall status
        $statusIcon = $statusSummary['overall_status'] === 'healthy' ? '✅' : '⚠️';
        $this->line("Overall Status: $statusIcon ".strtoupper($statusSummary['overall_status']));
        $this->line("Active Alerts: {$statusSummary['active_alerts']}");
        $this->line("Checked At: {$statusSummary['timestamp']}");
        $this->line('');

        // Detailed checks
        $headers = ['Check', 'Status', 'Value', 'Threshold', 'Message'];
        $rows = [];

        foreach ($statusSummary['checks'] as $checkName => $check) {
            $status = $check['triggered'] ? '⚠️ ALERT' : '✅ OK';
            $value = $check['value'] !== null ? $this->formatValue($check['value']) : 'N/A';
            $threshold = $check['threshold'] !== null ? $this->formatValue($check['threshold']) : 'N/A';

            $rows[] = [
                ucwords(str_replace('_', ' ', $checkName)),
                $status,
                $value,
                $threshold,
                $this->truncateMessage($check['message']),
            ];
        }

        $this->table($headers, $rows);

        // Show details for triggered alerts
        $triggeredChecks = array_filter($statusSummary['checks'], function ($check) {
            return $check['triggered'];
        });

        if (! empty($triggeredChecks)) {
            $this->line('');
            $this->warn('⚠️  Alert Details:');

            foreach ($triggeredChecks as $checkName => $check) {
                $this->line('');
                $this->error('• '.ucwords(str_replace('_', ' ', $checkName)));
                $this->line("  Message: {$check['message']}");

                if (! empty($check['details'])) {
                    foreach ($check['details'] as $key => $value) {
                        $formattedValue = is_array($value) ? json_encode($value) : $value;
                        $this->line('  '.ucwords(str_replace('_', ' ', $key)).": $formattedValue");
                    }
                }
            }
        }
    }

    /**
     * Format numeric values for display.
     */
    private function formatValue($value): string
    {
        if (is_numeric($value)) {
            if ($value >= 1000000) {
                return number_format($value / 1000000, 1).'M';
            } elseif ($value >= 1000) {
                return number_format($value / 1000, 1).'K';
            } elseif (is_float($value)) {
                return number_format($value, 2);
            }
        }

        return (string) $value;
    }

    /**
     * Truncate long messages for table display.
     */
    private function truncateMessage(string $message): string
    {
        return strlen($message) > 60 ? substr($message, 0, 57).'...' : $message;
    }
}
