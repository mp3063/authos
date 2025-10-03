<?php

namespace App\Services;

use App\Exports\AuditLogsExport;
use App\Jobs\ProcessAuditExportJob;
use App\Models\AuditExport;
use App\Models\AuthenticationLog;
use Exception;
use Illuminate\Support\Facades\Storage;
use Maatwebsite\Excel\Facades\Excel;

class AuditExportService
{
    /**
     * Create and process export asynchronously using a queued job
     */
    public function createExportAsync(int $organizationId, int $userId, array $filters, string $type = 'csv'): AuditExport
    {
        $export = AuditExport::create([
            'organization_id' => $organizationId,
            'user_id' => $userId,
            'type' => $type,
            'filters' => $filters,
            'status' => 'pending',
        ]);

        ProcessAuditExportJob::dispatch($export);

        return $export;
    }

    /**
     * Create a new audit export
     */
    public function createExport(int $organizationId, int $userId, array $filters, string $type = 'csv'): AuditExport
    {
        return AuditExport::create([
            'organization_id' => $organizationId,
            'user_id' => $userId,
            'type' => $type,
            'filters' => $filters,
            'status' => 'pending',
        ]);
    }

    /**
     * Process an audit export
     */
    public function processExport(AuditExport $export): void
    {
        $export->update(['status' => 'processing', 'started_at' => now()]);

        try {
            // Validate export type
            if (! in_array($export->type, ['json', 'csv', 'excel'])) {
                throw new Exception("Invalid export type: {$export->type}");
            }

            $logs = $this->getFilteredLogs($export);
            $filename = "audit-export-{$export->id}-".now()->format('Y-m-d-His').".{$export->type}";
            $path = "exports/{$filename}";

            // Export based on type
            if ($export->type === 'json') {
                Storage::disk('public')->put($path, json_encode($logs->toArray(), JSON_PRETTY_PRINT));
            } elseif ($export->type === 'csv' || $export->type === 'excel') {
                Excel::store(new AuditLogsExport($logs), $path, 'public');
            }

            $export->update([
                'status' => 'completed',
                'file_path' => $path,
                'records_count' => $logs->count(),
                'completed_at' => now(),
            ]);
        } catch (Exception $e) {
            $export->update([
                'status' => 'failed',
                'error_message' => $e->getMessage(),
                'completed_at' => now(),
            ]);
        }
    }

    /**
     * Get filtered authentication logs
     */
    private function getFilteredLogs(AuditExport $export)
    {
        // Get user IDs for this organization
        $userIds = \App\Models\User::where('organization_id', $export->organization_id)
            ->pluck('id')
            ->toArray();

        $query = AuthenticationLog::whereIn('user_id', $userIds);

        if ($filters = $export->filters) {
            if (isset($filters['date_from'])) {
                $query->where('created_at', '>=', $filters['date_from']);
            }
            if (isset($filters['date_to'])) {
                $query->where('created_at', '<=', $filters['date_to']);
            }
            if (isset($filters['event'])) {
                $query->where('event', $filters['event']);
            }
            if (isset($filters['user_id'])) {
                $query->where('user_id', $filters['user_id']);
            }
            if (isset($filters['success'])) {
                $query->where('success', $filters['success']);
            }
        }

        return $query->orderBy('created_at', 'desc')->get();
    }

    /**
     * Get all exports for an organization
     */
    public function getExports(int $organizationId, int $perPage = 15)
    {
        return AuditExport::where('organization_id', $organizationId)
            ->with('user:id,name,email')
            ->orderBy('created_at', 'desc')
            ->paginate($perPage);
    }

    /**
     * Delete old exports
     */
    public function cleanupOldExports(int $daysToKeep = 30): int
    {
        $exports = AuditExport::where('created_at', '<', now()->subDays($daysToKeep))->get();
        $count = 0;

        foreach ($exports as $export) {
            if ($export->file_path) {
                Storage::disk('public')->delete($export->file_path);
            }
            $export->delete();
            $count++;
        }

        return $count;
    }
}
