<?php

namespace App\Jobs;

use App\Models\BulkImportJob;
use App\Models\User;
use Illuminate\Bus\Queueable;
use Illuminate\Contracts\Queue\ShouldQueue;
use Illuminate\Foundation\Bus\Dispatchable;
use Illuminate\Queue\InteractsWithQueue;
use Illuminate\Queue\SerializesModels;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Facades\Storage;

class ProcessBulkExportJob implements ShouldQueue
{
    use Dispatchable;
    use InteractsWithQueue;
    use Queueable;
    use SerializesModels;

    public int $timeout = 600; // 10 minutes

    public int $tries = 3;

    /**
     * Create a new job instance.
     */
    public function __construct(
        public BulkImportJob $exportJob
    ) {}

    /**
     * Execute the job.
     */
    public function handle(): void
    {
        Log::info("Starting bulk export job {$this->exportJob->id}");

        try {
            // Mark as processing
            $this->exportJob->markAsProcessing();

            // Get export type and format
            $exportType = $this->exportJob->export_type ?? 'users';
            $format = $this->exportJob->format ?? 'csv';
            $filters = $this->exportJob->filters ?? [];

            // Export based on type
            match ($exportType) {
                'users' => $this->exportUsers($format, $filters),
                default => throw new \RuntimeException("Unsupported export type: {$exportType}"),
            };

            // Mark as completed
            $this->exportJob->markAsCompleted();

            Log::info("Completed bulk export job {$this->exportJob->id}");

        } catch (\Exception $e) {
            Log::error("Failed bulk export job {$this->exportJob->id}: ".$e->getMessage(), [
                'exception' => $e,
            ]);

            $this->exportJob->markAsFailed($e->getMessage());

            // Re-throw to mark job as failed in queue
            throw $e;
        }
    }

    /**
     * Export users
     */
    private function exportUsers(string $format, array $filters): void
    {
        // Query users
        $query = User::where('organization_id', $this->exportJob->organization_id);

        // Apply filters
        if (! empty($filters['email_verified'])) {
            $query->whereNotNull('email_verified_at');
        }

        if (! empty($filters['date_from'])) {
            $query->whereDate('created_at', '>=', $filters['date_from']);
        }

        if (! empty($filters['date_to'])) {
            $query->whereDate('created_at', '<=', $filters['date_to']);
        }

        if (! empty($filters['roles'])) {
            $query->whereHas('roles', function ($q) use ($filters) {
                $q->whereIn('name', (array) $filters['roles']);
            });
        }

        $users = $query->get();

        // Generate file content based on format
        $content = match ($format) {
            'csv' => $this->generateCsv($users),
            'json' => $this->generateJson($users),
            'xlsx' => $this->generateCsv($users), // Simplified - treat as CSV
            default => throw new \RuntimeException("Unsupported format: {$format}"),
        };

        // Store file
        $fileName = 'exports/users_'.now()->format('Y-m-d_His').'.'.$format;
        Storage::put($fileName, $content);

        // Update export job
        $this->exportJob->update([
            'file_path' => $fileName,
            'file_size' => strlen($content),
            'total_records' => $users->count(),
        ]);
    }

    /**
     * Generate CSV content
     */
    private function generateCsv($users): string
    {
        $lines = [];

        // Header
        $lines[] = 'id,name,email,email_verified_at,created_at';

        // Data rows
        foreach ($users as $user) {
            $lines[] = implode(',', [
                $user->id,
                '"'.str_replace('"', '""', $user->name).'"',
                $user->email,
                $user->email_verified_at?->toDateTimeString() ?? '',
                $user->created_at->toDateTimeString(),
            ]);
        }

        return implode("\n", $lines);
    }

    /**
     * Generate JSON content
     */
    private function generateJson($users): string
    {
        return json_encode($users->map(function ($user) {
            return [
                'id' => $user->id,
                'name' => $user->name,
                'email' => $user->email,
                'email_verified_at' => $user->email_verified_at?->toDateTimeString(),
                'created_at' => $user->created_at->toDateTimeString(),
            ];
        })->values()->all(), JSON_PRETTY_PRINT);
    }

    /**
     * Handle a job failure.
     */
    public function failed(\Throwable $exception): void
    {
        Log::error("Bulk export job {$this->exportJob->id} failed permanently", [
            'exception' => $exception,
        ]);

        $this->exportJob->markAsFailed($exception->getMessage());
    }
}
