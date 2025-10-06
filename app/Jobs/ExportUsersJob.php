<?php

namespace App\Jobs;

use App\Models\BulkImportJob;
use App\Models\User;
use App\Services\BulkImport\BulkImportService;
use App\Services\BulkImport\DTOs\ExportOptions;
use Illuminate\Bus\Queueable;
use Illuminate\Contracts\Queue\ShouldQueue;
use Illuminate\Foundation\Bus\Dispatchable;
use Illuminate\Queue\InteractsWithQueue;
use Illuminate\Queue\SerializesModels;
use Illuminate\Support\Facades\Log;

class ExportUsersJob implements ShouldQueue
{
    use Dispatchable, InteractsWithQueue, Queueable, SerializesModels;

    public int $timeout = 600; // 10 minutes

    public int $tries = 3;

    /**
     * Create a new job instance.
     */
    public function __construct(
        public BulkImportJob $job
    ) {}

    /**
     * Execute the job.
     */
    public function handle(BulkImportService $service): void
    {
        Log::info("Starting export job {$this->job->id}");

        try {
            // Mark as processing
            $this->job->markAsProcessing();

            // Get options
            $options = ExportOptions::fromArray($this->job->options);

            // Build query
            $query = $this->buildQuery($options);

            // Count total records
            $total = $query->count();
            $this->job->update(['total_records' => $total]);

            if ($total === 0) {
                throw new \RuntimeException('No users found matching the export criteria');
            }

            Log::info("Exporting {$total} users");

            // Collect records
            $records = [];
            $processedCount = 0;

            $query->chunk(100, function ($users) use (&$records, &$processedCount, $options) {
                foreach ($users as $user) {
                    $records[] = $this->formatUserRecord($user, $options);
                    $processedCount++;

                    // Update progress every 100 records
                    if ($processedCount % 100 === 0) {
                        $this->job->updateProgress([
                            'processed_records' => $processedCount,
                        ]);
                        Log::info("Exported {$processedCount} users");
                    }
                }
            });

            // Generate file
            $parser = $service->getParser($this->job->file_format);
            $filename = "users_export_{$this->job->id}_".now()->format('YmdHis').".{$this->job->file_format}";
            $filePath = $parser->generate($records, $filename);

            // Update job with file information
            $this->job->update([
                'file_path' => $filePath,
                'file_size' => filesize(storage_path('app/'.$filePath)),
                'processed_records' => $processedCount,
                'valid_records' => $processedCount,
            ]);

            // Mark as completed
            $this->job->markAsCompleted();

            Log::info("Completed export job {$this->job->id}");

        } catch (\Exception $e) {
            Log::error("Failed export job {$this->job->id}: ".$e->getMessage(), [
                'exception' => $e,
            ]);

            $this->job->markAsFailed($e->getMessage());

            // Re-throw to mark job as failed in queue
            throw $e;
        }
    }

    /**
     * Build query based on export options
     */
    private function buildQuery(ExportOptions $options)
    {
        $query = User::query()->with(['organization', 'roles']);

        // Filter by organization
        if ($options->organizationId) {
            $query->where('organization_id', $options->organizationId);
        }

        // Filter by date range
        if ($options->dateFrom) {
            $query->where('created_at', '>=', $options->dateFrom);
        }

        if ($options->dateTo) {
            $query->where('created_at', '<=', $options->dateTo);
        }

        // Filter by email verified
        if ($options->emailVerifiedOnly === true) {
            $query->whereNotNull('email_verified_at');
        }

        // Filter by active status
        if ($options->activeOnly === true) {
            $query->where('is_active', true);
        }

        // Filter by roles
        if ($options->roles && ! empty($options->roles)) {
            $query->whereHas('roles', function ($q) use ($options) {
                $q->whereIn('name', $options->roles);
            });
        }

        // Limit results
        if ($options->limit) {
            $query->limit($options->limit);
        }

        return $query;
    }

    /**
     * Format user record for export
     */
    private function formatUserRecord(User $user, ExportOptions $options): array
    {
        $fields = $options->getDefaultFields();
        $record = [];

        foreach ($fields as $field) {
            $record[$field] = match ($field) {
                'id' => $user->id,
                'email' => $user->email,
                'name' => $user->name,
                'email_verified_at' => $user->email_verified_at?->toDateTimeString(),
                'created_at' => $user->created_at->toDateTimeString(),
                'updated_at' => $user->updated_at->toDateTimeString(),
                'organization_name' => $user->organization?->name ?? 'N/A',
                'organization_id' => $user->organization_id,
                'roles' => $user->roles->pluck('name')->implode(', '),
                'is_active' => $user->is_active ? 'Yes' : 'No',
                'mfa_enabled' => $user->hasMfaEnabled() ? 'Yes' : 'No',
                'provider' => $user->getProviderDisplayName(),
                default => null,
            };
        }

        return $record;
    }

    /**
     * Handle a job failure.
     */
    public function failed(\Throwable $exception): void
    {
        Log::error("Export job {$this->job->id} failed permanently", [
            'exception' => $exception,
        ]);

        $this->job->markAsFailed($exception->getMessage());
    }
}
