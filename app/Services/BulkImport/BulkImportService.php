<?php

namespace App\Services\BulkImport;

use App\Jobs\ExportUsersJob;
use App\Jobs\ProcessBulkImportJob;
use App\Models\BulkImportJob;
use App\Services\BulkImport\DTOs\ExportOptions;
use App\Services\BulkImport\DTOs\ImportOptions;
use App\Services\BulkImport\Parsers\CsvParser;
use App\Services\BulkImport\Parsers\ExcelParser;
use App\Services\BulkImport\Parsers\JsonParser;
use Illuminate\Http\UploadedFile;

class BulkImportService
{
    /**
     * Start a bulk import job
     */
    public function import(UploadedFile $file, ImportOptions $options, int $userId): BulkImportJob
    {
        // Validate file
        $this->validateFile($file);

        // Store the uploaded file
        $filePath = $file->store('imports', 'local');

        // Create import job record
        $job = BulkImportJob::create([
            'type' => BulkImportJob::TYPE_IMPORT,
            'organization_id' => $options->organizationId,
            'created_by' => $userId,
            'status' => BulkImportJob::STATUS_PENDING,
            'options' => $options->toArray(),
            'file_path' => $filePath,
            'file_format' => $options->format,
            'file_size' => $file->getSize(),
        ]);

        // Dispatch job to queue for async processing
        ProcessBulkImportJob::dispatch($job);

        return $job;
    }

    /**
     * Start a bulk export job
     */
    public function export(ExportOptions $options, int $userId): BulkImportJob
    {
        // Create export job record
        $job = BulkImportJob::create([
            'type' => BulkImportJob::TYPE_EXPORT,
            'organization_id' => $options->organizationId,
            'created_by' => $userId,
            'status' => BulkImportJob::STATUS_PENDING,
            'options' => $options->toArray(),
            'file_format' => $options->format,
        ]);

        // Dispatch job to queue for async processing
        ExportUsersJob::dispatch($job);

        return $job;
    }

    /**
     * Get the appropriate parser for a file format
     */
    public function getParser(string $format)
    {
        return match (strtolower($format)) {
            'csv' => new CsvParser,
            'json' => new JsonParser,
            'xlsx', 'xls' => new ExcelParser,
            default => throw new \InvalidArgumentException("Unsupported format: {$format}"),
        };
    }

    /**
     * Validate uploaded file
     */
    private function validateFile(UploadedFile $file): void
    {
        // Check file size (max 10MB)
        $maxSize = 10 * 1024 * 1024; // 10MB in bytes
        if ($file->getSize() > $maxSize) {
            throw new \InvalidArgumentException('File size exceeds maximum allowed (10MB)');
        }

        // Check file type
        $allowedExtensions = ['csv', 'json', 'xlsx', 'xls'];
        $extension = strtolower($file->getClientOriginalExtension());

        if (! in_array($extension, $allowedExtensions)) {
            throw new \InvalidArgumentException(
                'Invalid file type. Allowed types: '.implode(', ', $allowedExtensions)
            );
        }

        // Validate MIME type
        $allowedMimeTypes = [
            'text/csv',
            'text/plain',
            'application/json',
            'application/vnd.ms-excel',
            'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
        ];

        if (! in_array($file->getMimeType(), $allowedMimeTypes)) {
            throw new \InvalidArgumentException('Invalid file MIME type');
        }
    }

    /**
     * Cancel an import/export job
     */
    public function cancel(BulkImportJob $job): bool
    {
        if ($job->isInProgress()) {
            $job->markAsCancelled();

            return true;
        }

        return false;
    }

    /**
     * Retry a failed import job
     */
    public function retry(BulkImportJob $job): BulkImportJob
    {
        if (! $job->hasFailed()) {
            throw new \RuntimeException('Only failed jobs can be retried');
        }

        // Reset job status
        $job->update([
            'status' => BulkImportJob::STATUS_PENDING,
            'processed_records' => 0,
            'failed_records' => 0,
            'errors' => null,
            'started_at' => null,
            'completed_at' => null,
            'processing_time' => null,
        ]);

        // Re-dispatch to queue
        if ($job->type === BulkImportJob::TYPE_IMPORT) {
            ProcessBulkImportJob::dispatch($job);
        } else {
            ExportUsersJob::dispatch($job);
        }

        return $job->fresh();
    }

    /**
     * Generate error report file
     */
    public function generateErrorReport(BulkImportJob $job): ?string
    {
        if (empty($job->errors)) {
            return null;
        }

        $parser = $this->getParser('csv');
        $records = [];

        foreach ($job->errors as $error) {
            $records[] = [
                'row' => $error['row'],
                'email' => $error['data']['email'] ?? '',
                'name' => $error['data']['name'] ?? '',
                'errors' => implode('; ', $error['errors']),
            ];
        }

        $filename = "errors_{$job->id}_".now()->format('YmdHis').'.csv';
        $path = $parser->generate($records, $filename);

        $job->update(['error_file_path' => $path]);

        return $path;
    }

    /**
     * Clean up old import/export jobs
     */
    public function cleanup(int $daysOld = 30): int
    {
        $jobs = BulkImportJob::where('created_at', '<', now()->subDays($daysOld))
            ->whereIn('status', [BulkImportJob::STATUS_COMPLETED, BulkImportJob::STATUS_FAILED])
            ->get();

        $count = 0;
        foreach ($jobs as $job) {
            // Files will be automatically deleted by model event
            $job->delete();
            $count++;
        }

        return $count;
    }
}
