<?php

namespace App\Jobs;

use App\Models\BulkImportJob;
use App\Services\BulkImport\BulkImportService;
use App\Services\BulkImport\DTOs\ImportOptions;
use App\Services\BulkImport\ImportValidator;
use App\Services\BulkImport\UserProcessor;
use Illuminate\Bus\Queueable;
use Illuminate\Contracts\Queue\ShouldQueue;
use Illuminate\Foundation\Bus\Dispatchable;
use Illuminate\Queue\InteractsWithQueue;
use Illuminate\Queue\SerializesModels;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Facades\Storage;

class ProcessBulkImportJob implements ShouldQueue
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
        Log::info("Starting bulk import job {$this->job->id}");

        try {
            // Mark as processing
            $this->job->markAsProcessing();

            // Get options
            $options = ImportOptions::fromArray($this->job->options);

            // Get parser
            $parser = $service->getParser($this->job->file_format);

            // Get file path
            $filePath = Storage::path($this->job->file_path);

            // Parse and validate records
            Log::info("Validating records for import job {$this->job->id}");
            $records = $parser->parse($filePath);
            $validator = new ImportValidator($options);
            $validationResult = $validator->validate($records);

            // Store validation report
            $this->job->update([
                'total_records' => $validationResult->getTotalRecords(),
                'valid_records' => $validationResult->getValidCount(),
                'invalid_records' => $validationResult->getInvalidCount(),
            ]);

            $this->job->storeValidationReport($validationResult->toArray());

            // Store invalid records as errors
            foreach ($validationResult->invalidRecords as $invalidRecord) {
                $this->job->addValidationError(
                    $invalidRecord['row'],
                    $invalidRecord['data'],
                    $invalidRecord['errors']
                );
            }

            // If skip_invalid is false and there are errors, fail the job
            if (! $options->skipInvalid && $validationResult->hasErrors()) {
                throw new \RuntimeException(
                    "Validation failed with {$validationResult->getInvalidCount()} invalid records"
                );
            }

            // Process valid records in batches
            if (! empty($validationResult->validRecords)) {
                Log::info("Processing {$validationResult->getValidCount()} valid records");
                $this->processRecords($validationResult->validRecords, $options);
            }

            // Generate error report if there are errors
            if ($validationResult->hasErrors()) {
                $service->generateErrorReport($this->job);
            }

            // Mark as completed
            $this->job->markAsCompleted();

            Log::info("Completed bulk import job {$this->job->id}");

        } catch (\Exception $e) {
            Log::error("Failed bulk import job {$this->job->id}: ".$e->getMessage(), [
                'exception' => $e,
            ]);

            $this->job->markAsFailed($e->getMessage());

            // Re-throw to mark job as failed in queue
            throw $e;
        }
    }

    /**
     * Process valid records in batches
     */
    private function processRecords(array $records, ImportOptions $options): void
    {
        $processor = new UserProcessor($options);
        $batchSize = $options->batchSize;
        $totalRecords = count($records);
        $processedCount = 0;

        // Process in batches
        foreach (array_chunk($records, $batchSize) as $batch) {
            try {
                $results = $processor->processBatch($batch);

                $processedCount += count($batch);

                // Update progress every batch
                $this->job->updateProgress([
                    'processed_records' => $processedCount,
                    'failed_records' => $this->job->failed_records + $results['failed'],
                ]);

                // Store batch errors
                foreach ($results['errors'] as $error) {
                    $errorRecord = collect($batch)->firstWhere('row', $error['row']);
                    if ($errorRecord) {
                        $this->job->addValidationError(
                            $error['row'],
                            $errorRecord['data'],
                            [$error['error']]
                        );
                    }
                }

                Log::info("Processed batch: {$processedCount}/{$totalRecords} records");

            } catch (\Exception $e) {
                Log::error('Batch processing error: '.$e->getMessage());

                // If not skipping invalid, re-throw to fail the entire import
                if (! $options->skipInvalid) {
                    throw $e;
                }

                // Otherwise, mark batch records as failed and continue
                foreach ($batch as $record) {
                    $this->job->addValidationError(
                        $record['row'],
                        $record['data'],
                        ['Batch processing failed: '.$e->getMessage()]
                    );
                }

                $this->job->updateProgress([
                    'processed_records' => $processedCount,
                    'failed_records' => $this->job->failed_records + count($batch),
                ]);
            }
        }
    }

    /**
     * Handle a job failure.
     */
    public function failed(\Throwable $exception): void
    {
        Log::error("Bulk import job {$this->job->id} failed permanently", [
            'exception' => $exception,
        ]);

        $this->job->markAsFailed($exception->getMessage());
    }
}
