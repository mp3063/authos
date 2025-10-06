<?php

namespace App\Http\Controllers\Api;

use App\Http\Controllers\Controller;
use App\Http\Requests\ExportUsersRequest;
use App\Http\Requests\ImportUsersRequest;
use App\Models\BulkImportJob;
use App\Services\BulkImport\BulkImportService;
use App\Services\BulkImport\DTOs\ExportOptions;
use App\Services\BulkImport\DTOs\ImportOptions;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Storage;
use Symfony\Component\HttpFoundation\StreamedResponse;

class BulkUserController extends Controller
{
    public function __construct(
        private readonly BulkImportService $service
    ) {}

    /**
     * Start a bulk import
     */
    public function import(ImportUsersRequest $request): JsonResponse
    {
        $options = ImportOptions::fromArray([
            'format' => $request->input('format'),
            'update_existing' => $request->input('update_existing', false),
            'skip_invalid' => $request->input('skip_invalid', true),
            'send_invitations' => $request->input('send_invitations', false),
            'auto_generate_passwords' => $request->input('auto_generate_passwords', false),
            'default_role' => $request->input('default_role'),
            'organization_id' => $request->input('organization_id'),
            'batch_size' => $request->input('batch_size', 100),
        ]);

        $job = $this->service->import(
            $request->file('file'),
            $options,
            $request->user()->id
        );

        return response()->json([
            'success' => true,
            'message' => 'Import job started successfully',
            'data' => [
                'job_id' => $job->id,
                'status' => $job->status,
                'type' => $job->type,
            ],
        ], 201);
    }

    /**
     * Start a bulk export
     */
    public function export(ExportUsersRequest $request): JsonResponse
    {
        $options = ExportOptions::fromArray([
            'format' => $request->input('format'),
            'organization_id' => $request->input('organization_id'),
            'fields' => $request->input('fields'),
            'roles' => $request->input('roles'),
            'date_from' => $request->input('date_from'),
            'date_to' => $request->input('date_to'),
            'email_verified_only' => $request->input('email_verified_only'),
            'active_only' => $request->input('active_only'),
            'limit' => $request->input('limit'),
        ]);

        $job = $this->service->export($options, $request->user()->id);

        return response()->json([
            'success' => true,
            'message' => 'Export job started successfully',
            'data' => [
                'job_id' => $job->id,
                'status' => $job->status,
                'type' => $job->type,
            ],
        ], 201);
    }

    /**
     * List import/export jobs
     */
    public function index(Request $request): JsonResponse
    {
        $query = BulkImportJob::query()
            ->with(['organization', 'createdBy'])
            ->where('organization_id', $request->user()->organization_id);

        // Filter by type
        if ($request->has('type')) {
            $query->where('type', $request->input('type'));
        }

        // Filter by status
        if ($request->has('status')) {
            $query->where('status', $request->input('status'));
        }

        // Recent jobs by default (last 30 days)
        if (! $request->has('all')) {
            $query->where('created_at', '>=', now()->subDays(30));
        }

        $jobs = $query->latest()
            ->paginate($request->input('per_page', 15));

        return response()->json([
            'success' => true,
            'data' => $jobs->items(),
            'pagination' => [
                'current_page' => $jobs->currentPage(),
                'per_page' => $jobs->perPage(),
                'total' => $jobs->total(),
                'last_page' => $jobs->lastPage(),
            ],
        ]);
    }

    /**
     * Get a specific job status
     */
    public function show(Request $request, BulkImportJob $job): JsonResponse
    {
        // Ensure user can only access their organization's jobs
        if ($job->organization_id !== $request->user()->organization_id && ! $request->user()->isSuperAdmin()) {
            return response()->json([
                'success' => false,
                'message' => 'Unauthorized access to this job',
            ], 403);
        }

        return response()->json([
            'success' => true,
            'data' => [
                'id' => $job->id,
                'type' => $job->type,
                'status' => $job->status,
                'status_label' => $job->status_label,
                'total_records' => $job->total_records,
                'valid_records' => $job->valid_records,
                'invalid_records' => $job->invalid_records,
                'processed_records' => $job->processed_records,
                'failed_records' => $job->failed_records,
                'progress_percentage' => $job->getProgressPercentage(),
                'file_format' => $job->file_format,
                'file_size' => $job->formatted_file_size,
                'validation_report' => $job->validation_report,
                'has_errors' => ! empty($job->errors),
                'error_count' => count($job->errors ?? []),
                'options' => $job->options,
                'started_at' => $job->started_at?->toIso8601String(),
                'completed_at' => $job->completed_at?->toIso8601String(),
                'processing_time' => $job->processing_time,
                'created_at' => $job->created_at->toIso8601String(),
                'created_by' => [
                    'id' => $job->createdBy->id,
                    'name' => $job->createdBy->name,
                    'email' => $job->createdBy->email,
                ],
                'file_url' => $job->getFileUrl(),
                'error_file_url' => $job->getErrorFileUrl(),
            ],
        ]);
    }

    /**
     * Download error file
     */
    public function downloadErrors(Request $request, BulkImportJob $job): StreamedResponse|JsonResponse
    {
        // Ensure user can only access their organization's jobs
        if ($job->organization_id !== $request->user()->organization_id && ! $request->user()->isSuperAdmin()) {
            return response()->json([
                'success' => false,
                'message' => 'Unauthorized access to this job',
            ], 403);
        }

        if (! $job->error_file_path) {
            // Generate error file if it doesn't exist
            if (! empty($job->errors)) {
                $this->service->generateErrorReport($job);
                $job->refresh();
            } else {
                return response()->json([
                    'success' => false,
                    'message' => 'No errors found for this job',
                ], 404);
            }
        }

        if (! Storage::exists($job->error_file_path)) {
            return response()->json([
                'success' => false,
                'message' => 'Error file not found',
            ], 404);
        }

        return Storage::download($job->error_file_path, "errors_job_{$job->id}.csv");
    }

    /**
     * Download export file
     */
    public function download(Request $request, BulkImportJob $job): StreamedResponse|JsonResponse
    {
        // Ensure user can only access their organization's jobs
        if ($job->organization_id !== $request->user()->organization_id && ! $request->user()->isSuperAdmin()) {
            return response()->json([
                'success' => false,
                'message' => 'Unauthorized access to this job',
            ], 403);
        }

        if ($job->type !== BulkImportJob::TYPE_EXPORT) {
            return response()->json([
                'success' => false,
                'message' => 'This is not an export job',
            ], 400);
        }

        if ($job->status !== BulkImportJob::STATUS_COMPLETED) {
            return response()->json([
                'success' => false,
                'message' => 'Export is not completed yet',
            ], 400);
        }

        if (! $job->file_path || ! Storage::exists($job->file_path)) {
            return response()->json([
                'success' => false,
                'message' => 'Export file not found',
            ], 404);
        }

        $filename = 'users_export_'.now()->format('Y-m-d_His').".{$job->file_format}";

        return Storage::download($job->file_path, $filename);
    }

    /**
     * Cancel a job
     */
    public function cancel(Request $request, BulkImportJob $job): JsonResponse
    {
        // Ensure user can only access their organization's jobs
        if ($job->organization_id !== $request->user()->organization_id && ! $request->user()->isSuperAdmin()) {
            return response()->json([
                'success' => false,
                'message' => 'Unauthorized access to this job',
            ], 403);
        }

        if (! $this->service->cancel($job)) {
            return response()->json([
                'success' => false,
                'message' => 'Job cannot be cancelled (not in progress)',
            ], 400);
        }

        return response()->json([
            'success' => true,
            'message' => 'Job cancelled successfully',
        ]);
    }

    /**
     * Retry a failed job
     */
    public function retry(Request $request, BulkImportJob $job): JsonResponse
    {
        // Ensure user can only access their organization's jobs
        if ($job->organization_id !== $request->user()->organization_id && ! $request->user()->isSuperAdmin()) {
            return response()->json([
                'success' => false,
                'message' => 'Unauthorized access to this job',
            ], 403);
        }

        try {
            $retried = $this->service->retry($job);

            return response()->json([
                'success' => true,
                'message' => 'Job restarted successfully',
                'data' => [
                    'job_id' => $retried->id,
                    'status' => $retried->status,
                ],
            ]);
        } catch (\RuntimeException $e) {
            return response()->json([
                'success' => false,
                'message' => $e->getMessage(),
            ], 400);
        }
    }

    /**
     * Delete a job
     */
    public function destroy(Request $request, BulkImportJob $job): JsonResponse
    {
        // Ensure user can only access their organization's jobs
        if ($job->organization_id !== $request->user()->organization_id && ! $request->user()->isSuperAdmin()) {
            return response()->json([
                'success' => false,
                'message' => 'Unauthorized access to this job',
            ], 403);
        }

        if ($job->isInProgress()) {
            return response()->json([
                'success' => false,
                'message' => 'Cannot delete a job that is in progress',
            ], 400);
        }

        $job->delete();

        return response()->json([
            'success' => true,
            'message' => 'Job deleted successfully',
        ]);
    }
}
