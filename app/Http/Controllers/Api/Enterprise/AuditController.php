<?php

namespace App\Http\Controllers\Api\Enterprise;

use App\Http\Controllers\Api\BaseApiController;
use App\Models\AuditExport;
use App\Services\AuditExportService;
use Exception;
use Illuminate\Database\Eloquent\ModelNotFoundException;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Storage;
use Symfony\Component\HttpFoundation\StreamedResponse;

class AuditController extends BaseApiController
{
    public function __construct(
        private readonly AuditExportService $auditService
    ) {
        $this->middleware('auth:api');
    }

    public function export(Request $request): JsonResponse
    {
        // Manual validation for consistent error format
        $validator = validator($request->all(), [
            'format' => ['required', 'string', 'in:csv,json,xlsx'],
            'start_date' => ['required', 'date'],
            'end_date' => ['required', 'date', 'after_or_equal:start_date'],
            'event_types' => ['nullable', 'array'],
            'event_types.*' => ['string'],
            'user_id' => ['nullable', 'integer', 'exists:users,id'],
        ]);

        if ($validator->fails()) {
            return $this->validationErrorResponse($validator->errors());
        }

        try {
            $user = $this->getAuthenticatedUser();

            // Check OAuth scope
            if (! auth()->user()->tokenCan('enterprise.audit.manage')) {
                return $this->forbiddenResponse('You do not have permission to create audit exports');
            }

            // Check if feature is enabled
            $organization = $user->organization;
            if (! ($organization->settings['enterprise_features']['audit_exports_enabled'] ?? true)) {
                return response()->json([
                    'success' => false,
                    'error' => 'feature_disabled',
                    'message' => 'Audit exports are disabled for this organization',
                ], 403);
            }

            $filters = [
                'date_from' => $request->input('start_date'),
                'date_to' => $request->input('end_date'),
                'event' => $request->input('event_types'),
                'user_id' => $request->input('user_id'),
            ];

            $export = $this->auditService->createExportAsync(
                $user->organization_id,
                $user->id,
                $filters,
                $request->input('format')
            );

            return response()->json([
                'success' => true,
                'data' => [
                    'export' => [
                        'id' => $export->id,
                        'format' => $export->type,
                        'status' => $export->status,
                        'file_path' => $export->file_path,
                    ],
                ],
                'message' => 'Audit export queued successfully',
            ], 201);
        } catch (Exception $e) {
            return $this->errorResponse($e->getMessage(), 500);
        }
    }

    public function listExports(Request $request): JsonResponse
    {
        try {
            $user = $this->getAuthenticatedUser();

            // Check OAuth scope
            if (! auth()->user()->tokenCan('enterprise.audit.read')) {
                return $this->forbiddenResponse('You do not have permission to view audit exports');
            }

            $exports = $this->auditService->getExports(
                $user->organization_id,
                $request->input('per_page', 15)
            );

            // Convert paginated results to array format
            $data = $exports->getCollection()->map(function ($export) {
                return [
                    'id' => $export->id,
                    'format' => $export->type,
                    'status' => $export->status,
                    'file_path' => $export->file_path,
                    'filters' => $export->filters,
                    'created_at' => $export->created_at->toISOString(),
                    'completed_at' => $export->completed_at?->toISOString(),
                ];
            })->all();

            return response()->json([
                'success' => true,
                'data' => $data,
                'message' => 'Exports retrieved successfully',
            ]);
        } catch (Exception $e) {
            return $this->errorResponse($e->getMessage(), 500);
        }
    }

    public function download(int $exportId): StreamedResponse|JsonResponse
    {
        try {
            $user = $this->getAuthenticatedUser();

            // Check OAuth scope
            if (! auth()->user()->tokenCan('enterprise.audit.read')) {
                return $this->forbiddenResponse('You do not have permission to download audit exports');
            }

            $export = AuditExport::where('id', $exportId)
                ->where('organization_id', $user->organization_id)
                ->firstOrFail();

            if ($export->status !== 'completed' || ! $export->file_path) {
                return response()->json([
                    'success' => false,
                    'error' => 'export_not_ready',
                    'message' => 'Export is not ready for download',
                ], 400);
            }

            // Determine the correct storage disk and path
            $disk = Storage::disk('local');
            $path = $export->file_path;

            if (! $disk->exists($path)) {
                return response()->json([
                    'success' => false,
                    'error' => 'file_not_found',
                    'message' => 'Export file not found',
                ], 404);
            }

            // Get the content type based on file extension
            $extension = pathinfo($path, PATHINFO_EXTENSION);
            $contentType = match ($extension) {
                'csv' => 'text/csv',
                'json' => 'application/json',
                'xlsx' => 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
                default => 'application/octet-stream',
            };

            return response()->streamDownload(function () use ($disk, $path) {
                echo $disk->get($path);
            }, basename($path), [
                'Content-Type' => $contentType,
            ]);
        } catch (ModelNotFoundException $e) {
            return response()->json([
                'success' => false,
                'error' => 'not_found',
                'message' => 'Export not found',
            ], 404);
        } catch (Exception $e) {
            return $this->errorResponse($e->getMessage(), 500);
        }
    }
}
