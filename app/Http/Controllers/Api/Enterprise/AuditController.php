<?php

namespace App\Http\Controllers\Api\Enterprise;

use App\Http\Controllers\Api\BaseApiController;
use App\Http\Requests\Enterprise\AuditExportRequest;
use App\Models\AuditExport;
use App\Services\AuditExportService;
use Exception;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Storage;

class AuditController extends BaseApiController
{
    public function __construct(
        private readonly AuditExportService $auditService
    ) {
        $this->middleware('auth:api');
    }

    public function export(AuditExportRequest $request): JsonResponse
    {
        try {
            $user = $this->getAuthenticatedUser();

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

            return $this->createdResponse($export, 'Audit export queued successfully');
        } catch (Exception $e) {
            return $this->errorResponse($e->getMessage(), 500);
        }
    }

    public function listExports(Request $request): JsonResponse
    {
        try {
            $user = $this->getAuthenticatedUser();

            $exports = $this->auditService->getExports(
                $user->organization_id,
                $request->input('per_page', 15)
            );

            return $this->paginatedResponse($exports, 'Exports retrieved successfully');
        } catch (Exception $e) {
            return $this->errorResponse($e->getMessage(), 500);
        }
    }

    public function download(int $exportId): JsonResponse
    {
        try {
            $user = $this->getAuthenticatedUser();

            $export = AuditExport::where('id', $exportId)
                ->where('organization_id', $user->organization_id)
                ->firstOrFail();

            if ($export->status !== 'completed' || ! $export->file_path) {
                return $this->errorResponse('Export is not ready for download', 400);
            }

            $url = Storage::disk('public')->url($export->file_path);

            return $this->successResponse([
                'download_url' => $url,
                'filename' => basename($export->file_path),
                'size' => Storage::disk('public')->size($export->file_path),
            ], 'Download URL generated successfully');
        } catch (Exception $e) {
            return $this->errorResponse($e->getMessage(), 500);
        }
    }
}
