<?php

namespace App\Http\Controllers\Api\Organizations;

use App\Http\Controllers\Api\BaseApiController;
use App\Http\Controllers\Api\Traits\CacheableResponse;
use App\Models\AuditExport;
use App\Models\Organization;
use App\Services\OrganizationAnalyticsService;
use Carbon\Carbon;
use Exception;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Storage;
use Illuminate\Support\Facades\URL;
use Illuminate\Support\Facades\Validator;
use Symfony\Component\HttpFoundation\StreamedResponse;

class OrganizationAnalyticsController extends BaseApiController
{
    use CacheableResponse;

    protected OrganizationAnalyticsService $analyticsService;

    public function __construct(OrganizationAnalyticsService $analyticsService)
    {
        $this->analyticsService = $analyticsService;
        $this->middleware('auth:api');
    }

    /**
     * Get organization analytics
     */
    public function analytics(Request $request, string $id): JsonResponse
    {
        $this->authorize('organizations.read');

        $organization = Organization::findOrFail($id);

        $validator = Validator::make($request->all(), [
            'period' => 'sometimes|string|in:24h,7d,7days,30d,30days,90d,1y',
            'metrics' => 'sometimes|array',
            'metrics.*' => 'string|in:users,applications,authentication_logs,active_sessions',
            'timezone' => 'sometimes|string|timezone',
        ]);

        if ($validator->fails()) {
            return $this->validationErrorResponse($validator->errors());
        }

        $period = $this->normalizePeriod($request->get('period', '30d'));
        $metrics = $request->get('metrics', ['users', 'applications', 'authentication_logs']);
        $timezone = $request->get('timezone', 'UTC');

        // Cache analytics using the improved caching trait
        $cacheParams = compact('period', 'metrics', 'timezone');
        $analyticsData = $this->cacheAnalytics(
            'organization_'.$organization->id,
            $cacheParams,
            function () use ($organization, $period) {
                return $this->analyticsService->getAnalytics(
                    $organization,
                    $period
                );
            },
            300 // 5 minutes cache
        );

        return $this->successResponse(
            $analyticsData,
            'Organization analytics retrieved successfully'
        );
    }

    /**
     * Get user activity metrics
     */
    public function userMetrics(Request $request, string $id): JsonResponse
    {
        $this->authorize('organizations.read');

        $organization = Organization::findOrFail($id);

        $validator = Validator::make($request->all(), [
            'period' => 'sometimes|string|in:24h,7d,30d,90d',
            'type' => 'sometimes|string|in:registrations,logins,active_users',
        ]);

        if ($validator->fails()) {
            return $this->validationErrorResponse($validator->errors());
        }

        $period = $request->get('period', '30d');
        $type = $request->get('type', 'active_users');

        $cacheParams = compact('period', 'type');
        $metrics = $this->cacheAnalytics(
            'user_metrics_'.$organization->id,
            $cacheParams,
            function () use ($organization, $period) {
                return $this->analyticsService->getComprehensiveUserMetrics($organization, $period);
            }
        );

        return $this->successResponse(
            $metrics,
            'User metrics retrieved successfully'
        );
    }

    /**
     * Get application usage metrics
     */
    public function applicationMetrics(Request $request, string $id): JsonResponse
    {
        $this->authorize('organizations.read');

        $organization = Organization::findOrFail($id);

        $validator = Validator::make($request->all(), [
            'period' => 'sometimes|string|in:24h,7d,30d,90d',
            'application_id' => 'sometimes|exists:applications,id',
        ]);

        if ($validator->fails()) {
            return $this->validationErrorResponse($validator->errors());
        }

        $period = $request->get('period', '30d');
        $applicationId = $request->get('application_id');

        $cacheParams = compact('period', 'applicationId');
        $metrics = $this->cacheAnalytics(
            'app_metrics_'.$organization->id,
            $cacheParams,
            function () use ($organization, $period, $applicationId) {
                return $this->analyticsService->getApplicationMetrics($organization->id, $period, $applicationId);
            }
        );

        return $this->successResponse(
            $metrics,
            'Application metrics retrieved successfully'
        );
    }

    /**
     * Get security metrics
     */
    public function securityMetrics(Request $request, string $id): JsonResponse
    {
        $this->authorize('organizations.read');

        $organization = Organization::findOrFail($id);

        $validator = Validator::make($request->all(), [
            'period' => 'sometimes|string|in:24h,7d,30d,90d',
            'include_failed_attempts' => 'sometimes|boolean',
        ]);

        if ($validator->fails()) {
            return $this->validationErrorResponse($validator->errors());
        }

        $period = $request->get('period', '30d');
        $includeFailedAttempts = $request->boolean('include_failed_attempts', true);

        $cacheParams = compact('period', 'includeFailedAttempts');
        $metrics = $this->cacheAnalytics(
            'security_metrics_'.$organization->id,
            $cacheParams,
            function () use ($organization, $period) {
                return $this->analyticsService->getSecurityMetrics($organization, $period);
            }
        );

        return $this->successResponse(
            $metrics,
            'Security metrics retrieved successfully'
        );
    }

    /**
     * Export organization data
     */
    public function export(Request $request, string $id): JsonResponse
    {
        $this->authorize('organizations.read');

        $organization = Organization::findOrFail($id);

        $validator = Validator::make($request->all(), [
            'format' => 'sometimes|string|in:json,csv,xlsx',
            'data_type' => 'required|string|in:users,applications,analytics,security_logs',
            'date_from' => 'sometimes|date|before_or_equal:date_to',
            'date_to' => 'sometimes|date|after_or_equal:date_from',
        ]);

        if ($validator->fails()) {
            return $this->validationErrorResponse($validator->errors());
        }

        $format = $request->get('format', 'json');
        $dataType = $request->get('data_type');
        $dateFrom = $request->get('date_from');
        $dateTo = $request->get('date_to');

        try {
            // Create AuditExport record with pending status
            $user = $this->getAuthenticatedUser();

            $auditExport = AuditExport::create([
                'organization_id' => $organization->id,
                'user_id' => $user->id,
                'type' => $format,
                'status' => 'pending',
                'filters' => array_filter([
                    'data_type' => $dataType,
                    'date_from' => $dateFrom,
                    'date_to' => $dateTo,
                ]),
                'started_at' => now(),
            ]);

            // Build export data based on data type
            $exportData = match ($dataType) {
                'users' => $this->exportUsers($organization, $dateFrom, $dateTo),
                'applications' => $this->exportApplications($organization, $dateFrom, $dateTo),
                'analytics' => $this->exportAnalytics($organization, $dateFrom, $dateTo),
                'security_logs' => $this->exportSecurityLogs($organization, $dateFrom, $dateTo),
                default => throw new Exception('Invalid data type'),
            };

            // Generate file content based on format
            $fileExtension = $format === 'xlsx' ? 'csv' : $format;
            $content = match ($format) {
                'csv', 'xlsx' => $this->arrayToCsv($exportData),
                'json' => json_encode($exportData, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE),
                default => json_encode($exportData, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE),
            };

            // Store file
            $timestamp = now()->format('Y-m-d_His');
            $filePath = "exports/org-{$organization->id}-{$dataType}-{$timestamp}.{$fileExtension}";

            Storage::disk('public')->put($filePath, $content);

            // Update AuditExport record
            $recordsCount = is_array($exportData) ? count($exportData) : 0;

            $auditExport->update([
                'file_path' => $filePath,
                'status' => 'completed',
                'records_count' => $recordsCount,
                'completed_at' => now(),
            ]);

            // Generate signed temporary URL (valid for 1 hour)
            $downloadUrl = URL::temporarySignedRoute(
                'api.organizations.exports.download',
                now()->addHour(),
                [
                    'id' => $organization->id,
                    'exportId' => $auditExport->id,
                ]
            );

            return $this->successResponse(
                [
                    'export_id' => $auditExport->id,
                    'status' => 'completed',
                    'download_url' => $downloadUrl,
                    'format' => $format,
                    'data_type' => $dataType,
                    'records_count' => $recordsCount,
                    'file_path' => $filePath,
                    'exported_at' => $auditExport->completed_at->toIso8601String(),
                ],
                'Organization data exported successfully'
            );
        } catch (Exception $e) {
            // Mark export as failed if record was created
            if (isset($auditExport)) {
                $auditExport->update([
                    'status' => 'failed',
                    'error_message' => $e->getMessage(),
                    'completed_at' => now(),
                ]);
            }

            return $this->errorResponse('Failed to export data: '.$e->getMessage(), 500);
        }
    }

    /**
     * Download an export file
     */
    public function downloadExport(Request $request, string $id, string $exportId): StreamedResponse|JsonResponse
    {
        // Validate signed URL
        if (! $request->hasValidSignature()) {
            return $this->errorResponse('Invalid or expired download link', 403);
        }

        $export = AuditExport::find($exportId);

        if (! $export || ! $export->isCompleted()) {
            return $this->notFoundResponse('Export not found or not yet completed');
        }

        // Check organization access
        $user = $this->getAuthenticatedUser();
        if (! $user) {
            return $this->unauthorizedResponse();
        }

        $isSuperAdmin = $this->isSuperAdmin();
        if (! $isSuperAdmin && $user->organization_id != $export->organization_id) {
            return $this->forbiddenResponse('You do not have access to this export');
        }

        // Verify the export belongs to the requested organization
        if ($export->organization_id != $id) {
            return $this->notFoundResponse('Export not found');
        }

        if (! Storage::disk('public')->exists($export->file_path)) {
            return $this->notFoundResponse('Export file not found');
        }

        $filename = basename($export->file_path);

        return Storage::disk('public')->download($export->file_path, $filename);
    }

    /**
     * Get export status
     */
    public function exportStatus(Request $request, string $id, string $exportId): JsonResponse
    {
        $this->authorize('organizations.read');

        $organization = Organization::findOrFail($id);

        $export = AuditExport::where('id', $exportId)
            ->where('organization_id', $organization->id)
            ->first();

        if (! $export) {
            return $this->notFoundResponse('Export not found');
        }

        $data = [
            'export_id' => $export->id,
            'status' => $export->status,
            'type' => $export->type,
            'filters' => $export->filters,
            'records_count' => $export->records_count,
            'started_at' => $export->started_at?->toIso8601String(),
            'completed_at' => $export->completed_at?->toIso8601String(),
            'error_message' => $export->error_message,
        ];

        // Include download URL for completed exports
        if ($export->isCompleted() && $export->file_path) {
            $data['download_url'] = URL::temporarySignedRoute(
                'api.organizations.exports.download',
                now()->addHour(),
                [
                    'id' => $organization->id,
                    'exportId' => $export->id,
                ]
            );
        }

        return $this->successResponse($data, 'Export status retrieved successfully');
    }

    /**
     * Export users data
     */
    private function exportUsers(Organization $organization, ?string $dateFrom, ?string $dateTo): array
    {
        $users = $this->analyticsService->getOrganizationUsers(
            $organization,
            array_filter([
                'date_from' => $dateFrom,
                'date_to' => $dateTo,
            ])
        );

        return $users->toArray();
    }

    /**
     * Export applications data
     */
    private function exportApplications(Organization $organization, ?string $dateFrom, ?string $dateTo): array
    {
        $dateRange = [
            'start' => $dateFrom ? Carbon::parse($dateFrom) : now()->subMonth(),
            'end' => $dateTo ? Carbon::parse($dateTo) : now(),
        ];

        return $this->analyticsService->getApplicationUsage($organization, $dateRange)->toArray();
    }

    /**
     * Export analytics data
     */
    private function exportAnalytics(Organization $organization, ?string $dateFrom, ?string $dateTo): array
    {
        $period = $this->determinePeriodFromDates($dateFrom, $dateTo);

        return $this->analyticsService->getAnalytics($organization, $period);
    }

    /**
     * Export security logs data
     */
    private function exportSecurityLogs(Organization $organization, ?string $dateFrom, ?string $dateTo): array
    {
        $period = $this->determinePeriodFromDates($dateFrom, $dateTo);

        return $this->analyticsService->getSecurityMetrics($organization, $period);
    }

    /**
     * Determine period from date range
     */
    private function determinePeriodFromDates(?string $dateFrom, ?string $dateTo): string
    {
        if (! $dateFrom || ! $dateTo) {
            return '30d';
        }

        $start = Carbon::parse($dateFrom);
        $end = Carbon::parse($dateTo);
        $days = $start->diffInDays($end);

        return match (true) {
            $days <= 1 => '24h',
            $days <= 7 => '7d',
            $days <= 30 => '30d',
            $days <= 90 => '90d',
            default => '1y',
        };
    }

    /**
     * Normalize period format (convert '7days' to '7d', '30days' to '30d', etc.)
     */
    private function normalizePeriod(string $period): string
    {
        return match ($period) {
            '7days' => '7d',
            '30days' => '30d',
            default => $period,
        };
    }

    /**
     * Convert array data to CSV string
     */
    private function arrayToCsv(array $data): string
    {
        if (empty($data)) {
            return '';
        }

        $output = fopen('php://temp', 'r+');

        // If the data is an associative array (not a list of rows), wrap it
        if (! array_is_list($data)) {
            $data = [$this->flattenArray($data)];
        } else {
            $data = array_map(fn ($row) => is_array($row) ? $this->flattenArray($row) : [$row], $data);
        }

        // Write header row from first element keys
        $firstRow = reset($data);
        if (is_array($firstRow)) {
            fputcsv($output, array_keys($firstRow));
        }

        // Write data rows
        foreach ($data as $row) {
            if (is_array($row)) {
                fputcsv($output, array_map(fn ($value) => is_array($value) ? json_encode($value) : $value, $row));
            } else {
                fputcsv($output, [$row]);
            }
        }

        rewind($output);
        $csv = stream_get_contents($output);
        fclose($output);

        return $csv;
    }

    /**
     * Flatten nested array with dot notation keys
     */
    private function flattenArray(array $array, string $prefix = ''): array
    {
        $result = [];

        foreach ($array as $key => $value) {
            $newKey = $prefix === '' ? $key : $prefix.'.'.$key;

            if (is_array($value) && ! empty($value) && ! array_is_list($value)) {
                $result = array_merge($result, $this->flattenArray($value, $newKey));
            } else {
                $result[$newKey] = is_array($value) ? json_encode($value) : $value;
            }
        }

        return $result;
    }
}
