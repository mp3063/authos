<?php

namespace App\Http\Controllers\Api\Enterprise;

use App\Http\Controllers\Api\BaseApiController;
use App\Http\Requests\Enterprise\ListComplianceReportsRequest;
use App\Http\Requests\Enterprise\ScheduleComplianceReportRequest;
use App\Http\Requests\Enterprise\UpdateScheduledComplianceReportRequest;
use App\Jobs\GenerateComplianceReportJob;
use App\Models\ComplianceReport;
use App\Models\ScheduledComplianceReport;
use App\Services\ComplianceReportService;
use Exception;
use Illuminate\Database\Eloquent\ModelNotFoundException;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Storage;
use Illuminate\Support\Str;
use Symfony\Component\HttpFoundation\StreamedResponse;

class ComplianceController extends BaseApiController
{
    public function __construct(
        private readonly ComplianceReportService $complianceService
    ) {
        $this->middleware('auth:api');
    }

    public function soc2(Request $request): JsonResponse
    {
        return $this->generateReport(
            'enterprise.compliance.read',
            'SOC2',
            fn ($org) => $this->complianceService->generateSOC2Report($org),
        );
    }

    public function iso27001(Request $request): JsonResponse
    {
        return $this->generateReport(
            'enterprise.compliance.read',
            'ISO 27001',
            fn ($org) => $this->complianceService->generateISO27001Report($org),
        );
    }

    public function gdpr(Request $request): JsonResponse
    {
        return $this->generateReport(
            'enterprise.compliance.read',
            'GDPR',
            fn ($org) => $this->complianceService->generateGDPRReport($org),
        );
    }

    public function schedule(ScheduleComplianceReportRequest $request): JsonResponse
    {
        try {
            $user = $this->getAuthenticatedUser();

            if ($denied = $this->ensureFeatureEnabled($user->organization)) {
                return $denied;
            }

            $schedule = $this->complianceService->createSchedule(
                $user->organization,
                $user,
                $request->input('report_type'),
                $request->input('frequency'),
                $request->input('recipients'),
                (bool) $request->input('is_active', true),
            );

            // Dispatch the first run immediately. The cron command takes over
            // for subsequent runs based on next_run_at.
            GenerateComplianceReportJob::dispatch(
                $user->organization,
                $schedule->report_type,
                $schedule->recipients,
            );

            return response()->json([
                'success' => true,
                'data' => ['schedule' => $this->formatSchedule($schedule)],
                'message' => 'Compliance report scheduled successfully',
            ], 201);
        } catch (Exception $e) {
            return $this->errorResponse($e->getMessage(), 500);
        }
    }

    public function listSchedules(Request $request): JsonResponse
    {
        try {
            $user = $this->getAuthenticatedUser();

            if (! auth()->user()->tokenCan('enterprise.compliance.read')) {
                return $this->forbiddenResponse('You do not have permission to view compliance schedules');
            }

            $schedules = ScheduledComplianceReport::query()
                ->forOrganization($user->organization_id)
                ->orderByDesc('created_at')
                ->get()
                ->map(fn ($s) => $this->formatSchedule($s))
                ->all();

            return response()->json([
                'success' => true,
                'data' => ['schedules' => $schedules],
            ]);
        } catch (Exception $e) {
            return $this->errorResponse($e->getMessage(), 500);
        }
    }

    public function updateSchedule(int $id, UpdateScheduledComplianceReportRequest $request): JsonResponse
    {
        try {
            $user = $this->getAuthenticatedUser();
            $schedule = $this->findOrgScopedSchedule($user->organization_id, $id);

            $updated = $this->complianceService->updateSchedule($schedule, $request->validated());

            return response()->json([
                'success' => true,
                'data' => ['schedule' => $this->formatSchedule($updated)],
                'message' => 'Schedule updated successfully',
            ]);
        } catch (ModelNotFoundException) {
            return response()->json(['success' => false, 'message' => 'Schedule not found'], 404);
        } catch (Exception $e) {
            return $this->errorResponse($e->getMessage(), 500);
        }
    }

    public function cancelSchedule(int $id): JsonResponse
    {
        try {
            $user = $this->getAuthenticatedUser();

            if (! auth()->user()->tokenCan('enterprise.compliance.manage')) {
                return $this->forbiddenResponse('You do not have permission to cancel compliance schedules');
            }

            $schedule = $this->findOrgScopedSchedule($user->organization_id, $id);
            $this->complianceService->cancelSchedule($schedule);

            return response()->json([
                'success' => true,
                'message' => 'Schedule cancelled successfully',
            ]);
        } catch (ModelNotFoundException) {
            return response()->json(['success' => false, 'message' => 'Schedule not found'], 404);
        } catch (Exception $e) {
            return $this->errorResponse($e->getMessage(), 500);
        }
    }

    private function findOrgScopedSchedule(int $organizationId, int $id): ScheduledComplianceReport
    {
        return ScheduledComplianceReport::query()
            ->forOrganization($organizationId)
            ->findOrFail($id);
    }

    private function generateReport(string $scope, string $label, \Closure $generate): JsonResponse
    {
        try {
            $user = $this->getAuthenticatedUser();

            if (! auth()->user()->tokenCan($scope)) {
                return $this->forbiddenResponse('You do not have permission to generate compliance reports');
            }

            if ($denied = $this->ensureFeatureEnabled($user->organization)) {
                return $denied;
            }

            $report = $generate($user->organization);

            return response()->json([
                'success' => true,
                'data' => ['report' => $report],
                'message' => "{$label} report generated successfully",
            ]);
        } catch (Exception $e) {
            return $this->errorResponse($e->getMessage(), 500);
        }
    }

    private function ensureFeatureEnabled($organization): ?JsonResponse
    {
        $enabled = $organization->settings['enterprise_features']['compliance_reports_enabled'] ?? true;

        return $enabled ? null : response()->json([
            'success' => false,
            'error' => 'feature_disabled',
            'message' => 'Compliance reports are disabled for this organization',
        ], 403);
    }

    private function formatSchedule(ScheduledComplianceReport $schedule): array
    {
        return [
            'id' => $schedule->id,
            'report_type' => $schedule->report_type,
            'frequency' => $schedule->frequency,
            'recipients' => $schedule->recipients,
            'is_active' => $schedule->is_active,
            'next_run_at' => $schedule->next_run_at?->toISOString(),
            'last_run_at' => $schedule->last_run_at?->toISOString(),
            'created_at' => $schedule->created_at?->toISOString(),
        ];
    }

    public function listReports(ListComplianceReportsRequest $request): JsonResponse
    {
        try {
            $user = $this->getAuthenticatedUser();

            $query = ComplianceReport::query()
                ->forOrganization($user->organization_id)
                ->latest('generated_at')
                ->latest('id');

            if ($type = $request->input('report_type')) {
                $query->where('report_type', $type);
            }
            if ($status = $request->input('status')) {
                $query->where('status', $status);
            }
            if ($from = $request->date('from')) {
                $query->where('created_at', '>=', $from);
            }
            if ($to = $request->date('to')) {
                $query->where('created_at', '<=', $to->copy()->endOfDay());
            }

            $perPage = (int) $request->input('per_page', 25);
            $reports = $query->paginate($perPage);

            return response()->json([
                'success' => true,
                'data' => [
                    'reports' => $reports->getCollection()
                        ->map(fn (ComplianceReport $r) => $this->formatReport($r))
                        ->all(),
                    'pagination' => [
                        'current_page' => $reports->currentPage(),
                        'per_page' => $reports->perPage(),
                        'total' => $reports->total(),
                        'last_page' => $reports->lastPage(),
                    ],
                ],
            ]);
        } catch (Exception $e) {
            return $this->errorResponse($e->getMessage(), 500);
        }
    }

    public function downloadReport(int $reportId, Request $request): StreamedResponse|JsonResponse
    {
        try {
            $user = $this->getAuthenticatedUser();

            if (! auth()->user()->tokenCan('enterprise.compliance.read')) {
                return $this->forbiddenResponse('You do not have permission to download compliance reports');
            }

            $report = ComplianceReport::query()
                ->forOrganization($user->organization_id)
                ->findOrFail($reportId);

            if (! $report->isCompleted()) {
                return response()->json([
                    'success' => false,
                    'error' => 'report_not_ready',
                    'message' => 'Report is still generating or has failed',
                ], 400);
            }

            if ($report->isExpired()) {
                return response()->json([
                    'success' => false,
                    'error' => 'report_expired',
                    'message' => 'Report has expired and is no longer available for download',
                ], 410);
            }

            $format = $request->query('format', 'pdf');
            $path = match ($format) {
                'pdf' => $report->file_path_pdf,
                'json' => $report->file_path_json,
                default => null,
            };

            if ($path === null) {
                return response()->json([
                    'success' => false,
                    'error' => 'invalid_format',
                    'message' => 'Format must be one of: pdf, json',
                ], 400);
            }

            // Defense in depth: ensure the stored path lives under our org's namespace.
            $expectedPrefix = "compliance_reports/{$report->organization_id}/";
            if (! Str::startsWith($path, $expectedPrefix)) {
                return response()->json([
                    'success' => false,
                    'error' => 'invalid_file_path',
                    'message' => 'File path does not match organization namespace',
                ], 403);
            }

            $disk = Storage::disk('local');
            if (! $disk->exists($path)) {
                return response()->json([
                    'success' => false,
                    'error' => 'file_not_found',
                    'message' => 'Report file not found on storage',
                ], 404);
            }

            $contentType = match ($format) {
                'pdf' => 'application/pdf',
                'json' => 'application/json',
            };

            return response()->streamDownload(
                fn () => print $disk->get($path),
                basename($path),
                ['Content-Type' => $contentType],
            );
        } catch (ModelNotFoundException) {
            return response()->json(['success' => false, 'message' => 'Report not found'], 404);
        } catch (Exception $e) {
            return $this->errorResponse($e->getMessage(), 500);
        }
    }

    private function formatReport(ComplianceReport $report): array
    {
        return [
            'id' => $report->id,
            'report_type' => $report->report_type,
            'status' => $report->status,
            'period_start' => $report->period_start?->toDateString(),
            'period_end' => $report->period_end?->toDateString(),
            'generated_at' => $report->generated_at?->toISOString(),
            'expires_at' => $report->expires_at?->toISOString(),
            'is_expired' => $report->isExpired(),
            'has_pdf' => ! empty($report->file_path_pdf),
            'has_json' => ! empty($report->file_path_json),
            'pdf_download_url' => $report->pdfDownloadUrl(),
            'json_download_url' => $report->jsonDownloadUrl(),
            'summary' => $report->summary,
            'error_message' => $report->error_message,
            'created_at' => $report->created_at?->toISOString(),
        ];
    }
}
