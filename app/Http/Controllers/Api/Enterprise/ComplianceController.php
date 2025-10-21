<?php

namespace App\Http\Controllers\Api\Enterprise;

use App\Http\Controllers\Api\BaseApiController;
use App\Services\ComplianceReportService;
use Exception;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;

class ComplianceController extends BaseApiController
{
    public function __construct(
        private readonly ComplianceReportService $complianceService
    ) {
        $this->middleware('auth:api');
    }

    public function soc2(Request $request): JsonResponse
    {
        try {
            $user = $this->getAuthenticatedUser();

            // Check OAuth scope
            if (! auth()->user()->tokenCan('enterprise.compliance.read')) {
                return $this->forbiddenResponse('You do not have permission to generate compliance reports');
            }

            // Check if feature is enabled
            $organization = $user->organization;
            if (! ($organization->settings['enterprise_features']['compliance_reports_enabled'] ?? true)) {
                return response()->json([
                    'success' => false,
                    'error' => 'feature_disabled',
                    'message' => 'Compliance reports are disabled for this organization',
                ], 403);
            }

            $report = $this->complianceService->generateSOC2Report($user->organization);

            return response()->json([
                'success' => true,
                'data' => [
                    'report' => $report,
                ],
                'message' => 'SOC2 report generated successfully',
            ]);
        } catch (Exception $e) {
            return $this->errorResponse($e->getMessage(), 500);
        }
    }

    public function iso27001(Request $request): JsonResponse
    {
        try {
            $user = $this->getAuthenticatedUser();

            // Check OAuth scope
            if (! auth()->user()->tokenCan('enterprise.compliance.read')) {
                return $this->forbiddenResponse('You do not have permission to generate compliance reports');
            }

            // Check if feature is enabled
            $organization = $user->organization;
            if (! ($organization->settings['enterprise_features']['compliance_reports_enabled'] ?? true)) {
                return response()->json([
                    'success' => false,
                    'error' => 'feature_disabled',
                    'message' => 'Compliance reports are disabled for this organization',
                ], 403);
            }

            $report = $this->complianceService->generateISO27001Report($user->organization);

            return response()->json([
                'success' => true,
                'data' => [
                    'report' => $report,
                ],
                'message' => 'ISO 27001 report generated successfully',
            ]);
        } catch (Exception $e) {
            return $this->errorResponse($e->getMessage(), 500);
        }
    }

    public function gdpr(Request $request): JsonResponse
    {
        try {
            $user = $this->getAuthenticatedUser();

            // Check OAuth scope
            if (! auth()->user()->tokenCan('enterprise.compliance.read')) {
                return $this->forbiddenResponse('You do not have permission to generate compliance reports');
            }

            // Check if feature is enabled
            $organization = $user->organization;
            if (! ($organization->settings['enterprise_features']['compliance_reports_enabled'] ?? true)) {
                return response()->json([
                    'success' => false,
                    'error' => 'feature_disabled',
                    'message' => 'Compliance reports are disabled for this organization',
                ], 403);
            }

            $report = $this->complianceService->generateGDPRReport($user->organization);

            return response()->json([
                'success' => true,
                'data' => [
                    'report' => $report,
                ],
                'message' => 'GDPR report generated successfully',
            ]);
        } catch (Exception $e) {
            return $this->errorResponse($e->getMessage(), 500);
        }
    }

    public function schedule(Request $request): JsonResponse
    {
        // Manual validation for consistent error format
        $validator = validator($request->all(), [
            'report_type' => ['required', 'string', 'in:soc2,iso27001,gdpr'],
            'frequency' => ['required', 'string', 'in:daily,weekly,monthly,quarterly'],
            'recipients' => ['required', 'array', 'min:1'],
            'recipients.*' => ['required', 'email'],
        ]);

        if ($validator->fails()) {
            return $this->validationErrorResponse($validator->errors());
        }

        try {
            $user = $this->getAuthenticatedUser();

            // Check OAuth scope
            if (! auth()->user()->tokenCan('enterprise.compliance.manage')) {
                return $this->forbiddenResponse('You do not have permission to schedule compliance reports');
            }

            // Check if feature is enabled
            $organization = $user->organization;
            if (! ($organization->settings['enterprise_features']['compliance_reports_enabled'] ?? true)) {
                return response()->json([
                    'success' => false,
                    'error' => 'feature_disabled',
                    'message' => 'Compliance reports are disabled for this organization',
                ], 403);
            }

            $this->complianceService->scheduleReport(
                $user->organization,
                $request->input('report_type'),
                $request->input('recipients')
            );

            // Calculate next run time based on frequency
            $nextRunAt = match ($request->input('frequency')) {
                'daily' => now()->addDay(),
                'weekly' => now()->addWeek(),
                'monthly' => now()->addMonth(),
                'quarterly' => now()->addMonths(3),
                default => now()->addMonth(),
            };

            return response()->json([
                'success' => true,
                'data' => [
                    'schedule' => [
                        'report_type' => $request->input('report_type'),
                        'frequency' => $request->input('frequency'),
                        'recipients' => $request->input('recipients'),
                        'next_run_at' => $nextRunAt->toISOString(),
                    ],
                ],
                'message' => 'Compliance report scheduled successfully',
            ], 201);
        } catch (Exception $e) {
            return $this->errorResponse($e->getMessage(), 500);
        }
    }
}
