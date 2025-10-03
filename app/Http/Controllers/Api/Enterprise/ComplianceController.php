<?php

namespace App\Http\Controllers\Api\Enterprise;

use App\Http\Controllers\Api\BaseApiController;
use App\Http\Requests\Enterprise\ComplianceScheduleRequest;
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
            $report = $this->complianceService->generateSOC2Report($user->organization);

            return $this->successResponse($report, 'SOC2 report generated successfully');
        } catch (Exception $e) {
            return $this->errorResponse($e->getMessage(), 500);
        }
    }

    public function iso27001(Request $request): JsonResponse
    {
        try {
            $user = $this->getAuthenticatedUser();
            $report = $this->complianceService->generateISO27001Report($user->organization);

            return $this->successResponse($report, 'ISO 27001 report generated successfully');
        } catch (Exception $e) {
            return $this->errorResponse($e->getMessage(), 500);
        }
    }

    public function gdpr(Request $request): JsonResponse
    {
        try {
            $user = $this->getAuthenticatedUser();
            $report = $this->complianceService->generateGDPRReport($user->organization);

            return $this->successResponse($report, 'GDPR report generated successfully');
        } catch (Exception $e) {
            return $this->errorResponse($e->getMessage(), 500);
        }
    }

    public function schedule(ComplianceScheduleRequest $request): JsonResponse
    {
        try {
            $user = $this->getAuthenticatedUser();

            $this->complianceService->scheduleReport(
                $user->organization,
                $request->input('report_type'),
                $request->input('email_recipients')
            );

            return $this->successResponse([
                'report_type' => $request->input('report_type'),
                'frequency' => $request->input('frequency'),
                'recipients' => $request->input('email_recipients'),
            ], 'Compliance report scheduled successfully');
        } catch (Exception $e) {
            return $this->errorResponse($e->getMessage(), 500);
        }
    }
}
