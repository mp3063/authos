<?php

namespace App\Http\Controllers\Api;

use App\Http\Controllers\Controller;
use App\Models\Organization;
use App\Services\OAuthService;
use App\Services\OrganizationReportingService;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Storage;
use Illuminate\Support\Facades\Validator;

class OrganizationReportController extends Controller
{
    protected OrganizationReportingService $reportingService;

    protected OAuthService $oAuthService;

    public function __construct(OrganizationReportingService $reportingService, OAuthService $oAuthService)
    {
        $this->reportingService = $reportingService;
        $this->oAuthService = $oAuthService;
        $this->middleware('auth:api');
    }

    /**
     * Generate user activity report for an organization
     */
    public function userActivity(Request $request, string $organizationId): JsonResponse
    {
        $this->authorize('organizations.read');

        $validator = Validator::make($request->all(), [
            'start_date' => 'sometimes|date|before_or_equal:end_date',
            'end_date' => 'sometimes|date|after_or_equal:start_date',
            'format' => 'sometimes|string|in:json,pdf',
        ]);

        if ($validator->fails()) {
            return response()->json([
                'error' => 'validation_failed',
                'error_description' => 'The given data was invalid.',
                'details' => $validator->errors(),
            ], 422);
        }

        $organization = Organization::findOrFail($organizationId);
        $currentUser = auth()->user();

        // Check organization access
        if (! $currentUser->isSuperAdmin() && $currentUser->organization_id !== $organization->id) {
            return response()->json([
                'error' => 'forbidden',
                'error_description' => 'You do not have permission to access this organization.',
            ], 403);
        }

        $dateRange = null;
        if ($request->has('start_date') && $request->has('end_date')) {
            $dateRange = [
                'start' => $request->start_date,
                'end' => $request->end_date,
            ];
        }

        try {
            $report = $this->reportingService->generateUserActivityReport($organizationId, $dateRange);

            if ($request->input('format') === 'pdf') {
                $pdfPath = $this->reportingService->exportReportToPDF($report, 'user_activity');

                return response()->json([
                    'data' => [
                        'download_url' => Storage::url($pdfPath),
                        'filename' => basename($pdfPath),
                        'expires_at' => now()->addHours(24),
                    ],
                    'message' => 'User activity report generated successfully',
                ]);
            }

            // Log report generation
            $this->oAuthService->logAuthenticationEvent(
                $currentUser,
                'user_activity_report_generated',
                $request,
                null,
                true,
                [
                    'organization_id' => $organization->id,
                    'report_type' => 'user_activity',
                    'date_range' => $dateRange,
                ]
            );

            return response()->json([
                'data' => $report,
                'message' => 'User activity report generated successfully',
            ]);

        } catch (\Exception $e) {
            return response()->json([
                'error' => 'report_generation_failed',
                'error_description' => 'Failed to generate user activity report: '.$e->getMessage(),
            ], 500);
        }
    }

    /**
     * Generate application usage report for an organization
     */
    public function applicationUsage(Request $request, string $organizationId): JsonResponse
    {
        $this->authorize('organizations.read');

        $validator = Validator::make($request->all(), [
            'format' => 'sometimes|string|in:json,pdf',
        ]);

        if ($validator->fails()) {
            return response()->json([
                'error' => 'validation_failed',
                'error_description' => 'The given data was invalid.',
                'details' => $validator->errors(),
            ], 422);
        }

        $organization = Organization::findOrFail($organizationId);
        $currentUser = auth()->user();

        // Check organization access
        if (! $currentUser->isSuperAdmin() && $currentUser->organization_id !== $organization->id) {
            return response()->json([
                'error' => 'forbidden',
                'error_description' => 'You do not have permission to access this organization.',
            ], 403);
        }

        try {
            $report = $this->reportingService->generateApplicationUsageReport($organizationId);

            if ($request->input('format') === 'pdf') {
                $pdfPath = $this->reportingService->exportReportToPDF($report, 'application_usage');

                return response()->json([
                    'data' => [
                        'download_url' => Storage::url($pdfPath),
                        'filename' => basename($pdfPath),
                        'expires_at' => now()->addHours(24),
                    ],
                    'message' => 'Application usage report generated successfully',
                ]);
            }

            // Log report generation
            $this->oAuthService->logAuthenticationEvent(
                $currentUser,
                'application_usage_report_generated',
                $request,
                null,
                true,
                [
                    'organization_id' => $organization->id,
                    'report_type' => 'application_usage',
                ]
            );

            return response()->json([
                'data' => $report,
                'message' => 'Application usage report generated successfully',
            ]);

        } catch (\Exception $e) {
            return response()->json([
                'error' => 'report_generation_failed',
                'error_description' => 'Failed to generate application usage report: '.$e->getMessage(),
            ], 500);
        }
    }

    /**
     * Generate security audit report for an organization
     */
    public function securityAudit(Request $request, string $organizationId): JsonResponse
    {
        $this->authorize('organizations.read');

        $validator = Validator::make($request->all(), [
            'format' => 'sometimes|string|in:json,pdf',
        ]);

        if ($validator->fails()) {
            return response()->json([
                'error' => 'validation_failed',
                'error_description' => 'The given data was invalid.',
                'details' => $validator->errors(),
            ], 422);
        }

        $organization = Organization::findOrFail($organizationId);
        $currentUser = auth()->user();

        // Check organization access
        if (! $currentUser->isSuperAdmin() && $currentUser->organization_id !== $organization->id) {
            return response()->json([
                'error' => 'forbidden',
                'error_description' => 'You do not have permission to access this organization.',
            ], 403);
        }

        try {
            $report = $this->reportingService->generateSecurityAuditReport($organizationId);

            if ($request->input('format') === 'pdf') {
                $pdfPath = $this->reportingService->exportReportToPDF($report, 'security_audit');

                return response()->json([
                    'data' => [
                        'download_url' => Storage::url($pdfPath),
                        'filename' => basename($pdfPath),
                        'expires_at' => now()->addHours(24),
                    ],
                    'message' => 'Security audit report generated successfully',
                ]);
            }

            // Log report generation
            $this->oAuthService->logAuthenticationEvent(
                $currentUser,
                'security_audit_report_generated',
                $request,
                null,
                true,
                [
                    'organization_id' => $organization->id,
                    'report_type' => 'security_audit',
                ]
            );

            return response()->json([
                'data' => $report,
                'message' => 'Security audit report generated successfully',
            ]);

        } catch (\Exception $e) {
            return response()->json([
                'error' => 'report_generation_failed',
                'error_description' => 'Failed to generate security audit report: '.$e->getMessage(),
            ], 500);
        }
    }

    /**
     * Get available report types and their descriptions
     */
    public function reportTypes(): JsonResponse
    {
        return response()->json([
            'data' => [
                'user_activity' => [
                    'name' => 'User Activity Report',
                    'description' => 'Comprehensive analysis of user login patterns, activity trends, and engagement metrics.',
                    'features' => [
                        'Login statistics and trends',
                        'Active vs inactive users',
                        'MFA adoption rates',
                        'Role distribution analysis',
                        'Top active users',
                    ],
                    'date_range_supported' => true,
                ],
                'application_usage' => [
                    'name' => 'Application Usage Report',
                    'description' => 'Detailed insights into application usage patterns, user engagement, and token analytics.',
                    'features' => [
                        'Application engagement scores',
                        'User distribution across applications',
                        'Token usage statistics',
                        'Application activity metrics',
                        'Performance indicators',
                    ],
                    'date_range_supported' => false,
                ],
                'security_audit' => [
                    'name' => 'Security Audit Report',
                    'description' => 'Comprehensive security analysis including failed logins, suspicious activities, and compliance.',
                    'features' => [
                        'Failed login analysis',
                        'Suspicious IP detection',
                        'MFA compliance tracking',
                        'Security event timeline',
                        'Compliance recommendations',
                    ],
                    'date_range_supported' => false,
                ],
            ],
        ]);
    }
}
