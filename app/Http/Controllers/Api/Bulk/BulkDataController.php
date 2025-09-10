<?php

namespace App\Http\Controllers\Api\Bulk;

use App\Http\Controllers\Api\BaseApiController;
use App\Models\Organization;
use App\Services\BulkOperationService;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Validator;
use Symfony\Component\HttpFoundation\BinaryFileResponse;

class BulkDataController extends BaseApiController
{
    protected BulkOperationService $bulkOperationService;

    public function __construct(BulkOperationService $bulkOperationService)
    {
        $this->bulkOperationService = $bulkOperationService;
        $this->middleware('auth:api');
    }

    /**
     * Export users from an organization
     */
    public function exportUsers(Request $request, string $organizationId): JsonResponse|BinaryFileResponse
    {
        $this->authorize('users.read');

        $organization = Organization::findOrFail($organizationId);

        $validator = Validator::make($request->all(), [
            'format' => 'sometimes|string|in:csv,xlsx,json',
            'filters' => 'sometimes|array',
            'filters.is_active' => 'sometimes|in:true,false,1,0',
            'filters.has_mfa' => 'sometimes|in:true,false,1,0',
            'filters.role' => 'sometimes|string|max:255',
            'filters.created_after' => 'sometimes|date',
            'filters.created_before' => 'sometimes|date|after_or_equal:filters.created_after',
            'fields' => 'sometimes|array',
            'fields.*' => 'string|in:id,name,email,is_active,created_at,updated_at,last_login_at,roles,applications',
            'include_roles' => 'sometimes|boolean',
            'include_applications' => 'sometimes|boolean',
        ]);

        if ($validator->fails()) {
            return $this->validationErrorResponse($validator->errors());
        }

        try {
            $format = $request->get('format', 'csv');
            $filters = $request->get('filters', []);
            $fields = $request->get('fields', ['name', 'email', 'is_active', 'created_at']);
            $includeRoles = $request->boolean('include_roles', false);
            $includeApplications = $request->boolean('include_applications', false);

            $result = $this->bulkOperationService->exportUsers(
                $organization,
                $format,
                $filters
            );

            if ($result['success']) {
                if ($format === 'json') {
                    return $this->successResponse([
                        'users' => $result['data']['users'],
                        'export_metadata' => [
                            'total_users' => $result['data']['total'],
                            'export_date' => now()->toISOString(),
                            'organization' => $organization->name,
                            'format' => $format,
                            'filters_applied' => $filters,
                        ],
                    ], 'Users exported successfully');
                }

                return $result['data']['file_response'];
            }

            return $this->errorResponse($result['message'], 400);
        } catch (\Exception $e) {
            return $this->serverErrorResponse('Failed to export users: '.$e->getMessage());
        }
    }

    /**
     * Import users to an organization
     */
    public function importUsers(Request $request, string $organizationId): JsonResponse
    {
        $this->authorize('users.create');

        $organization = Organization::findOrFail($organizationId);

        $validator = Validator::make($request->all(), [
            'file' => 'required|file|mimes:csv,xlsx,json|max:10240',
            'options' => 'sometimes|array',
            'options.send_invitations' => 'sometimes|boolean',
            'options.default_role' => 'sometimes|string|exists:roles,name',
            'options.skip_duplicates' => 'sometimes|boolean',
            'options.update_existing' => 'sometimes|boolean',
            'mapping' => 'sometimes|array',
            'mapping.name' => 'sometimes|string',
            'mapping.email' => 'sometimes|string',
            'mapping.role' => 'sometimes|string',
        ]);

        if ($validator->fails()) {
            return $this->validationErrorResponse($validator->errors());
        }

        try {
            $file = $request->file('file');
            $options = $request->get('options', []);
            $mapping = $request->get('mapping', []);

            $defaultRole = $options['default_role'] ?? 'user';

            $result = $this->bulkOperationService->importUsers(
                $file,
                $organization,
                $defaultRole
            );

            if ($result['success']) {
                return $this->successResponse([
                    'imported' => $result['data']['imported'],
                    'failed' => $result['data']['failed'],
                    'skipped' => $result['data']['skipped'] ?? [],
                    'summary' => [
                        'total_processed' => $result['data']['total_processed'],
                        'successful' => count($result['data']['imported']),
                        'failed' => count($result['data']['failed']),
                        'skipped' => count($result['data']['skipped'] ?? []),
                        'success_rate' => count($result['data']['imported']) / $result['data']['total_processed'] * 100,
                    ],
                ], $result['message']);
            }

            return $this->errorResponse($result['message'], 400);
        } catch (\Exception $e) {
            return $this->serverErrorResponse('Failed to import users: '.$e->getMessage());
        }
    }
}
