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

            // Use the extended method that returns the proper array format
            $options = array_merge($filters, [
                'format' => $format,
                'include_roles' => $includeRoles,
                'include_applications' => $includeApplications,
                'fields' => $fields,
            ]);

            $result = $this->bulkOperationService->exportUsersExtended(
                $organization,
                $options,
                auth()->user()
            );

            return $this->successResponse($result, 'Export completed successfully');
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
            'send_invitations' => 'sometimes|boolean',
            'default_role' => 'sometimes|string|exists:roles,name',
            'skip_duplicates' => 'sometimes|boolean',
            'update_existing' => 'sometimes|boolean',
            'invite_expires_in_days' => 'sometimes|integer|min:1|max:30',
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
            // Use flat format to match test expectations
            return $this->validationErrorResponse($validator->errors());
        }

        try {
            $file = $request->file('file');
            $requestOptions = $request->get('options', []);
            $mapping = $request->get('mapping', []);

            // Merge top-level options with nested options object
            $options = [
                'send_invitations' => $request->boolean('send_invitations', $requestOptions['send_invitations'] ?? false),
                'default_role' => $request->get('default_role', $requestOptions['default_role'] ?? 'user'),
                'skip_duplicates' => $request->boolean('skip_duplicates', $requestOptions['skip_duplicates'] ?? false),
                'update_existing' => $request->boolean('update_existing', $requestOptions['update_existing'] ?? false),
                'invite_expires_in_days' => $request->integer('invite_expires_in_days', 7),
            ];

            $result = $this->bulkOperationService->importUsersExtended(
                $file,
                $organization,
                $options,
                auth()->user()
            );

            // The service returns the direct result from UsersImport::getResults()
            // which has the structure: ['created' => [], 'updated' => [], 'invited' => [], 'failed' => []]

            $totalProcessed = count($result['created']) + count($result['updated']) + count($result['invited']) + count($result['failed']);
            $successful = count($result['created']) + count($result['updated']) + count($result['invited']);

            return $this->successResponse([
                'created' => $result['created'],
                'updated' => $result['updated'],
                'invited' => $result['invited'],
                'failed' => $result['failed'],
                'summary' => [
                    'total_processed' => $totalProcessed,
                    'successful' => $successful,
                    'failed' => count($result['failed']),
                    'success_rate' => $totalProcessed > 0 ? ($successful / $totalProcessed * 100) : 0,
                ],
            ], 'Import completed successfully');
        } catch (\Exception $e) {
            return $this->serverErrorResponse('Failed to import users: '.$e->getMessage());
        }
    }
}
