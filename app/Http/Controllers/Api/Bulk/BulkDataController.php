<?php

namespace App\Http\Controllers\Api\Bulk;

use App\Http\Controllers\Api\Traits\ApiControllerHelpers;
use App\Http\Controllers\Api\Traits\FindsOrgScopedOrganizations;
use App\Models\User;
use App\Services\BulkUserDataService;
use App\Services\UserRoleService;
use Closure;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Routing\Controller as BaseController;
use Illuminate\Support\Str;
use Symfony\Component\HttpFoundation\BinaryFileResponse;

class BulkDataController extends BaseController
{
    use ApiControllerHelpers;
    use FindsOrgScopedOrganizations;

    protected BulkUserDataService $bulkUserDataService;

    public function __construct(BulkUserDataService $bulkUserDataService, private readonly UserRoleService $userRoleService)
    {
        $this->bulkUserDataService = $bulkUserDataService;
        $this->middleware('auth:api');
    }

    /**
     * Export users from an organization
     */
    public function exportUsers(Request $request, string $organizationId): JsonResponse|BinaryFileResponse
    {
        $organization = $this->findOrganizationWithOrgScope($organizationId);
        $this->authorize('viewAny', User::class);

        $request->validate([
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

            $result = $this->bulkUserDataService->exportUsersExtended(
                $organization,
                $options
            );

            // Generate export ID for tracking
            $exportId = (string) Str::uuid();

            return $this->successResponse([
                'export_id' => $exportId,
                'status' => 'completed',
                'download_url' => $result['download_url'],
                'total_records' => $result['users_count'],
                'format' => $result['format'],
                'filename' => $result['filename'],
                'expires_at' => $result['expires_at'],
            ], 'Export completed successfully');
        } catch (\Exception $e) {
            return $this->serverErrorResponse('Failed to export users: '.$e->getMessage());
        }
    }

    /**
     * Import users to an organization
     */
    public function importUsers(Request $request, string $organizationId): JsonResponse
    {
        $organization = $this->findOrganizationWithOrgScope($organizationId);
        $this->authorize('create', User::class);

        $updateExisting = $request->boolean('update_existing', $request->boolean('options.update_existing'));
        if ($updateExisting) {
            $this->authorize('updateAny', User::class);
        }

        $defaultRoleRules = [
            'bail',
            'sometimes',
            'string',
            $this->userRoleService->assignableRoleRule($request->user(), $organization->id, 'name'),
            function (string $attribute, mixed $value, Closure $fail) use ($request, $organization): void {
                if ($this->userRoleService->grantableRole($request->user(), $organization->id, $value, (new User)->getDefaultGuardName()) === null) {
                    $fail('You cannot grant the specified default role');
                }
            },
        ];

        $request->validate([
            'file' => 'required|file|mimes:csv,xlsx,json|max:10240',
            'format' => 'sometimes|string|in:csv,xlsx,json',
            'send_invitations' => 'sometimes|boolean',
            'default_role' => $defaultRoleRules,
            'skip_duplicates' => 'sometimes|boolean',
            'update_existing' => 'sometimes|boolean',
            'invite_expires_in_days' => 'sometimes|integer|min:1|max:30',
            'options' => 'sometimes|array',
            'options.send_invitations' => 'sometimes|boolean',
            'options.default_role' => $defaultRoleRules,
            'options.skip_duplicates' => 'sometimes|boolean',
            'options.update_existing' => 'sometimes|boolean',
            'mapping' => 'sometimes|array',
            'mapping.name' => 'sometimes|string',
            'mapping.email' => 'sometimes|string',
            'mapping.role' => 'sometimes|string',
        ]);

        try {
            $file = $request->file('file');

            $requestOptions = $request->get('options', []);

            // Merge top-level options with nested options object
            $options = [
                'send_invitations' => $request->boolean('send_invitations', $requestOptions['send_invitations'] ?? false),
                'default_role' => $request->get('default_role', $requestOptions['default_role'] ?? 'user'),
                'skip_duplicates' => $request->boolean('skip_duplicates', $requestOptions['skip_duplicates'] ?? false),
                'update_existing' => $updateExisting,
                'invite_expires_in_days' => $request->integer('invite_expires_in_days', 7),
            ];

            $result = $this->bulkUserDataService->importUsersExtended(
                $file,
                $organization,
                $options,
                auth()->user()
            );

            // The service returns the direct result from UsersImport::getResults()
            // which has the structure: ['created' => [], 'updated' => [], 'invited' => [], 'failed' => []]

            $totalProcessed = count($result['created']) + count($result['updated']) + count($result['invited']) + count($result['failed']);
            $successful = count($result['created']) + count($result['updated']) + count($result['invited']);

            // Generate import ID for tracking
            $importId = (string) Str::uuid();

            return response()->json([
                'data' => [
                    'import_id' => $importId,
                    'status' => 'completed',
                    'total_records' => $totalProcessed,
                    'processed_records' => $successful,
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
                ],
                'message' => 'Import completed successfully',
            ], 201);
        } catch (\Exception $e) {
            return $this->serverErrorResponse('Failed to import users: '.$e->getMessage());
        }
    }
}
