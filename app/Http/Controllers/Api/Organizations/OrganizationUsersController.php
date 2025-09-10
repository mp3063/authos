<?php

namespace App\Http\Controllers\Api\Organizations;

use App\Http\Controllers\Api\BaseApiController;
use App\Http\Requests\Organization\GrantUserAccessRequest;
use App\Http\Resources\UserResource;
use App\Models\Application;
use App\Models\Organization;
use App\Models\User;
use App\Services\UserManagementService;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Validator;

class OrganizationUsersController extends BaseApiController
{
    protected UserManagementService $userService;

    public function __construct(UserManagementService $userService)
    {
        $this->userService = $userService;
        $this->middleware('auth:api');
    }

    /**
     * Get users within an organization
     */
    public function users(Request $request, string $id): JsonResponse
    {
        $this->authorize('users.read');

        $organization = Organization::findOrFail($id);

        $validator = Validator::make($request->all(), [
            'page' => 'sometimes|integer|min:1',
            'per_page' => 'sometimes|integer|min:1|max:100',
            'search' => 'sometimes|string|max:255',
            'sort' => 'sometimes|string|in:name,email,created_at,updated_at,last_login_at',
            'order' => 'sometimes|string|in:asc,desc',
            'filter' => 'sometimes|array',
            'filter.is_active' => 'sometimes|in:true,false,1,0',
            'filter.has_mfa' => 'sometimes|in:true,false,1,0',
            'filter.role' => 'sometimes|string|max:255',
        ]);

        if ($validator->fails()) {
            return $this->errorValidation($validator->errors());
        }

        $filters = $request->get('filter', []);
        $filters['organization_id'] = $organization->id;

        $users = $this->userService->getFilteredUsers(
            $request->get('search'),
            $filters,
            $request->get('sort', 'created_at'),
            $request->get('order', 'desc'),
            (int) $request->get('per_page', 15)
        );

        return $this->successResourceCollection(
            UserResource::collection($users),
            'Organization users retrieved successfully'
        );
    }

    /**
     * Get applications within an organization
     */
    public function applications(Request $request, string $id): JsonResponse
    {
        $this->authorize('applications.read');

        $organization = Organization::findOrFail($id);

        $validator = Validator::make($request->all(), [
            'page' => 'sometimes|integer|min:1',
            'per_page' => 'sometimes|integer|min:1|max:100',
            'search' => 'sometimes|string|max:255',
            'sort' => 'sometimes|string|in:name,created_at,updated_at',
            'order' => 'sometimes|string|in:asc,desc',
            'filter' => 'sometimes|array',
            'filter.is_active' => 'sometimes|in:true,false,1,0',
        ]);

        if ($validator->fails()) {
            return $this->errorValidation($validator->errors());
        }

        $query = Application::where('organization_id', $organization->id)
            ->with(['organization', 'users']);

        if ($request->has('search')) {
            $search = $request->get('search');
            $query->where(function ($q) use ($search) {
                $q->where('name', 'ILIKE', "%{$search}%")
                    ->orWhere('description', 'ILIKE', "%{$search}%");
            });
        }

        if ($request->has('filter.is_active')) {
            $isActive = filter_var($request->get('filter.is_active'), FILTER_VALIDATE_BOOLEAN);
            $query->where('is_active', $isActive);
        }

        $sort = $request->get('sort', 'created_at');
        $order = $request->get('order', 'desc');
        $query->orderBy($sort, $order);

        $applications = $query->paginate((int) $request->get('per_page', 15));

        return $this->successResourceCollection(
            $applications,
            'Organization applications retrieved successfully'
        );
    }

    /**
     * Grant user access to an application
     */
    public function grantUserAccess(GrantUserAccessRequest $request, string $id): JsonResponse
    {
        $this->authorize('applications.manage');

        $organization = Organization::findOrFail($id);

        $validator = Validator::make($request->all(), [
            'user_id' => 'required|exists:users,id',
            'application_id' => 'required|exists:applications,id',
        ]);

        if ($validator->fails()) {
            return $this->errorValidation($validator->errors());
        }

        $user = User::findOrFail($request->input('user_id'));
        $application = Application::findOrFail($request->input('application_id'));

        if ($user->organization_id !== $organization->id) {
            return $this->errorBadRequest('User does not belong to this organization');
        }

        if ($application->organization_id !== $organization->id) {
            return $this->errorBadRequest('Application does not belong to this organization');
        }

        if ($user->applications()->where('application_id', $application->id)->exists()) {
            return $this->errorBadRequest('User already has access to this application');
        }

        $result = $this->userService->grantApplicationAccess($user->id, $application->id);

        if ($result['success']) {
            return $this->success(
                $result['data'],
                'User access granted successfully'
            );
        }

        return $this->errorBadRequest($result['message']);
    }

    /**
     * Revoke user access from an application
     */
    public function revokeUserAccess(string $id, string $userId, string $applicationId): JsonResponse
    {
        $this->authorize('applications.manage');

        $organization = Organization::findOrFail($id);

        $user = User::findOrFail($userId);
        $application = Application::findOrFail($applicationId);

        if ($user->organization_id !== $organization->id) {
            return $this->errorBadRequest('User does not belong to this organization');
        }

        if ($application->organization_id !== $organization->id) {
            return $this->errorBadRequest('Application does not belong to this organization');
        }

        if (! $user->applications()->where('application_id', $application->id)->exists()) {
            return $this->errorBadRequest('User does not have access to this application');
        }

        $result = $this->userService->revokeApplicationAccess($user->id, $application->id);

        if ($result['success']) {
            return $this->success(
                $result['data'],
                'User access revoked successfully'
            );
        }

        return $this->errorBadRequest($result['message']);
    }
}
