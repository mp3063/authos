<?php

namespace App\Http\Controllers\Api\Organizations;

use App\Http\Controllers\Api\BaseApiController;
use App\Http\Requests\Organization\GrantUserAccessRequest;
use App\Http\Resources\ApplicationResource;
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
            return $this->validationErrorResponse($validator->errors());
        }

        $query = User::with(['roles', 'organization'])
            ->where('organization_id', $organization->id);

        if ($request->has('search')) {
            $search = $request->get('search');
            $query->where(function ($q) use ($search) {
                $q->where('name', 'LIKE', "%$search%")
                    ->orWhere('email', 'LIKE', "%$search%");
            });
        }

        $filters = $request->get('filter', []);
        if (isset($filters['is_active'])) {
            $isActive = filter_var($filters['is_active'], FILTER_VALIDATE_BOOLEAN);
            $query->where('is_active', $isActive);
        }

        if (isset($filters['has_mfa'])) {
            $hasMfa = filter_var($filters['has_mfa'], FILTER_VALIDATE_BOOLEAN);
            if ($hasMfa) {
                $query->whereNotNull('mfa_methods');
            } else {
                $query->whereNull('mfa_methods');
            }
        }

        if (isset($filters['role'])) {
            $query->whereHas('roles', function ($q) use ($filters) {
                $q->where('name', $filters['role']);
            });
        }

        $sort = $request->get('sort', 'created_at');
        $order = $request->get('order', 'desc');
        $query->orderBy($sort, $order);

        $users = $query->paginate((int) $request->get('per_page', 15));

        return $this->paginatedResponse(
            $users,
            'Organization users retrieved successfully',
            UserResource::class
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
            return $this->validationErrorResponse($validator->errors());
        }

        $query = Application::where('organization_id', $organization->id)
            ->with(['organization', 'users']);

        if ($request->has('search')) {
            $search = $request->get('search');
            $query->where(function ($q) use ($search) {
                $q->where('name', 'LIKE', "%$search%")
                    ->orWhere('description', 'LIKE', "%$search%");
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

        return $this->paginatedResponse(
            $applications,
            'Organization applications retrieved successfully',
            ApplicationResource::class
        );
    }

    /**
     * Grant user access to an application
     */
    public function grantUserAccess(GrantUserAccessRequest $request, string $id): JsonResponse
    {
        $this->authorize('applications.update');

        $organization = Organization::findOrFail($id);

        $validator = Validator::make($request->all(), [
            'user_id' => 'required|exists:users,id',
            'application_id' => 'required|exists:applications,id',
        ]);

        if ($validator->fails()) {
            return $this->validationErrorResponse($validator->errors());
        }

        /** @var User $user */
        $user = User::findOrFail($request->input('user_id'));
        /** @var Application $application */
        $application = Application::findOrFail($request->input('application_id'));

        if ($user->organization_id !== $organization->id) {
            return $this->errorResponse('User does not belong to this organization');
        }

        if ($application->organization_id !== $organization->id) {
            return $this->errorResponse('Application does not belong to this organization');
        }

        if ($user->applications()->where('application_id', $application->id)->exists()) {
            return $this->errorResponse('User already has access to this application');
        }

        $result = $this->userService->grantApplicationAccess($user, $application->id);

        if ($result) {
            return $this->createdResponse(
                ['user_id' => $user->id, 'application_id' => $application->id],
                'User application access granted successfully'
            );
        }

        return $this->errorResponse('Failed to grant user access to application');
    }

    /**
     * Revoke user access from an application
     */
    public function revokeUserAccess(string $id, string $userId, string $applicationId): JsonResponse
    {
        $this->authorize('applications.update');

        $organization = Organization::findOrFail($id);

        /** @var User $user */
        $user = User::findOrFail($userId);
        /** @var Application $application */
        $application = Application::findOrFail($applicationId);

        if ($user->organization_id !== $organization->id) {
            return $this->errorResponse('User does not belong to this organization');
        }

        if ($application->organization_id !== $organization->id) {
            return $this->errorResponse('Application does not belong to this organization');
        }

        if (! $user->applications()->where('application_id', $application->id)->exists()) {
            return $this->errorResponse('User does not have access to this application');
        }

        $result = $this->userService->revokeApplicationAccess($user, $application->id);

        if ($result) {
            return $this->successResponse(
                ['user_id' => $user->id, 'application_id' => $application->id],
                'User application access revoked successfully'
            );
        }

        return $this->errorResponse('Failed to revoke user access from application');
    }
}
