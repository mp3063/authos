<?php

namespace App\Http\Controllers\Api;

use App\Http\Controllers\Api\Traits\ApiControllerHelpers;
use App\Http\Controllers\Api\Traits\FindsOrgScopedApplications;
use App\Models\User;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Routing\Controller as BaseController;
use Illuminate\Validation\Rule;
use Laravel\Passport\Token;

class ApplicationUserController extends BaseController
{
    use ApiControllerHelpers;
    use FindsOrgScopedApplications;

    public function __construct()
    {
        $this->middleware('auth:api');
    }

    /**
     * Get application users
     */
    public function users(string $id): JsonResponse
    {
        $this->authorize('applications.read');

        $application = $this->findApplicationWithOrgScope($id);
        $users = $application->users()->withPivot(['granted_at', 'last_login_at', 'login_count'])->get();

        return response()->json([
            'data' => $users->map(function ($user) {
                return [
                    'id' => $user->id,
                    'name' => $user->name,
                    'email' => $user->email,
                    'granted_at' => $user->pivot->granted_at,
                    'last_login_at' => $user->pivot->last_login_at,
                    'login_count' => $user->pivot->login_count,
                ];
            }),
        ]);
    }

    /**
     * Grant user access to application
     */
    public function grantUserAccess(Request $request, string $id): JsonResponse
    {
        $this->authorize('applications.update');

        $application = $this->findApplicationWithOrgScope($id);

        $request->validate([
            'user_id' => [
                'required',
                'integer',
                Rule::exists('users', 'id')->where('organization_id', $application->organization_id),
            ],
        ]);

        $user = User::findOrFail($request->user_id);

        // Check if access already exists
        if ($application->users()->where('user_id', $user->id)->exists()) {
            return response()->json([
                'error' => 'resource_conflict',
                'error_description' => 'User already has access to this application.',
            ], 409);
        }

        $application->users()->attach($user->id, [
            'granted_at' => now(),
            'login_count' => 0,
        ]);

        return response()->json([
            'message' => 'User access granted successfully',
        ], 201);
    }

    /**
     * Revoke user access to application
     */
    public function revokeUserAccess(string $id, string $userId): JsonResponse
    {
        $this->authorize('applications.update');

        $application = $this->findApplicationWithOrgScope($id);
        $user = User::where('organization_id', $application->organization_id)->findOrFail($userId);

        if (! $application->users()->where('user_id', $user->id)->exists()) {
            return response()->json([
                'error' => 'resource_not_found',
                'error_description' => 'User does not have access to this application.',
            ], 404);
        }

        $application->users()->detach($user->id);

        // Revoke user's tokens for this application
        Token::where('client_id', $application->passport_client_id)
            ->where('user_id', $user->id)
            ->delete();

        return response()->json([], 204);
    }
}
