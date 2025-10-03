<?php

namespace App\Http\Controllers\Api;

use App\Models\Application;
use App\Models\AuthenticationLog;
use App\Models\User;
use App\Services\AuthenticationLogService;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Validator;
use Illuminate\Support\Str;
use Laravel\Passport\Client;
use Laravel\Passport\Token;

class ApplicationController extends BaseApiController
{
    protected AuthenticationLogService $authLogService;

    public function __construct(AuthenticationLogService $authLogService)
    {
        $this->authLogService = $authLogService;
        $this->middleware('auth:api');
    }

    /**
     * Display a paginated listing of applications
     */
    public function index(Request $request): JsonResponse
    {
        $this->authorize('applications.read');

        $validator = Validator::make($request->all(), [
            'page' => 'sometimes|integer|min:1',
            'per_page' => 'sometimes|integer|min:1|max:100',
            'search' => 'sometimes|string|max:255',
            'sort' => 'sometimes|string|in:name,created_at,updated_at',
            'order' => 'sometimes|string|in:asc,desc',
            'organization_id' => 'sometimes|integer|exists:organizations,id',
            'is_active' => 'sometimes|boolean',
        ]);

        if ($validator->fails()) {
            return response()->json([
                'error' => 'validation_failed',
                'error_description' => 'The given data was invalid.',
                'details' => $validator->errors(),
            ], 422);
        }

        $query = Application::query()->with(['organization']);

        // Enforce organization-based data isolation for non-super-admin users
        $currentUser = auth()->user();
        if (! $currentUser->hasRole('Super Admin') && ! $currentUser->hasRole('super-admin')) {
            $query->where('organization_id', $currentUser->organization_id);
        }

        // Apply filters
        if ($request->has('search')) {
            $search = $request->search;
            $query->where(function ($q) use ($search) {
                $q->where('name', 'LIKE', "%$search%")
                    ->orWhere('client_id', 'LIKE', "%$search%");
            });
        }

        if ($request->has('organization_id')) {
            // Only allow filtering by organization_id if user is super admin or it's their own organization
            if ($currentUser->hasRole('Super Admin') || $currentUser->hasRole('super-admin') ||
                $request->organization_id == $currentUser->organization_id) {
                $query->where('organization_id', $request->organization_id);
            }
        }

        if ($request->has('is_active')) {
            $query->where('is_active', $request->is_active);
        }

        // Apply sorting
        $sort = $request->input('sort', 'created_at');
        $order = $request->input('order', 'desc');
        $query->orderBy($sort, $order);

        // Paginate
        $perPage = $request->input('per_page', 15);
        $applications = $query->paginate($perPage);

        return response()->json([
            'data' => collect($applications->items())->map(function ($app) {
                return $this->formatApplicationResponse($app);
            }),
            'meta' => [
                'pagination' => [
                    'current_page' => $applications->currentPage(),
                    'per_page' => $applications->perPage(),
                    'total' => $applications->total(),
                    'total_pages' => $applications->lastPage(),
                ],
            ],
            'links' => [
                'self' => $applications->url($applications->currentPage()),
                'next' => $applications->nextPageUrl(),
                'prev' => $applications->previousPageUrl(),
            ],
        ]);
    }

    /**
     * Store a newly created application
     */
    public function store(Request $request): JsonResponse
    {
        $this->authorize('applications.create');

        $validator = Validator::make($request->all(), [
            'organization_id' => 'required|exists:organizations,id',
            'name' => 'required|string|max:255',
            'redirect_uris' => 'required|array|min:1|max:10',
            'redirect_uris.*' => 'required|url|max:2048',
            'allowed_origins' => 'sometimes|array|max:10',
            'allowed_origins.*' => 'url',
            'allowed_grant_types' => 'required|array',
            'allowed_grant_types.*' => 'in:authorization_code,client_credentials,refresh_token,password',
            'scopes' => 'sometimes|array',
            'scopes.*' => 'in:openid,profile,email,read,write,admin',
            'settings' => 'sometimes|array',
            'settings.token_lifetime' => 'sometimes|integer|min:300|max:86400', // 5 minutes to 24 hours
            'settings.refresh_token_lifetime' => 'sometimes|integer|min:3600|max:31536000', // 1 hour to 1 year
            'settings.require_pkce' => 'sometimes|boolean',
            'settings.auto_approve' => 'sometimes|boolean',
            'description' => 'sometimes|string|max:1000',
        ]);

        if ($validator->fails()) {
            return response()->json([
                'error' => 'validation_failed',
                'error_description' => 'The given data was invalid.',
                'details' => $validator->errors(),
            ], 422);
        }

        // Generate OAuth client credentials
        $clientId = Str::uuid()->toString();
        $clientSecret = Str::random(64);

        // Create Passport client
        $passportClient = Client::create([
            'name' => $request->name,
            'secret' => hash('sha256', $clientSecret),
            'redirect' => implode(',', $request->redirect_uris),
            'personal_access_client' => false,
            'password_client' => in_array('password', $request->allowed_grant_types),
            'revoked' => false,
        ]);

        // Create application record with description stored in settings
        $settings = array_merge([
            'token_lifetime' => 3600,
            'refresh_token_lifetime' => 2592000,
            'require_pkce' => true,
            'auto_approve' => false,
        ], $request->input('settings', []));

        // Add description to settings if provided
        if ($request->has('description')) {
            $settings['description'] = $request->input('description');
        }

        $application = Application::create([
            'organization_id' => $request->organization_id,
            'name' => $request->name,
            'client_id' => $clientId,
            'client_secret' => $clientSecret,
            'passport_client_id' => $passportClient->id,
            'redirect_uris' => $request->redirect_uris,
            'allowed_origins' => $request->input('allowed_origins', []),
            'allowed_grant_types' => $request->allowed_grant_types,
            'scopes' => $request->input('scopes', ['openid', 'profile', 'email']),
            'settings' => $settings,
            'is_active' => true,
        ]);

        return response()->json([
            'data' => $this->formatApplicationResponse($application, true),
            'message' => 'Application created successfully',
        ], 201);
    }

    /**
     * Display the specified application
     */
    public function show(string $id): JsonResponse
    {
        $this->authorize('applications.read');

        $query = Application::with(['organization', 'users']);

        // Enforce organization-based data isolation for non-super-admin users
        $currentUser = auth()->user();
        if (! $currentUser->hasRole('Super Admin') && ! $currentUser->hasRole('super-admin')) {
            $query->where('organization_id', $currentUser->organization_id);
        }

        /** @var Application $application */
        $application = $query->findOrFail($id);

        return $this->successResponse($this->formatApplicationResponse($application, true));
    }

    /**
     * Update the specified application
     */
    public function update(Request $request, string $id): JsonResponse
    {
        $this->authorize('applications.update');

        $application = Application::findOrFail($id);

        $validator = Validator::make($request->all(), [
            'name' => 'sometimes|string|max:255',
            'description' => 'sometimes|string|max:1000',
            'redirect_uris' => 'sometimes|array|min:1|max:10',
            'redirect_uris.*' => 'required|url|max:2048',
            'allowed_origins' => 'sometimes|array|max:10',
            'allowed_origins.*' => 'url',
            'allowed_grant_types' => 'sometimes|array',
            'allowed_grant_types.*' => 'in:authorization_code,client_credentials,refresh_token,password',
            'scopes' => 'sometimes|array',
            'scopes.*' => 'in:openid,profile,email,read,write,admin',
            'settings' => 'sometimes|array',
            'settings.token_lifetime' => 'sometimes|integer|min:300|max:86400',
            'settings.refresh_token_lifetime' => 'sometimes|integer|min:3600|max:31536000',
            'settings.require_pkce' => 'sometimes|boolean',
            'settings.auto_approve' => 'sometimes|boolean',
            'is_active' => 'sometimes|boolean',
        ]);

        if ($validator->fails()) {
            return response()->json([
                'error' => 'validation_failed',
                'error_description' => 'The given data was invalid.',
                'details' => $validator->errors(),
            ], 422);
        }

        $updateData = $request->only([
            'name', 'redirect_uris', 'allowed_origins',
            'allowed_grant_types', 'scopes', 'is_active',
        ]);

        if ($request->has('settings') || $request->has('description')) {
            $settings = array_merge($application->settings ?? [], $request->input('settings', []));

            // Add description to settings if provided
            if ($request->has('description')) {
                $settings['description'] = $request->input('description');
            }

            $updateData['settings'] = $settings;
        }

        $application->update($updateData);

        // Update Passport client if needed
        if ($request->has('name') || $request->has('redirect_uris')) {
            Client::find($application->passport_client_id)?->update([
                'name' => $application->name,
                'redirect' => implode(',', $application->redirect_uris),
            ]);
        }

        return response()->json([
            'data' => $this->formatApplicationResponse($application->fresh()),
            'message' => 'Application updated successfully',
        ]);
    }

    /**
     * Remove the specified application
     */
    public function destroy(string $id): JsonResponse
    {
        $this->authorize('applications.delete');

        $application = Application::findOrFail($id);

        // Revoke all tokens for this application
        Token::where('client_id', $application->passport_client_id)->delete();

        // Delete Passport client
        Client::find($application->passport_client_id)?->delete();

        // Delete application
        $application->delete();

        return response()->json([], 204);
    }

    /**
     * Regenerate application credentials
     */
    public function regenerateCredentials(string $id): JsonResponse
    {
        $this->authorize('applications.update');

        $application = Application::findOrFail($id);

        // Generate new credentials
        $newClientId = Str::uuid()->toString();
        $newClientSecret = Str::random(64);

        // Update application
        $application->update([
            'client_id' => $newClientId,
            'client_secret' => $newClientSecret,
        ]);

        // Update Passport client
        Client::find($application->passport_client_id)?->update([
            'secret' => hash('sha256', $newClientSecret),
        ]);

        // Revoke all existing tokens
        Token::where('client_id', $application->passport_client_id)->delete();

        return response()->json([
            'data' => [
                'client_id' => $newClientId,
                'client_secret' => $newClientSecret,
            ],
            'message' => 'Application credentials regenerated successfully',
        ]);
    }

    /**
     * Get application users
     */
    public function users(string $id): JsonResponse
    {
        $this->authorize('applications.read');

        $application = Application::findOrFail($id);
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

        $validator = Validator::make($request->all(), [
            'user_id' => 'required|integer|exists:users,id',
        ]);

        if ($validator->fails()) {
            return response()->json([
                'error' => 'validation_failed',
                'error_description' => 'The given data was invalid.',
                'details' => $validator->errors(),
            ], 422);
        }

        $application = Application::findOrFail($id);
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

        $application = Application::findOrFail($id);
        $user = User::findOrFail($userId);

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

    /**
     * Get application active tokens
     */
    public function tokens(string $id): JsonResponse
    {
        $this->authorize('applications.read');

        $application = Application::findOrFail($id);
        $tokens = Token::where('client_id', $application->passport_client_id)
            ->where('expires_at', '>', now())
            ->get();

        return response()->json([
            'data' => $tokens->map(function ($token) {
                // Load user manually to avoid relationship issues
                $user = User::find($token->user_id);

                return [
                    'id' => $token->id,
                    'name' => $token->name,
                    'scopes' => $token->scopes,
                    'user' => $user ? [
                        'id' => $user->id,
                        'name' => $user->name,
                        'email' => $user->email,
                    ] : null,
                    'created_at' => $token->created_at,
                    'expires_at' => $token->expires_at,
                    'last_used_at' => $token->last_used_at,
                ];
            }),
        ]);
    }

    /**
     * Revoke all application tokens
     */
    public function revokeAllTokens(string $id): JsonResponse
    {
        $this->authorize('applications.update');

        $application = Application::findOrFail($id);
        $revokedCount = Token::where('client_id', $application->passport_client_id)->count();

        Token::where('client_id', $application->passport_client_id)->delete();

        return response()->json([
            'message' => "Revoked $revokedCount active tokens",
        ]);
    }

    /**
     * Revoke specific application token
     */
    public function revokeToken(string $id, string $tokenId): JsonResponse
    {
        $this->authorize('applications.update');

        $application = Application::findOrFail($id);
        $token = Token::where('client_id', $application->passport_client_id)
            ->where('id', $tokenId)
            ->first();

        if (! $token) {
            return response()->json([
                'error' => 'resource_not_found',
                'error_description' => 'Token not found.',
            ], 404);
        }

        // Log the token revocation
        if ($token->user) {
            $this->authLogService->logAuthenticationEvent($token->user, 'token_revoked', [
                'token_id' => $token->id,
                'application_id' => $application->id,
            ]);
        }

        // Revoke the token using Passport
        $token->revoke();

        // Also revoke refresh token if it exists
        if ($token->refreshToken) {
            $token->refreshToken->revoke();
        }

        return response()->json([
            'message' => 'Token revoked successfully',
        ]);
    }

    /**
     * Get application analytics
     */
    public function analytics(Request $request, string $id): JsonResponse
    {
        $this->authorize('applications.read');

        $validator = Validator::make($request->all(), [
            'period' => 'sometimes|string|in:24h,7d,30d,90d',
        ]);

        if ($validator->fails()) {
            return response()->json([
                'error' => 'validation_failed',
                'error_description' => 'The given data was invalid.',
                'details' => $validator->errors(),
            ], 422);
        }

        $application = Application::findOrFail($id);
        $period = $request->input('period', '7d');

        // Calculate period start date
        $periodMap = [
            '24h' => now()->subHours(24),
            '7d' => now()->subDays(7),
            '30d' => now()->subDays(30),
            '90d' => now()->subDays(90),
        ];

        $startDate = $periodMap[$period];

        // Get analytics data
        $totalUsers = $application->users()->count();
        $activeTokens = Token::where('client_id', $application->passport_client_id)
            ->where('expires_at', '>', now())
            ->count();

        $authLogs = AuthenticationLog::where('application_id', $application->id)
            ->where('created_at', '>=', $startDate)
            ->get();

        $successfulLogins = $authLogs->where('event', 'login_success')->count();
        $failedLogins = $authLogs->where('event', 'login_failed')->count();
        $uniqueUsers = $authLogs->pluck('user_id')->unique()->count();

        return response()->json([
            'data' => [
                'period' => $period,
                'total_users' => $totalUsers,
                'active_tokens' => $activeTokens,
                'successful_logins' => $successfulLogins,
                'failed_logins' => $failedLogins,
                'unique_active_users' => $uniqueUsers,
                'login_success_rate' => $successfulLogins + $failedLogins > 0
                    ? round(($successfulLogins / ($successfulLogins + $failedLogins)) * 100, 2)
                    : 0,
            ],
        ]);
    }

    /**
     * Format application response
     */
    private function formatApplicationResponse(Application $application, bool $detailed = false): array
    {
        $data = [
            'id' => $application->id,
            'name' => $application->name,
            'description' => $application->settings['description'] ?? null,
            'client_id' => $application->client_id,
            'redirect_uris' => $application->redirect_uris,
            'allowed_origins' => $application->allowed_origins,
            'allowed_grant_types' => $application->allowed_grant_types,
            'scopes' => $application->scopes,
            'settings' => $application->settings,
            'is_active' => $application->is_active,
            'organization_id' => $application->organization_id,
            'organization' => $application->organization ? [
                'id' => $application->organization->id,
                'name' => $application->organization->name,
                'slug' => $application->organization->slug,
            ] : null,
            'user_count' => $application->users()->count(),
            'created_at' => $application->created_at,
            'updated_at' => $application->updated_at,
        ];

        if ($detailed) {
            $data['client_secret'] = $application->client_secret;

            if ($application->relationLoaded('users')) {
                $data['users'] = $application->users->map(function ($user) {
                    return [
                        'id' => $user->id,
                        'name' => $user->name,
                        'email' => $user->email,
                        'granted_at' => $user->pivot->granted_at ?? null,
                        'last_login_at' => $user->pivot->last_login_at ?? null,
                        'login_count' => $user->pivot->login_count ?? 0,
                    ];
                });
            }
        }

        return $data;
    }
}
