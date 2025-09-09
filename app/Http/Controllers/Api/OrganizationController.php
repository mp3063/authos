<?php

namespace App\Http\Controllers\Api;

use App\Http\Controllers\Controller;
use App\Models\Organization;
use App\Models\User;
use App\Models\Application;
use App\Models\AuthenticationLog;
use App\Services\OAuthService;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Validator;
use Illuminate\Support\Str;
use Illuminate\Validation\Rule;
use Carbon\Carbon;

class OrganizationController extends Controller
{
    protected OAuthService $oAuthService;

    public function __construct(OAuthService $oAuthService)
    {
        $this->oAuthService = $oAuthService;
        $this->middleware('auth:api');
    }

    /**
     * Display a paginated listing of organizations
     */
    public function index(Request $request): JsonResponse
    {
        $this->authorize('organizations.read');

        $validator = Validator::make($request->all(), [
            'page' => 'sometimes|integer|min:1',
            'per_page' => 'sometimes|integer|min:1|max:100',
            'search' => 'sometimes|string|max:255',
            'sort' => 'sometimes|string|in:name,slug,created_at,updated_at',
            'order' => 'sometimes|string|in:asc,desc',
            'is_active' => 'sometimes|boolean',
        ]);

        if ($validator->fails()) {
            return response()->json([
                'error' => 'validation_failed',
                'error_description' => 'The given data was invalid.',
                'details' => $validator->errors(),
            ], 422);
        }

        $query = Organization::query()->withCount('applications');

        // Apply filters
        if ($request->has('search')) {
            $search = $request->search;
            $query->where(function ($q) use ($search) {
                $q->where('name', 'LIKE', "%{$search}%")
                  ->orWhere('slug', 'LIKE', "%{$search}%");
            });
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
        $organizations = $query->paginate($perPage);

        return response()->json([
            'data' => collect($organizations->items())->map(function ($organization) {
                return $this->formatOrganizationResponse($organization);
            }),
            'meta' => [
                'pagination' => [
                    'current_page' => $organizations->currentPage(),
                    'per_page' => $organizations->perPage(),
                    'total' => $organizations->total(),
                    'total_pages' => $organizations->lastPage(),
                ],
            ],
            'links' => [
                'self' => $organizations->url($organizations->currentPage()),
                'next' => $organizations->nextPageUrl(),
                'prev' => $organizations->previousPageUrl(),
            ],
        ]);
    }

    /**
     * Store a newly created organization
     */
    public function store(Request $request): JsonResponse
    {
        $this->authorize('organizations.create');

        $validator = Validator::make($request->all(), [
            'name' => 'required|string|max:255',
            'slug' => 'sometimes|string|max:255|unique:organizations,slug|regex:/^[a-z0-9-]+$/',
            'settings' => 'sometimes|array',
            'settings.require_mfa' => 'sometimes|boolean',
            'settings.password_policy' => 'sometimes|array',
            'settings.password_policy.min_length' => 'sometimes|integer|min:6|max:128',
            'settings.password_policy.require_uppercase' => 'sometimes|boolean',
            'settings.password_policy.require_lowercase' => 'sometimes|boolean',
            'settings.password_policy.require_numbers' => 'sometimes|boolean',
            'settings.password_policy.require_symbols' => 'sometimes|boolean',
            'settings.session_timeout' => 'sometimes|integer|min:300|max:86400',
            'settings.allowed_domains' => 'sometimes|array',
            'settings.allowed_domains.*' => 'string|regex:/^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/',
            'settings.branding' => 'sometimes|array',
            'settings.branding.logo_url' => 'sometimes|string|url|max:2048',
            'settings.branding.primary_color' => 'sometimes|string|regex:/^#[0-9A-Fa-f]{6}$/',
            'settings.branding.secondary_color' => 'sometimes|string|regex:/^#[0-9A-Fa-f]{6}$/',
            'is_active' => 'sometimes|boolean',
        ]);

        if ($validator->fails()) {
            return response()->json([
                'error' => 'validation_failed',
                'error_description' => 'The given data was invalid.',
                'details' => $validator->errors(),
            ], 422);
        }

        // Generate slug if not provided
        $slug = $request->input('slug', Str::slug($request->name));
        
        // Ensure slug is unique
        $originalSlug = $slug;
        $counter = 1;
        while (Organization::where('slug', $slug)->exists()) {
            $slug = $originalSlug . '-' . $counter;
            $counter++;
        }

        // Default settings
        $defaultSettings = [
            'require_mfa' => false,
            'password_policy' => [
                'min_length' => 8,
                'require_uppercase' => true,
                'require_lowercase' => true,
                'require_numbers' => true,
                'require_symbols' => true,
            ],
            'session_timeout' => 3600, // 1 hour
            'allowed_domains' => [],
            'branding' => [
                'logo_url' => null,
                'primary_color' => '#3B82F6',
                'secondary_color' => '#64748B',
            ],
        ];

        $settings = array_merge($defaultSettings, $request->input('settings', []));

        $organization = Organization::create([
            'name' => $request->name,
            'slug' => $slug,
            'settings' => $settings,
            'is_active' => $request->input('is_active', true),
        ]);

        // Log organization creation
        $this->oAuthService->logAuthenticationEvent(
            auth()->user(),
            'organization_created',
            $request,
            null,
            true,
            ['organization_id' => $organization->id, 'organization_name' => $organization->name]
        );

        return response()->json([
            'data' => $this->formatOrganizationResponse($organization),
            'message' => 'Organization created successfully',
        ], 201);
    }

    /**
     * Display the specified organization
     */
    public function show(string $id): JsonResponse
    {
        $this->authorize('organizations.read');

        $organization = Organization::withCount('applications')
            ->with('applications:id,name,client_id,is_active,organization_id')
            ->findOrFail($id);

        return response()->json([
            'data' => $this->formatOrganizationResponse($organization, true),
        ]);
    }

    /**
     * Update the specified organization
     */
    public function update(Request $request, string $id): JsonResponse
    {
        $this->authorize('organizations.update');

        $organization = Organization::findOrFail($id);

        $validator = Validator::make($request->all(), [
            'name' => 'sometimes|string|max:255',
            'slug' => [
                'sometimes',
                'string',
                'max:255',
                'regex:/^[a-z0-9-]+$/',
                Rule::unique('organizations', 'slug')->ignore($organization->id),
            ],
            'settings' => 'sometimes|array',
            'settings.require_mfa' => 'sometimes|boolean',
            'settings.password_policy' => 'sometimes|array',
            'settings.password_policy.min_length' => 'sometimes|integer|min:6|max:128',
            'settings.password_policy.require_uppercase' => 'sometimes|boolean',
            'settings.password_policy.require_lowercase' => 'sometimes|boolean',
            'settings.password_policy.require_numbers' => 'sometimes|boolean',
            'settings.password_policy.require_symbols' => 'sometimes|boolean',
            'settings.session_timeout' => 'sometimes|integer|min:300|max:86400',
            'settings.allowed_domains' => 'sometimes|array',
            'settings.allowed_domains.*' => 'string|regex:/^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/',
            'settings.branding' => 'sometimes|array',
            'settings.branding.logo_url' => 'sometimes|string|url|max:2048',
            'settings.branding.primary_color' => 'sometimes|string|regex:/^#[0-9A-Fa-f]{6}$/',
            'settings.branding.secondary_color' => 'sometimes|string|regex:/^#[0-9A-Fa-f]{6}$/',
            'is_active' => 'sometimes|boolean',
        ]);

        if ($validator->fails()) {
            return response()->json([
                'error' => 'validation_failed',
                'error_description' => 'The given data was invalid.',
                'details' => $validator->errors(),
            ], 422);
        }

        $updateData = $request->only(['name', 'slug', 'is_active']);

        // Handle settings update (merge with existing)
        if ($request->has('settings')) {
            $currentSettings = $organization->settings ?? [];
            $newSettings = $request->input('settings');
            
            // Deep merge settings
            $updateData['settings'] = array_merge_recursive($currentSettings, $newSettings);
        }

        $organization->update($updateData);

        // Log organization update
        $this->oAuthService->logAuthenticationEvent(
            auth()->user(),
            'organization_updated',
            $request,
            null,
            true,
            ['organization_id' => $organization->id, 'organization_name' => $organization->name]
        );

        return response()->json([
            'data' => $this->formatOrganizationResponse($organization->fresh()),
            'message' => 'Organization updated successfully',
        ]);
    }

    /**
     * Remove the specified organization
     */
    public function destroy(string $id): JsonResponse
    {
        $this->authorize('organizations.delete');

        $organization = Organization::withCount('applications')->findOrFail($id);

        // Prevent deletion if organization has active applications or users
        if ($organization->applications_count > 0) {
            return response()->json([
                'error' => 'resource_conflict',
                'error_description' => 'Cannot delete organization with active applications.',
            ], 409);
        }

        // Manually calculate users count
        $usersCount = User::whereHas('applications', function ($query) use ($organization) {
            $query->where('organization_id', $organization->id);
        })->count();

        if ($usersCount > 0) {
            return response()->json([
                'error' => 'resource_conflict',
                'error_description' => 'Cannot delete organization with active users.',
            ], 409);
        }

        // Log organization deletion
        $this->oAuthService->logAuthenticationEvent(
            auth()->user(),
            'organization_deleted',
            request(),
            null,
            true,
            ['organization_id' => $organization->id, 'organization_name' => $organization->name]
        );

        $organization->delete();

        return response()->json([], 204);
    }

    /**
     * Get organization settings
     */
    public function settings(string $id): JsonResponse
    {
        $this->authorize('organizations.read');

        $organization = Organization::findOrFail($id);

        return response()->json([
            'data' => [
                'settings' => $organization->settings ?? [],
            ],
        ]);
    }

    /**
     * Update organization settings
     */
    public function updateSettings(Request $request, string $id): JsonResponse
    {
        $this->authorize('organizations.update');

        $organization = Organization::findOrFail($id);

        $validator = Validator::make($request->all(), [
            'require_mfa' => 'sometimes|boolean',
            'password_policy' => 'sometimes|array',
            'password_policy.min_length' => 'sometimes|integer|min:6|max:128',
            'password_policy.require_uppercase' => 'sometimes|boolean',
            'password_policy.require_lowercase' => 'sometimes|boolean',
            'password_policy.require_numbers' => 'sometimes|boolean',
            'password_policy.require_symbols' => 'sometimes|boolean',
            'session_timeout' => 'sometimes|integer|min:300|max:86400',
            'allowed_domains' => 'sometimes|array',
            'allowed_domains.*' => 'string|regex:/^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/',
            'branding' => 'sometimes|array',
            'branding.logo_url' => 'sometimes|string|url|max:2048',
            'branding.primary_color' => 'sometimes|string|regex:/^#[0-9A-Fa-f]{6}$/',
            'branding.secondary_color' => 'sometimes|string|regex:/^#[0-9A-Fa-f]{6}$/',
        ]);

        if ($validator->fails()) {
            return response()->json([
                'error' => 'validation_failed',
                'error_description' => 'The given data was invalid.',
                'details' => $validator->errors(),
            ], 422);
        }

        $currentSettings = $organization->settings ?? [];
        $newSettings = $request->only([
            'require_mfa', 'password_policy', 'session_timeout', 
            'allowed_domains', 'branding'
        ]);

        // Deep merge settings
        $updatedSettings = array_merge_recursive($currentSettings, $newSettings);
        
        $organization->update(['settings' => $updatedSettings]);

        // Log settings update
        $this->oAuthService->logAuthenticationEvent(
            auth()->user(),
            'organization_settings_updated',
            $request,
            null,
            true,
            ['organization_id' => $organization->id, 'organization_name' => $organization->name]
        );

        return response()->json([
            'data' => [
                'settings' => $updatedSettings,
            ],
            'message' => 'Organization settings updated successfully',
        ]);
    }

    /**
     * Get organization users
     */
    public function users(Request $request, string $id): JsonResponse
    {
        $this->authorize('organizations.read');

        $organization = Organization::findOrFail($id);

        $validator = Validator::make($request->all(), [
            'page' => 'sometimes|integer|min:1',
            'per_page' => 'sometimes|integer|min:1|max:100',
            'search' => 'sometimes|string|max:255',
            'sort' => 'sometimes|string|in:name,email,last_login_at,login_count',
            'order' => 'sometimes|string|in:asc,desc',
            'application_id' => 'sometimes|integer|exists:applications,id',
        ]);

        if ($validator->fails()) {
            return response()->json([
                'error' => 'validation_failed',
                'error_description' => 'The given data was invalid.',
                'details' => $validator->errors(),
            ], 422);
        }

        // Get users through applications
        $query = User::whereHas('applications', function ($q) use ($organization, $request) {
            $q->where('organization_id', $organization->id);
            
            if ($request->has('application_id')) {
                $q->where('application_id', $request->application_id);
            }
        })->with(['roles', 'applications' => function ($q) use ($organization) {
            $q->where('organization_id', $organization->id)
              ->withPivot(['granted_at', 'last_login_at', 'login_count']);
        }]);

        // Apply search filter
        if ($request->has('search')) {
            $search = $request->search;
            $query->where(function ($q) use ($search) {
                $q->where('name', 'LIKE', "%{$search}%")
                  ->orWhere('email', 'LIKE', "%{$search}%");
            });
        }

        // Apply sorting
        $sort = $request->input('sort', 'name');
        $order = $request->input('order', 'asc');
        
        if (in_array($sort, ['last_login_at', 'login_count'])) {
            // Sort by pivot data requires special handling
            $query->join('user_applications', 'users.id', '=', 'user_applications.user_id')
                  ->join('applications', 'user_applications.application_id', '=', 'applications.id')
                  ->where('applications.organization_id', $organization->id)
                  ->orderBy('user_applications.' . $sort, $order)
                  ->select('users.*')
                  ->distinct();
        } else {
            $query->orderBy($sort, $order);
        }

        // Paginate
        $perPage = $request->input('per_page', 15);
        $users = $query->paginate($perPage);

        return response()->json([
            'data' => $users->items()->map(function ($user) use ($organization) {
                return $this->formatUserResponse($user, $organization);
            }),
            'meta' => [
                'pagination' => [
                    'current_page' => $users->currentPage(),
                    'per_page' => $users->perPage(),
                    'total' => $users->total(),
                    'total_pages' => $users->lastPage(),
                ],
                'organization' => [
                    'id' => $organization->id,
                    'name' => $organization->name,
                    'slug' => $organization->slug,
                ],
            ],
            'links' => [
                'self' => $users->url($users->currentPage()),
                'next' => $users->nextPageUrl(),
                'prev' => $users->previousPageUrl(),
            ],
        ]);
    }

    /**
     * Get organization applications
     */
    public function applications(Request $request, string $id): JsonResponse
    {
        $this->authorize('organizations.read');

        $organization = Organization::findOrFail($id);

        $validator = Validator::make($request->all(), [
            'page' => 'sometimes|integer|min:1',
            'per_page' => 'sometimes|integer|min:1|max:100',
            'search' => 'sometimes|string|max:255',
            'sort' => 'sometimes|string|in:name,client_id,created_at,updated_at',
            'order' => 'sometimes|string|in:asc,desc',
            'is_active' => 'sometimes|boolean',
        ]);

        if ($validator->fails()) {
            return response()->json([
                'error' => 'validation_failed',
                'error_description' => 'The given data was invalid.',
                'details' => $validator->errors(),
            ], 422);
        }

        $query = $organization->applications();

        // Apply filters
        if ($request->has('search')) {
            $search = $request->search;
            $query->where(function ($q) use ($search) {
                $q->where('name', 'LIKE', "%{$search}%")
                  ->orWhere('client_id', 'LIKE', "%{$search}%");
            });
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
            'data' => collect($applications->items())->map(function ($application) {
                return [
                    'id' => $application->id,
                    'name' => $application->name,
                    'client_id' => $application->client_id,
                    'redirect_uris' => $application->redirect_uris ?? [],
                    'scopes' => $application->scopes ?? [],
                    'is_active' => $application->is_active,
                    'users_count' => $application->users()->count(),
                    'created_at' => $application->created_at,
                    'updated_at' => $application->updated_at,
                ];
            }),
            'meta' => [
                'pagination' => [
                    'current_page' => $applications->currentPage(),
                    'per_page' => $applications->perPage(),
                    'total' => $applications->total(),
                    'total_pages' => $applications->lastPage(),
                ],
                'organization' => [
                    'id' => $organization->id,
                    'name' => $organization->name,
                    'slug' => $organization->slug,
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
     * Grant user access to organization (through application)
     */
    public function grantUserAccess(Request $request, string $id): JsonResponse
    {
        $this->authorize('organizations.manage_users');

        $validator = Validator::make($request->all(), [
            'user_id' => 'required|integer|exists:users,id',
            'application_id' => 'required|integer|exists:applications,id',
        ]);

        if ($validator->fails()) {
            return response()->json([
                'error' => 'validation_failed',
                'error_description' => 'The given data was invalid.',
                'details' => $validator->errors(),
            ], 422);
        }

        $organization = Organization::findOrFail($id);
        $user = User::findOrFail($request->user_id);
        $application = Application::findOrFail($request->application_id);

        // Verify application belongs to organization
        if ($application->organization_id !== $organization->id) {
            return response()->json([
                'error' => 'validation_failed',
                'error_description' => 'Application does not belong to this organization.',
            ], 422);
        }

        // Check if access already exists
        if ($user->applications()->where('application_id', $application->id)->exists()) {
            return response()->json([
                'error' => 'resource_conflict',
                'error_description' => 'User already has access to this application.',
            ], 409);
        }

        $user->applications()->attach($application->id, [
            'granted_at' => now(),
            'login_count' => 0,
        ]);

        // Log access granted
        $this->oAuthService->logAuthenticationEvent(
            $user,
            'organization_access_granted',
            $request,
            null,
            true,
            [
                'organization_id' => $organization->id,
                'organization_name' => $organization->name,
                'application_id' => $application->id,
                'application_name' => $application->name,
                'granted_by' => auth()->id(),
            ]
        );

        return response()->json([
            'message' => 'User access granted successfully',
        ], 201);
    }

    /**
     * Revoke user access from organization application
     */
    public function revokeUserAccess(string $id, string $userId, string $applicationId): JsonResponse
    {
        $this->authorize('organizations.manage_users');

        $organization = Organization::findOrFail($id);
        $user = User::findOrFail($userId);
        $application = Application::findOrFail($applicationId);

        // Verify application belongs to organization
        if ($application->organization_id !== $organization->id) {
            return response()->json([
                'error' => 'validation_failed',
                'error_description' => 'Application does not belong to this organization.',
            ], 422);
        }

        if (!$user->applications()->where('application_id', $application->id)->exists()) {
            return response()->json([
                'error' => 'resource_not_found',
                'error_description' => 'User does not have access to this application.',
            ], 404);
        }

        $user->applications()->detach($application->id);

        // Revoke user's tokens for this application
        $user->tokens()->whereHas('client', function ($query) use ($application) {
            $query->where('id', $application->client_id);
        })->delete();

        // Log access revoked
        $this->oAuthService->logAuthenticationEvent(
            $user,
            'organization_access_revoked',
            request(),
            null,
            true,
            [
                'organization_id' => $organization->id,
                'organization_name' => $organization->name,
                'application_id' => $application->id,
                'application_name' => $application->name,
                'revoked_by' => auth()->id(),
            ]
        );

        return response()->json([], 204);
    }

    /**
     * Get organization analytics
     */
    public function analytics(Request $request, string $id): JsonResponse
    {
        $this->authorize('organizations.read');

        $validator = Validator::make($request->all(), [
            'period' => 'sometimes|string|in:24h,7d,30d,90d',
            'timezone' => 'sometimes|string|timezone',
        ]);

        if ($validator->fails()) {
            return response()->json([
                'error' => 'validation_failed',
                'error_description' => 'The given data was invalid.',
                'details' => $validator->errors(),
            ], 422);
        }

        $organization = Organization::findOrFail($id);
        $period = $request->input('period', '30d');
        $timezone = $request->input('timezone', 'UTC');

        // Calculate date range
        $endDate = now($timezone);
        $startDate = match ($period) {
            '24h' => $endDate->copy()->subHours(24),
            '7d' => $endDate->copy()->subDays(7),
            '30d' => $endDate->copy()->subDays(30),
            '90d' => $endDate->copy()->subDays(90),
            default => $endDate->copy()->subDays(30),
        };

        // Get organization applications for filtering logs
        $applicationIds = $organization->applications()->pluck('id');

        // Authentication logs analytics
        $authLogs = AuthenticationLog::whereHas('user.applications', function ($query) use ($applicationIds) {
            $query->whereIn('application_id', $applicationIds);
        })->whereBetween('created_at', [$startDate, $endDate]);

        $totalLogins = $authLogs->clone()->where('event', 'login_success')->count();
        $failedLogins = $authLogs->clone()->where('event', 'login_failed')->count();
        $uniqueUsers = $authLogs->clone()->where('event', 'login_success')->distinct('user_id')->count('user_id');

        // Daily login activity
        $dailyLogins = $authLogs->clone()
            ->where('event', 'login_success')
            ->select(
                DB::raw("DATE_TRUNC('day', created_at AT TIME ZONE '{$timezone}') as date"),
                DB::raw('COUNT(*) as count')
            )
            ->groupBy('date')
            ->orderBy('date')
            ->get()
            ->map(function ($item) {
                return [
                    'date' => Carbon::parse($item->date)->format('Y-m-d'),
                    'count' => $item->count,
                ];
            });

        // Application usage
        $applicationUsage = $organization->applications()
            ->with(['users' => function ($query) use ($startDate, $endDate) {
                $query->withPivot(['last_login_at', 'login_count'])
                      ->wherePivot('last_login_at', '>=', $startDate);
            }])
            ->get()
            ->map(function ($app) {
                return [
                    'id' => $app->id,
                    'name' => $app->name,
                    'total_users' => $app->users->count(),
                    'active_users' => $app->users->count(),
                    'total_logins' => $app->users->sum('pivot.login_count'),
                ];
            });

        // Top users by login activity
        $topUsers = User::whereHas('applications', function ($query) use ($applicationIds, $startDate) {
            $query->whereIn('application_id', $applicationIds)
                  ->wherePivot('last_login_at', '>=', $startDate);
        })->with(['applications' => function ($query) use ($applicationIds) {
            $query->whereIn('application_id', $applicationIds)
                  ->withPivot(['last_login_at', 'login_count']);
        }])
        ->get()
        ->map(function ($user) {
            $totalLogins = $user->applications->sum('pivot.login_count');
            $lastLogin = $user->applications->max('pivot.last_login_at');
            
            return [
                'id' => $user->id,
                'name' => $user->name,
                'email' => $user->email,
                'total_logins' => $totalLogins,
                'last_login_at' => $lastLogin,
            ];
        })
        ->sortByDesc('total_logins')
        ->take(10)
        ->values();

        // Security metrics
        $securityMetrics = [
            'mfa_enabled_users' => User::whereHas('applications', function ($query) use ($applicationIds) {
                $query->whereIn('application_id', $applicationIds);
            })->whereNotNull('mfa_methods')->count(),
            'failed_login_attempts' => $failedLogins,
            'suspicious_activity' => $authLogs->clone()
                ->whereIn('event', ['login_failed', 'token_revoked', 'logout'])
                ->where('success', false)
                ->count(),
        ];

        return response()->json([
            'data' => [
                'period' => $period,
                'date_range' => [
                    'start' => $startDate->toISOString(),
                    'end' => $endDate->toISOString(),
                ],
                'summary' => [
                    'total_applications' => $organization->applications()->count(),
                    'total_users' => $uniqueUsers,
                    'total_logins' => $totalLogins,
                    'failed_logins' => $failedLogins,
                    'success_rate' => $totalLogins + $failedLogins > 0 
                        ? round(($totalLogins / ($totalLogins + $failedLogins)) * 100, 2) 
                        : 0,
                ],
                'daily_activity' => $dailyLogins,
                'application_usage' => $applicationUsage,
                'top_users' => $topUsers,
                'security_metrics' => $securityMetrics,
            ],
        ]);
    }

    /**
     * Format organization response
     */
    private function formatOrganizationResponse(Organization $organization, bool $detailed = false): array
    {
        // Manually calculate users count since users() is not a proper relationship
        $usersCount = User::whereHas('applications', function ($query) use ($organization) {
            $query->where('organization_id', $organization->id);
        })->count();
        
        $data = [
            'id' => $organization->id,
            'name' => $organization->name,
            'slug' => $organization->slug,
            'description' => null, // Field doesn't exist in DB yet
            'website' => null, // Field doesn't exist in DB yet  
            'logo' => $organization->logo,
            'is_active' => $organization->is_active,
            'settings' => $organization->settings ?? [],
            'applications_count' => $organization->applications_count ?? 0,
            'users_count' => $usersCount,
            'created_at' => $organization->created_at,
            'updated_at' => $organization->updated_at,
        ];

        if ($detailed) {
            // Additional detailed fields can be added here
            
            if ($organization->relationLoaded('applications')) {
                $data['applications'] = $organization->applications->map(function ($app) {
                    return [
                        'id' => $app->id,
                        'name' => $app->name,
                        'client_id' => $app->client_id,
                        'is_active' => $app->is_active,
                    ];
                });
            }
        }

        return $data;
    }

    /**
     * Format user response for organization context
     */
    private function formatUserResponse(User $user, Organization $organization): array
    {
        $orgApplications = $user->applications->where('organization_id', $organization->id);
        
        return [
            'id' => $user->id,
            'name' => $user->name,
            'email' => $user->email,
            'mfa_enabled' => $user->hasMfaEnabled(),
            'roles' => $user->roles->map(function ($role) {
                return [
                    'id' => $role->id,
                    'name' => $role->name,
                    'display_name' => $role->display_name ?? ucfirst($role->name),
                ];
            }),
            'organization_access' => $orgApplications->map(function ($app) {
                return [
                    'application_id' => $app->id,
                    'application_name' => $app->name,
                    'granted_at' => $app->pivot->granted_at ?? null,
                    'last_login_at' => $app->pivot->last_login_at ?? null,
                    'login_count' => $app->pivot->login_count ?? 0,
                ];
            }),
            'created_at' => $user->created_at,
        ];
    }
}