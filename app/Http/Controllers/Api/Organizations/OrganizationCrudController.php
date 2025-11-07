<?php

namespace App\Http\Controllers\Api\Organizations;

use App\Http\Controllers\Api\BaseApiController;
use App\Http\Controllers\Api\Traits\CacheableResponse;
use App\Http\Requests\Organization\StoreOrganizationRequest;
use App\Http\Requests\Organization\UpdateOrganizationRequest;
use App\Http\Requests\Organization\UpdateOrganizationSettingsRequest;
use App\Http\Resources\OrganizationResource;
use App\Models\Application;
use App\Models\Organization;
use App\Models\User;
use App\Services\OrganizationAnalyticsService;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Validator;
use Illuminate\Support\Str;
use Illuminate\Validation\Rule;

class OrganizationCrudController extends BaseApiController
{
    use CacheableResponse;

    protected OrganizationAnalyticsService $organizationService;

    public function __construct(OrganizationAnalyticsService $organizationService)
    {
        $this->organizationService = $organizationService;
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
            'filter' => 'sometimes|array',
            'filter.is_active' => 'sometimes|in:true,false,1,0',
        ]);

        if ($validator->fails()) {
            return $this->validationErrorResponse($validator->errors());
        }

        $organizations = $this->organizationService->getFilteredOrganizations(
            $request->get('search'),
            $request->get('filter', []),
            $request->get('sort', 'created_at'),
            $request->get('order', 'desc'),
            (int) $request->get('per_page', 15)
        );

        return $this->paginatedResponse(
            $organizations,
            'Organizations retrieved successfully',
            OrganizationResource::class
        );
    }

    /**
     * Store a newly created organization
     */
    public function store(StoreOrganizationRequest $request): JsonResponse
    {
        $this->authorize('organizations.create');

        $validator = Validator::make($request->all(), [
            'name' => ['required', 'string', 'max:255'],
            'slug' => [
                'sometimes',
                'string',
                'max:255',
                'alpha_dash',
                Rule::unique('organizations', 'slug')->whereNull('deleted_at'),
            ],
            'description' => ['sometimes', 'string', 'max:1000'],
            'website' => ['sometimes', 'url', 'max:255'],
            'settings' => ['sometimes', 'array'],
            'settings.allow_registration' => ['sometimes', 'boolean'],
            'settings.require_email_verification' => ['sometimes', 'boolean'],
            'settings.session_lifetime' => ['sometimes', 'integer', 'min:15', 'max:10080'],
            'settings.password_policy' => ['sometimes', 'array'],
            'settings.password_policy.min_length' => ['sometimes', 'integer', 'min:6', 'max:128'],
            'settings.password_policy.require_uppercase' => ['sometimes', 'boolean'],
            'settings.password_policy.require_lowercase' => ['sometimes', 'boolean'],
            'settings.password_policy.require_numbers' => ['sometimes', 'boolean'],
            'settings.password_policy.require_symbols' => ['sometimes', 'boolean'],
            'is_active' => ['sometimes', 'boolean'],
        ]);

        if ($validator->fails()) {
            return $this->validationErrorResponse($validator->errors());
        }

        $data = $request->validated();

        if (empty($data['slug'])) {
            $data['slug'] = Str::slug($data['name']);
        }

        if (Organization::where('slug', $data['slug'])->whereNull('deleted_at')->exists()) {
            return $this->validationErrorResponse(['slug' => ['The slug has already been taken.']]);
        }

        $defaultSettings = [
            'allow_registration' => true,
            'require_email_verification' => true,
            'session_timeout' => 60, // 60 minutes default
            'password_policy' => [
                'min_length' => 8,
                'require_uppercase' => true,
                'require_lowercase' => true,
                'require_numbers' => true,
                'require_symbols' => false,
            ],
        ];

        $organization = Organization::create([
            'name' => $data['name'],
            'slug' => $data['slug'],
            'description' => $data['description'] ?? null,
            'website' => $data['website'] ?? null,
            'settings' => $data['settings'] ?? $defaultSettings,
            'is_active' => $data['is_active'] ?? true,
        ]);

        // Return flat response structure for test compatibility
        $resource = new OrganizationResource($organization);
        $responseData = array_merge(
            $resource->resolve(),
            ['message' => 'Organization created successfully']
        );

        return response()->json($responseData, 201);
    }

    /**
     * Display the specified organization
     */
    public function show(string $id): JsonResponse
    {
        $this->authorize('organizations.read');

        $organization = Organization::findOrFail($id);

        // Set manual counts for resource compatibility (using separate queries)
        $organization->setAttribute('users_count', User::where('organization_id', $organization->id)->count());
        $organization->setAttribute('applications_count', Application::where('organization_id', $organization->id)->count());

        // Return flat response structure for test compatibility
        $resource = new OrganizationResource($organization);
        $responseData = array_merge(
            $resource->resolve(),
            ['message' => 'Organization retrieved successfully']
        );

        return response()->json($responseData);
    }

    /**
     * Update the specified organization
     */
    public function update(UpdateOrganizationRequest $request, string $id): JsonResponse
    {
        $this->authorize('organizations.update');

        $organization = Organization::findOrFail($id);

        $validator = Validator::make($request->all(), [
            'name' => ['sometimes', 'string', 'max:255'],
            'slug' => [
                'sometimes',
                'string',
                'max:255',
                'alpha_dash',
                Rule::unique('organizations', 'slug')->whereNull('deleted_at')->ignore($organization->id),
            ],
            'description' => ['sometimes', 'string', 'max:1000'],
            'website' => ['sometimes', 'url', 'max:255'],
            'is_active' => ['sometimes', 'boolean'],
        ]);

        if ($validator->fails()) {
            return $this->validationErrorResponse($validator->errors());
        }

        $organization->update($request->only([
            'name', 'slug', 'description', 'website', 'is_active',
        ]));

        // Return flat response structure for test compatibility
        $resource = new OrganizationResource($organization);
        $responseData = array_merge(
            $resource->resolve(),
            ['message' => 'Organization updated successfully']
        );

        return response()->json($responseData);
    }

    /**
     * Remove the specified organization
     */
    public function destroy(string $id): JsonResponse
    {
        $this->authorize('organizations.delete');

        $organization = Organization::findOrFail($id);

        if ($organization->users()->count() > 0) {
            return $this->errorResponse(
                'Cannot delete organization with existing users. Transfer or remove users first.'
            );
        }

        if ($organization->applications()->count() > 0) {
            return $this->errorResponse(
                'Cannot delete organization with existing applications. Remove applications first.'
            );
        }

        $organization->delete();

        return $this->noContentResponse();
    }

    /**
     * Get organization settings
     */
    public function settings(string $id): JsonResponse
    {
        $this->authorize('organizations.read');

        // Use organization scope to return 404 for unauthorized access
        $query = Organization::query();

        // If not super admin, scope to user's organization
        if (!auth()->user()->hasRole('Super Admin')) {
            $query->where('id', auth()->user()->organization_id);
        }

        $organization = $query->findOrFail($id);

        $settings = $organization->settings ?? [];

        // Return flat data structure for test compatibility
        return response()->json([
            'message' => 'Organization settings retrieved successfully',
            'data' => $settings
        ]);
    }

    /**
     * Update organization settings
     */
    public function updateSettings(UpdateOrganizationSettingsRequest $request, string $id): JsonResponse
    {
        // Use organization scope BEFORE authorization to return 404 for unauthorized access
        $query = Organization::query();

        // If not super admin, scope to user's organization
        if (!auth()->user()->hasRole('Super Admin')) {
            $query->where('id', auth()->user()->organization_id);
        }

        // This will throw 404 if organization not found or not in user's org
        $organization = $query->findOrFail($id);

        // Now check authorization
        $this->authorize('organizations.update');

        $currentSettings = $organization->settings ?? [];

        // Extract settings from request (tests send data wrapped in 'settings' key)
        $inputData = $request->input('settings', $request->all());

        // Deep merge all settings fields
        $newSettings = $currentSettings;

        // Top-level settings
        $topLevelFields = [
            'require_mfa', 'session_timeout', 'allowed_ip_ranges', 'password_expiry_days',
            'enforce_2fa_for_admins', 'session_absolute_timeout', 'session_idle_timeout',
            'require_reauth_for_sensitive', 'allowed_domains', 'sso_enabled',
            'mfa_grace_period', 'mfa_methods'
        ];

        foreach ($topLevelFields as $field) {
            if (isset($inputData[$field])) {
                $newSettings[$field] = $inputData[$field];
            }
        }

        // Nested settings (deep merge)
        $nestedFields = ['lockout_policy', 'password_policy', 'notifications', 'oauth'];

        foreach ($nestedFields as $field) {
            if (isset($inputData[$field])) {
                $newSettings[$field] = array_merge(
                    $currentSettings[$field] ?? [],
                    $inputData[$field]
                );
            }
        }

        $organization->update(['settings' => $newSettings]);

        // Invalidate organization cache after settings update
        $this->invalidateOrganizationCache($organization->id);

        return response()->json([
            'message' => 'Settings updated successfully',
            'data' => [
                'settings' => $newSettings
            ]
        ]);
    }

    /**
     * Reset organization settings to defaults
     */
    public function resetSettings(string $id): JsonResponse
    {
        $this->authorize('organizations.update');

        // Use organization scope to return 404 for unauthorized access
        $query = Organization::query();

        // If not super admin, scope to user's organization
        if (!auth()->user()->hasRole('Super Admin')) {
            $query->where('id', auth()->user()->organization_id);
        }

        $organization = $query->findOrFail($id);

        // Default settings
        $defaultSettings = [
            'require_mfa' => false,
            'session_timeout' => 60, // 60 minutes default
            'password_policy' => [
                'min_length' => 8,
                'require_uppercase' => true,
                'require_lowercase' => true,
                'require_numbers' => true,
                'require_symbols' => false,
            ],
        ];

        $organization->update(['settings' => $defaultSettings]);

        // Invalidate organization cache after settings reset
        $this->invalidateOrganizationCache($organization->id);

        return response()->json([
            'message' => 'Settings reset to defaults successfully',
            'data' => [
                'settings' => $defaultSettings
            ]
        ]);
    }
}
