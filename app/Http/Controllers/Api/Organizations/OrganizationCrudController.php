<?php

namespace App\Http\Controllers\Api\Organizations;

use App\Http\Controllers\Api\BaseApiController;
use App\Http\Controllers\Api\Traits\CacheableResponse;
use App\Http\Requests\Organization\StoreOrganizationRequest;
use App\Http\Requests\Organization\UpdateOrganizationRequest;
use App\Http\Requests\Organization\UpdateOrganizationSettingsRequest;
use App\Http\Resources\OrganizationResource;
use App\Models\Organization;
use App\Services\OrganizationAnalyticsService;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Validator;
use Illuminate\Support\Str;

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
            return $this->errorValidation($validator->errors());
        }

        $organizations = $this->organizationService->getFilteredOrganizations(
            $request->get('search'),
            $request->get('filter', []),
            $request->get('sort', 'created_at'),
            $request->get('order', 'desc'),
            (int) $request->get('per_page', 15)
        );

        return $this->successResourceCollection(
            OrganizationResource::collection($organizations),
            'Organizations retrieved successfully'
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
            return $this->errorValidation($validator->errors());
        }

        $data = $request->validated();

        if (! isset($data['slug']) || empty($data['slug'])) {
            $data['slug'] = Str::slug($data['name']);
        }

        if (Organization::where('slug', $data['slug'])->whereNull('deleted_at')->exists()) {
            return $this->errorValidation(['slug' => ['The slug has already been taken.']]);
        }

        $organization = Organization::create([
            'name' => $data['name'],
            'slug' => $data['slug'],
            'description' => $data['description'] ?? null,
            'website' => $data['website'] ?? null,
            'settings' => $data['settings'] ?? [
                'allow_registration' => true,
                'require_email_verification' => true,
                'session_lifetime' => 1440,
                'password_policy' => [
                    'min_length' => 8,
                    'require_uppercase' => true,
                    'require_lowercase' => true,
                    'require_numbers' => true,
                    'require_symbols' => false,
                ],
            ],
            'is_active' => $data['is_active'] ?? true,
        ]);

        return $this->successResource(
            new OrganizationResource($organization),
            'Organization created successfully',
            201
        );
    }

    /**
     * Display the specified organization
     */
    public function show(string $id): JsonResponse
    {
        $this->authorize('organizations.read');

        $organization = Organization::findOrFail($id);

        return $this->successResource(
            new OrganizationResource($organization),
            'Organization retrieved successfully'
        );
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
            return $this->errorValidation($validator->errors());
        }

        $organization->update($request->only([
            'name', 'slug', 'description', 'website', 'is_active',
        ]));

        return $this->successResource(
            new OrganizationResource($organization),
            'Organization updated successfully'
        );
    }

    /**
     * Remove the specified organization
     */
    public function destroy(string $id): JsonResponse
    {
        $this->authorize('organizations.delete');

        $organization = Organization::findOrFail($id);

        if ($organization->users()->count() > 0) {
            return $this->errorBadRequest(
                'Cannot delete organization with existing users. Transfer or remove users first.'
            );
        }

        if ($organization->applications()->count() > 0) {
            return $this->errorBadRequest(
                'Cannot delete organization with existing applications. Remove applications first.'
            );
        }

        $organization->delete();

        return $this->successMessage('Organization deleted successfully');
    }

    /**
     * Get organization settings
     */
    public function settings(string $id): JsonResponse
    {
        $this->authorize('organizations.read');

        $organization = Organization::findOrFail($id);

        return $this->success([
            'settings' => $organization->settings,
            'name' => $organization->name,
            'slug' => $organization->slug,
        ], 'Organization settings retrieved successfully');
    }

    /**
     * Update organization settings
     */
    public function updateSettings(UpdateOrganizationSettingsRequest $request, string $id): JsonResponse
    {
        $this->authorize('organizations.update');

        $organization = Organization::findOrFail($id);

        $validator = Validator::make($request->all(), [
            'settings' => ['required', 'array'],
            'settings.allow_registration' => ['sometimes', 'boolean'],
            'settings.require_email_verification' => ['sometimes', 'boolean'],
            'settings.session_lifetime' => ['sometimes', 'integer', 'min:15', 'max:10080'],
            'settings.password_policy' => ['sometimes', 'array'],
            'settings.password_policy.min_length' => ['sometimes', 'integer', 'min:6', 'max:128'],
            'settings.password_policy.require_uppercase' => ['sometimes', 'boolean'],
            'settings.password_policy.require_lowercase' => ['sometimes', 'boolean'],
            'settings.password_policy.require_numbers' => ['sometimes', 'boolean'],
            'settings.password_policy.require_symbols' => ['sometimes', 'boolean'],
        ]);

        if ($validator->fails()) {
            return $this->errorValidation($validator->errors());
        }

        $currentSettings = $organization->settings ?? [];
        $newSettings = array_merge($currentSettings, $request->input('settings'));

        $organization->update(['settings' => $newSettings]);

        // Invalidate organization cache after settings update
        $this->invalidateOrganizationCache($organization->id);

        return $this->success([
            'settings' => $organization->settings,
        ], 'Organization settings updated successfully');
    }
}
