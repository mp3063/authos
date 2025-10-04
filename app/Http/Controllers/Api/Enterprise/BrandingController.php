<?php

namespace App\Http\Controllers\Api\Enterprise;

use App\Http\Controllers\Api\BaseApiController;
use App\Models\Organization;
use App\Services\BrandingService;
use Exception;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;

class BrandingController extends BaseApiController
{
    public function __construct(
        private readonly BrandingService $brandingService
    ) {
        $this->middleware('auth:api');
    }

    public function show(int $organizationId): JsonResponse
    {
        try {
            if (! $this->validateOrganizationAccess($organizationId)) {
                return $this->forbiddenResponse();
            }

            $organization = Organization::findOrFail($organizationId);
            $branding = $this->brandingService->getBranding($organization);

            // If no branding exists, return default structure
            if (! $branding) {
                $brandingData = [
                    'logo_url' => null,
                    'background_url' => null,
                    'primary_color' => '#3b82f6',
                    'secondary_color' => '#10b981',
                    'accent_color' => null,
                    'custom_css' => null,
                    'custom_html' => null,
                ];
            } else {
                $brandingData = array_merge($branding->toArray(), [
                    'accent_color' => null, // Not in DB yet
                    'custom_html' => null, // Not in DB yet
                ]);
            }

            return $this->successResponse($brandingData, 'Branding retrieved successfully');
        } catch (Exception $e) {
            return $this->errorResponse($e->getMessage(), 500);
        }
    }

    public function update(Request $request, int $organizationId): JsonResponse
    {
        $validator = validator($request->all(), [
            'primary_color' => ['nullable', 'string', 'regex:/^#[0-9A-Fa-f]{6}$/'],
            'secondary_color' => ['nullable', 'string', 'regex:/^#[0-9A-Fa-f]{6}$/'],
            'accent_color' => ['nullable', 'string', 'regex:/^#[0-9A-Fa-f]{6}$/'],
            'custom_css' => ['nullable', 'string', 'max:50000'],
            'custom_html' => ['nullable', 'string', 'max:50000'],
            'settings' => ['nullable', 'array'],
        ]);

        if ($validator->fails()) {
            return $this->validationErrorResponse($validator->errors());
        }

        try {
            if (! $this->validateOrganizationAccess($organizationId)) {
                return $this->forbiddenResponse();
            }

            // Check if user has permission to manage branding
            if (! auth()->user()->tokenCan('enterprise.branding.manage')) {
                return $this->forbiddenResponse('You do not have permission to manage branding');
            }

            $organization = Organization::findOrFail($organizationId);

            // Check if branding feature is enabled
            if (! ($organization->settings['enterprise_features']['custom_branding_enabled'] ?? true)) {
                return response()->json([
                    'success' => false,
                    'error' => 'feature_disabled',
                    'message' => 'Custom branding is disabled for this organization',
                ], 403);
            }

            $branding = $this->brandingService->updateBranding($organization, $request->all());

            $brandingData = array_merge($branding->toArray(), [
                'accent_color' => $request->input('accent_color'),
                'custom_html' => $request->input('custom_html'),
            ]);

            return $this->successResponse(['branding' => $brandingData], 'Branding updated successfully');
        } catch (Exception $e) {
            return $this->errorResponse($e->getMessage(), 500);
        }
    }

    public function uploadLogo(Request $request, int $organizationId): JsonResponse
    {
        $validator = validator($request->all(), [
            'logo' => ['required', 'image', 'max:2048', 'mimes:png,jpg,jpeg,svg', 'dimensions:min_width=200,min_height=200'],
        ]);

        if ($validator->fails()) {
            return $this->validationErrorResponse($validator->errors());
        }

        try {
            if (! $this->validateOrganizationAccess($organizationId)) {
                return $this->forbiddenResponse();
            }

            // Check if user has permission to manage branding
            if (! auth()->user()->tokenCan('enterprise.branding.manage')) {
                return $this->forbiddenResponse('You do not have permission to manage branding');
            }

            $organization = Organization::findOrFail($organizationId);
            $logoUrl = $this->brandingService->uploadLogo($organization, $request->file('logo'));

            return $this->successResponse(['logo_url' => $logoUrl], 'Logo uploaded successfully');
        } catch (Exception $e) {
            return $this->errorResponse($e->getMessage(), 500);
        }
    }

    public function uploadBackground(Request $request, int $organizationId): JsonResponse
    {
        $validator = validator($request->all(), [
            'background' => ['required', 'image', 'max:5120', 'mimes:png,jpg,jpeg'],
        ]);

        if ($validator->fails()) {
            return $this->validationErrorResponse($validator->errors());
        }

        try {
            if (! $this->validateOrganizationAccess($organizationId)) {
                return $this->forbiddenResponse();
            }

            // Check if user has permission to manage branding
            if (! auth()->user()->tokenCan('enterprise.branding.manage')) {
                return $this->forbiddenResponse('You do not have permission to manage branding');
            }

            $organization = Organization::findOrFail($organizationId);
            $backgroundUrl = $this->brandingService->uploadBackground($organization, $request->file('background'));

            return $this->successResponse(['background_url' => $backgroundUrl], 'Background uploaded successfully');
        } catch (Exception $e) {
            return $this->errorResponse($e->getMessage(), 500);
        }
    }
}
