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

            return $this->successResponse($branding, 'Branding retrieved successfully');
        } catch (Exception $e) {
            return $this->errorResponse($e->getMessage(), 500);
        }
    }

    public function update(Request $request, int $organizationId): JsonResponse
    {
        $request->validate([
            'primary_color' => ['nullable', 'string', 'regex:/^#[0-9A-Fa-f]{6}$/'],
            'secondary_color' => ['nullable', 'string', 'regex:/^#[0-9A-Fa-f]{6}$/'],
            'custom_css' => ['nullable', 'string', 'max:50000'],
            'settings' => ['nullable', 'array'],
        ]);

        try {
            if (! $this->validateOrganizationAccess($organizationId)) {
                return $this->forbiddenResponse();
            }

            $organization = Organization::findOrFail($organizationId);
            $branding = $this->brandingService->updateBranding($organization, $request->all());

            return $this->successResponse($branding, 'Branding updated successfully');
        } catch (Exception $e) {
            return $this->errorResponse($e->getMessage(), 500);
        }
    }

    public function uploadLogo(Request $request, int $organizationId): JsonResponse
    {
        $request->validate([
            'logo' => ['required', 'image', 'max:2048', 'mimes:png,jpg,jpeg,svg'],
        ]);

        try {
            if (! $this->validateOrganizationAccess($organizationId)) {
                return $this->forbiddenResponse();
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
        $request->validate([
            'background' => ['required', 'image', 'max:5120', 'mimes:png,jpg,jpeg'],
        ]);

        try {
            if (! $this->validateOrganizationAccess($organizationId)) {
                return $this->forbiddenResponse();
            }

            $organization = Organization::findOrFail($organizationId);
            $backgroundUrl = $this->brandingService->uploadBackground($organization, $request->file('background'));

            return $this->successResponse(['background_url' => $backgroundUrl], 'Background uploaded successfully');
        } catch (Exception $e) {
            return $this->errorResponse($e->getMessage(), 500);
        }
    }
}
