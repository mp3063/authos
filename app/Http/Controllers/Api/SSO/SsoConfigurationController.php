<?php

namespace App\Http\Controllers\Api\SSO;

use App\Http\Controllers\Controller;
use App\Models\Organization;
use App\Models\SSOConfiguration;
use Exception;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;

class SsoConfigurationController extends Controller
{
    /**
     * Get SSO configuration for an organization
     */
    public function getSSOConfiguration(Request $request, int $organizationId): JsonResponse
    {
        try {
            // Check if user belongs to the organization or is super admin
            $user = $request->user();
            if ($user->organization_id !== $organizationId && ! $user->hasRole('Super Admin')) {
                return response()->json([
                    'message' => 'Insufficient permissions',
                ], 403);
            }

            Organization::findOrFail($organizationId);

            // Get active SSO configuration for the organization
            $ssoConfig = SSOConfiguration::whereHas('application', function ($query) use ($organizationId) {
                $query->where('organization_id', $organizationId);
            })
                ->where('is_active', true)
                ->first();

            if (! $ssoConfig) {
                return response()->json([
                    'message' => 'No active SSO configuration found for this organization',
                ], 404);
            }

            return response()->json([
                'id' => $ssoConfig->id,
                'name' => $ssoConfig->name ?? 'Default SSO Configuration',
                'provider' => $ssoConfig->provider,
                'application_id' => $ssoConfig->application_id,
                'logout_url' => $ssoConfig->logout_url,
                'callback_url' => $ssoConfig->callback_url,
                'allowed_domains' => $ssoConfig->allowed_domains,
                'session_lifetime' => $ssoConfig->session_lifetime,
                'settings' => $ssoConfig->settings,
                'configuration' => $ssoConfig->configuration,
                'is_active' => $ssoConfig->is_active,
                'created_at' => $ssoConfig->created_at,
                'updated_at' => $ssoConfig->updated_at,
            ]);

        } catch (Exception $e) {
            return response()->json([
                'message' => $e->getMessage(),
            ], 404);
        }
    }

    /**
     * Create SSO configuration
     */
    public function createSSOConfiguration(Request $request): JsonResponse
    {
        $validated = $request->validate([
            'application_id' => 'required|integer|exists:applications,id',
            'logout_url' => 'required|url',
            'callback_url' => 'required|url',
            'allowed_domains' => 'sometimes|array',
            'session_lifetime' => 'sometimes|integer|min:300',
            'settings' => 'sometimes|array',
        ]);

        try {
            $ssoConfig = SSOConfiguration::create($validated);

            return response()->json([
                'id' => $ssoConfig->id,
                'application_id' => $ssoConfig->application_id,
                'logout_url' => $ssoConfig->logout_url,
                'callback_url' => $ssoConfig->callback_url,
                'allowed_domains' => $ssoConfig->allowed_domains,
                'session_lifetime' => $ssoConfig->session_lifetime,
                'settings' => $ssoConfig->settings,
                'is_active' => $ssoConfig->is_active,
                'created_at' => $ssoConfig->created_at,
                'updated_at' => $ssoConfig->updated_at,
            ], 201);

        } catch (Exception $e) {
            return response()->json([
                'message' => $e->getMessage(),
            ], 400);
        }
    }

    /**
     * Update SSO configuration
     */
    public function updateSSOConfiguration(Request $request, int $id): JsonResponse
    {
        $validated = $request->validate([
            'logout_url' => 'sometimes|url',
            'callback_url' => 'sometimes|url',
            'allowed_domains' => 'sometimes|array',
            'session_lifetime' => 'sometimes|integer|min:300',
            'settings' => 'sometimes|array',
            'is_active' => 'sometimes|boolean',
        ]);

        try {
            $ssoConfig = SSOConfiguration::findOrFail($id);
            $ssoConfig->update($validated);

            return response()->json([
                'id' => $ssoConfig->id,
                'application_id' => $ssoConfig->application_id,
                'logout_url' => $ssoConfig->logout_url,
                'callback_url' => $ssoConfig->callback_url,
                'allowed_domains' => $ssoConfig->allowed_domains,
                'session_lifetime' => $ssoConfig->session_lifetime,
                'settings' => $ssoConfig->settings,
                'is_active' => $ssoConfig->is_active,
                'created_at' => $ssoConfig->created_at,
                'updated_at' => $ssoConfig->updated_at,
            ]);

        } catch (Exception $e) {
            return response()->json([
                'message' => $e->getMessage(),
            ], 404);
        }
    }

    /**
     * Delete SSO configuration
     */
    public function deleteSSOConfiguration(int $id): JsonResponse
    {
        try {
            $ssoConfig = SSOConfiguration::findOrFail($id);
            $ssoConfig->delete();

            return response()->json([
                'message' => 'SSO configuration deleted successfully',
            ]);

        } catch (Exception $e) {
            return response()->json([
                'message' => $e->getMessage(),
            ], 404);
        }
    }
}
