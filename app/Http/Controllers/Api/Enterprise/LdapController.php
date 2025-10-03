<?php

namespace App\Http\Controllers\Api\Enterprise;

use App\Http\Controllers\Api\BaseApiController;
use App\Http\Requests\Enterprise\LdapConfigurationRequest;
use App\Models\LdapConfiguration;
use App\Services\LdapAuthService;
use Exception;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;

class LdapController extends BaseApiController
{
    public function __construct(
        private readonly LdapAuthService $ldapService
    ) {
        $this->middleware('auth:api');
    }

    public function testConnection(LdapConfigurationRequest $request): JsonResponse
    {
        try {
            // Check if LDAP is enabled for the organization
            $user = $request->user();

            if (! $user) {
                return $this->errorResponse('Unauthorized', 401);
            }

            $ldapEnabled = $user->organization->settings['enterprise_features']['ldap_enabled'] ?? false;

            if (! $ldapEnabled) {
                return response()->json([
                    'success' => false,
                    'error' => 'feature_disabled',
                    'message' => 'LDAP feature is not enabled for this organization',
                ], 403);
            }

            $config = new LdapConfiguration($request->validated());
            $config->organization_id = $user->organization_id;

            $result = $this->ldapService->testConnection($config);

            return $this->successResponse([
                'connection_status' => $result['success'] ? 'success' : 'failed',
                'message' => $result['message'],
                'user_count' => $result['user_count'] ?? null,
            ], 'LDAP connection test completed');
        } catch (Exception $e) {
            return $this->errorResponse($e->getMessage(), 500);
        }
    }

    public function syncUsers(Request $request): JsonResponse
    {
        try {
            $user = $request->user();

            // Get the organization's LDAP configuration
            $config = LdapConfiguration::where('organization_id', $user->organization_id)
                ->where('is_active', true)
                ->firstOrFail();

            $stats = $this->ldapService->syncUsers($config, $config->organization);

            return $this->successResponse([
                'sync_results' => [
                    'created' => $stats['created'] ?? 0,
                    'updated' => $stats['updated'] ?? 0,
                    'failed' => $stats['failed'] ?? 0,
                ],
            ], 'LDAP user sync completed');
        } catch (Exception $e) {
            return $this->errorResponse($e->getMessage(), 500);
        }
    }

    public function listUsers(Request $request): JsonResponse
    {
        try {
            $user = $request->user();

            // Get the organization's LDAP configuration
            $config = LdapConfiguration::where('organization_id', $user->organization_id)
                ->where('is_active', true)
                ->firstOrFail();

            $limit = $request->input('limit', 100);
            $users = $this->ldapService->getUsersFromLdap($config, $limit);

            return $this->successResponse($users, 'LDAP users retrieved successfully');
        } catch (Exception $e) {
            return $this->errorResponse($e->getMessage(), 500);
        }
    }

    public function configure(LdapConfigurationRequest $request): JsonResponse
    {
        try {
            $user = $request->user();

            $config = LdapConfiguration::updateOrCreate(
                ['organization_id' => $user->organization_id],
                array_merge($request->validated(), [
                    'organization_id' => $user->organization_id,
                    'is_active' => true,
                ])
            );

            // Update organization settings
            $settings = $user->organization->settings ?? [];
            $settings['ldap_config'] = [
                'host' => $config->host,
                'port' => $config->port,
                'base_dn' => $config->base_dn,
                'user_filter' => $config->user_filter,
                'username_attribute' => $config->user_attribute,
            ];
            $user->organization->update(['settings' => $settings]);

            return $this->successResponse([
                'ldap_config' => $config->makeHidden(['password']),
            ], 'LDAP configuration saved successfully');
        } catch (Exception $e) {
            return $this->errorResponse($e->getMessage(), 500);
        }
    }
}
