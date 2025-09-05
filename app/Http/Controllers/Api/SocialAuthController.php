<?php

namespace App\Http\Controllers\Api;

use App\Http\Controllers\Controller;
use App\Services\SocialAuthService;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Facades\Validator;

class SocialAuthController extends Controller
{
    public function __construct(
        private SocialAuthService $socialAuthService
    ) {}

    /**
     * Get available social providers
     */
    public function providers(): JsonResponse
    {
        try {
            $providers = $this->socialAuthService->getAvailableProviders();
            
            // Filter only enabled providers
            $enabledProviders = array_filter($providers, fn($provider) => $provider['enabled']);
            
            return response()->json([
                'success' => true,
                'data' => [
                    'providers' => $enabledProviders,
                    'count' => count($enabledProviders)
                ]
            ]);
        } catch (\Exception $e) {
            Log::error('Failed to get social providers', [
                'error' => $e->getMessage(),
                'trace' => $e->getTraceAsString()
            ]);
            
            return response()->json([
                'success' => false,
                'message' => 'Failed to get social providers',
                'error' => $e->getMessage()
            ], 500);
        }
    }

    /**
     * Redirect to social provider
     */
    public function redirect(Request $request, string $provider): JsonResponse
    {
        try {
            // Validate provider
            if (!$this->socialAuthService->isProviderSupported($provider)) {
                return response()->json([
                    'success' => false,
                    'message' => 'Unsupported social provider'
                ], 400);
            }

            if (!$this->socialAuthService->isProviderEnabled($provider)) {
                return response()->json([
                    'success' => false,
                    'message' => 'Social provider is not configured'
                ], 400);
            }

            // Get redirect URL
            $redirectUrl = $this->socialAuthService->getRedirectUrl($provider);
            
            return response()->json([
                'success' => true,
                'data' => [
                    'redirect_url' => $redirectUrl,
                    'provider' => $provider
                ]
            ]);
        } catch (\Exception $e) {
            Log::error('Social auth redirect failed', [
                'provider' => $provider,
                'error' => $e->getMessage(),
                'trace' => $e->getTraceAsString()
            ]);
            
            return response()->json([
                'success' => false,
                'message' => 'Failed to generate redirect URL',
                'error' => $e->getMessage()
            ], 500);
        }
    }

    /**
     * Handle OAuth callback
     */
    public function callback(Request $request, string $provider): JsonResponse
    {
        try {
            // Validate provider
            if (!$this->socialAuthService->isProviderSupported($provider)) {
                return response()->json([
                    'success' => false,
                    'message' => 'Unsupported social provider'
                ], 400);
            }

            if (!$this->socialAuthService->isProviderEnabled($provider)) {
                return response()->json([
                    'success' => false,
                    'message' => 'Social provider is not configured'
                ], 400);
            }

            // Get organization slug from query parameter (optional)
            $organizationSlug = $request->query('organization');
            
            // Handle the callback
            $result = $this->socialAuthService->handleCallback($provider, $organizationSlug);
            
            return response()->json([
                'success' => true,
                'message' => 'Authentication successful',
                'data' => [
                    'access_token' => $result['access_token'],
                    'refresh_token' => $result['refresh_token'],
                    'expires_in' => $result['expires_in'],
                    'token_type' => $result['token_type'],
                    'user' => [
                        'id' => $result['user']->id,
                        'name' => $result['user']->name,
                        'email' => $result['user']->email,
                        'avatar' => $result['user']->avatar,
                        'provider' => $result['user']->provider,
                        'provider_display_name' => $result['user']->getProviderDisplayName(),
                        'organization' => $result['user']->organization ? [
                            'id' => $result['user']->organization->id,
                            'name' => $result['user']->organization->name,
                            'slug' => $result['user']->organization->slug,
                        ] : null,
                        'roles' => $result['user']->getRoleNames(),
                        'permissions' => $result['user']->getAllPermissions()->pluck('name'),
                        'is_social_user' => $result['user']->isSocialUser(),
                        'has_password' => $result['user']->hasPassword(),
                        'mfa_enabled' => $result['user']->hasMfaEnabled(),
                        'is_active' => $result['user']->is_active,
                        'created_at' => $result['user']->created_at,
                        'updated_at' => $result['user']->updated_at,
                    ]
                ]
            ]);
        } catch (\Exception $e) {
            Log::error('Social auth callback failed', [
                'provider' => $provider,
                'organization_slug' => $request->query('organization'),
                'error' => $e->getMessage(),
                'trace' => $e->getTraceAsString()
            ]);
            
            return response()->json([
                'success' => false,
                'message' => 'Authentication failed',
                'error' => $e->getMessage()
            ], 400);
        }
    }

    /**
     * Handle social login from web (for admin panel)
     */
    public function webLogin(Request $request, string $provider)
    {
        try {
            // Validate provider
            if (!$this->socialAuthService->isProviderSupported($provider)) {
                return redirect('/admin/login?error=unsupported_provider');
            }

            if (!$this->socialAuthService->isProviderEnabled($provider)) {
                return redirect('/admin/login?error=provider_not_configured');
            }

            // Get redirect URL and redirect user
            $redirectUrl = $this->socialAuthService->getRedirectUrl($provider);
            
            return redirect($redirectUrl);
        } catch (\Exception $e) {
            Log::error('Social web login redirect failed', [
                'provider' => $provider,
                'error' => $e->getMessage()
            ]);
            
            return redirect('/admin/login?error=social_login_failed');
        }
    }

    /**
     * Handle OAuth callback for web login
     */
    public function webCallback(Request $request, string $provider)
    {
        try {
            // Validate provider
            if (!$this->socialAuthService->isProviderSupported($provider)) {
                return redirect('/admin/login?error=unsupported_provider');
            }

            if (!$this->socialAuthService->isProviderEnabled($provider)) {
                return redirect('/admin/login?error=provider_not_configured');
            }

            // Handle the callback (no organization for admin panel)
            $result = $this->socialAuthService->handleCallback($provider);
            
            // Check if user has admin access
            if (!$result['user']->hasRole(['Super Admin', 'Organization Admin', 'Application Admin'])) {
                return redirect('/admin/login?error=insufficient_privileges');
            }

            // Log the user in
            auth()->login($result['user']);
            
            return redirect('/admin');
        } catch (\Exception $e) {
            Log::error('Social web callback failed', [
                'provider' => $provider,
                'error' => $e->getMessage()
            ]);
            
            return redirect('/admin/login?error=authentication_failed');
        }
    }

    /**
     * Unlink social account
     */
    public function unlink(Request $request): JsonResponse
    {
        try {
            $user = $request->user();
            
            // Check if user has a password before unlinking social account
            if (!$user->hasPassword()) {
                return response()->json([
                    'success' => false,
                    'message' => 'Cannot unlink social account without setting a password first'
                ], 400);
            }
            
            // Clear social provider data
            $user->update([
                'provider' => null,
                'provider_id' => null,
                'provider_token' => null,
                'provider_refresh_token' => null,
                'provider_data' => null,
            ]);
            
            return response()->json([
                'success' => true,
                'message' => 'Social account unlinked successfully'
            ]);
        } catch (\Exception $e) {
            Log::error('Failed to unlink social account', [
                'user_id' => $request->user()->id,
                'error' => $e->getMessage()
            ]);
            
            return response()->json([
                'success' => false,
                'message' => 'Failed to unlink social account',
                'error' => $e->getMessage()
            ], 500);
        }
    }
}