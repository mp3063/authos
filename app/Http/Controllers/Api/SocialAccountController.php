<?php

namespace App\Http\Controllers\Api;

use App\Models\SocialAccount;
use Illuminate\Http\JsonResponse;
use Illuminate\Routing\Controller as BaseController;
use Illuminate\Support\Facades\Auth;

class SocialAccountController extends BaseController
{
    public function __construct()
    {
        $this->middleware('auth:api');
    }

    /**
     * Get user's social accounts
     */
    public function socialAccounts(): JsonResponse
    {
        $user = Auth::user();

        // Get all connected social accounts for the user
        $socialAccounts = $user->socialAccounts()
            ->get()
            ->map(function ($account) {
                return [
                    'id' => $account->id,
                    'provider' => $account->provider,
                    'provider_display_name' => $account->getProviderDisplayName(),
                    'provider_id' => $account->provider_id,
                    'email' => $account->email,
                    'name' => $account->name,
                    'avatar' => $account->avatar,
                    'connected_at' => $account->created_at,
                    'token_expired' => $account->isTokenExpired(),
                ];
            });

        // Include legacy social account if exists (for backward compatibility)
        if ($user->provider && $user->provider_id) {
            $legacyExists = $socialAccounts->firstWhere('provider', $user->provider);
            if (! $legacyExists) {
                $socialAccounts->push([
                    'id' => null,
                    'provider' => $user->provider,
                    'provider_display_name' => $user->getProviderDisplayName(),
                    'provider_id' => $user->provider_id,
                    'email' => $user->email,
                    'name' => $user->name,
                    'avatar' => $user->avatar,
                    'connected_at' => $user->created_at,
                    'token_expired' => false,
                    'legacy' => true,
                ]);
            }
        }

        // Build available providers list
        $availableProviders = collect(['google', 'github', 'facebook', 'twitter', 'linkedin'])
            ->mapWithKeys(function ($provider) use ($socialAccounts) {
                $connected = $socialAccounts->firstWhere('provider', $provider);

                return [$provider => [
                    'name' => ucfirst($provider),
                    'connected' => (bool) $connected,
                    'account' => $connected ?: null,
                ]];
            });

        return response()->json([
            'success' => true,
            'data' => [
                'linked_providers' => $socialAccounts->values(),
                'available_providers' => $availableProviders,
            ],
        ]);
    }

    /**
     * Unlink a social account by provider
     */
    public function unlinkSocialAccount(string $provider): JsonResponse
    {
        $user = Auth::user();

        // Check if user has a password before unlinking social account
        if (! $user->hasPassword()) {
            return response()->json([
                'success' => false,
                'message' => 'Cannot unlink social account without setting a password first',
            ], 400);
        }

        // Find the social account
        $socialAccount = SocialAccount::where('user_id', $user->id)
            ->where('provider', $provider)
            ->first();

        if (! $socialAccount) {
            return response()->json([
                'success' => false,
                'message' => 'Social account not found',
            ], 404);
        }

        // Delete the social account
        $socialAccount->delete();

        // If this was the user's main provider, clear it
        if ($user->provider === $provider) {
            $user->update([
                'provider' => null,
                'provider_id' => null,
                'provider_token' => null,
                'provider_refresh_token' => null,
                'provider_data' => null,
            ]);
        }

        return response()->json([
            'success' => true,
            'message' => 'Social account unlinked successfully',
        ]);
    }
}
