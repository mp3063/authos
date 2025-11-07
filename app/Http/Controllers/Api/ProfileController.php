<?php

namespace App\Http\Controllers\Api;

use App\Http\Controllers\Controller;
use App\Http\Requests\Profile\ChangePasswordRequest;
use App\Http\Requests\Profile\UpdateProfileRequest;
use App\Services\AuthenticationLogService;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Storage;
use Illuminate\Support\Facades\Validator;
use PragmaRX\Google2FA\Google2FA;

class ProfileController extends Controller
{
    protected AuthenticationLogService $authLogService;

    public function __construct(AuthenticationLogService $authLogService)
    {
        $this->authLogService = $authLogService;
        $this->middleware('auth:api');
    }

    /**
     * Get current user profile
     */
    public function index(): JsonResponse
    {
        $user = Auth::user();

        return response()->json([
            'data' => [
                'id' => $user->id,
                'name' => $user->name,
                'email' => $user->email,
                'avatar' => $user->avatar,
                'email_verified_at' => $user->email_verified_at,
                'profile' => $user->profile ?? [],
                'mfa_enabled' => $user->hasMfaEnabled(),
                'mfa_methods' => $user->mfa_methods ?? [],
                'organization' => $user->organization ? [
                    'id' => $user->organization->id,
                    'name' => $user->organization->name,
                    'slug' => $user->organization->slug,
                ] : null,
                'roles' => $user->roles->map(function ($role) {
                    return [
                        'id' => $role->id,
                        'name' => $role->name,
                        'display_name' => $role->display_name ?? ucfirst($role->name),
                    ];
                }),
                'created_at' => $user->created_at,
                'updated_at' => $user->updated_at,
            ],
        ]);
    }

    /**
     * Update user profile
     */
    public function update(UpdateProfileRequest $request): JsonResponse
    {
        $user = Auth::user();

        $updateData = $request->only(['name', 'email']);

        if ($request->has('profile')) {
            $updateData['profile'] = array_merge($user->profile ?? [], $request->profile);
        }

        // If email is being changed, reset email verification
        if ($request->isEmailChanged()) {
            $updateData['email_verified_at'] = null;
        }

        $user->update($updateData);

        // Log profile update
        $this->authLogService->logAuthenticationEvent(
            $user,
            'profile_updated',
            [],
            $request
        );

        return response()->json([
            'data' => [
                'id' => $user->id,
                'name' => $user->name,
                'email' => $user->email,
                'avatar' => $user->avatar,
                'email_verified_at' => $user->email_verified_at,
                'profile' => $user->profile ?? [],
                'mfa_enabled' => $user->hasMfaEnabled(),
                'updated_at' => $user->updated_at,
            ],
            'message' => 'Profile updated successfully',
        ]);
    }

    /**
     * Upload user avatar
     */
    public function uploadAvatar(Request $request): JsonResponse
    {
        $validator = Validator::make($request->all(), [
            'avatar' => 'required|image|mimes:jpeg,png,jpg,gif|max:2048', // 2MB max
        ]);

        if ($validator->fails()) {
            return response()->json([
                'error' => 'validation_failed',
                'error_description' => 'The given data was invalid.',
                'details' => $validator->errors(),
            ], 422);
        }

        $user = Auth::user();

        // Delete old avatar if exists
        if ($user->avatar && Storage::disk('public')->exists($user->avatar)) {
            Storage::disk('public')->delete($user->avatar);
        }

        // Store new avatar
        $avatarPath = $request->file('avatar')->store('avatars', 'public');
        $user->update(['avatar' => $avatarPath]);

        // Log avatar update
        $this->authLogService->logAuthenticationEvent(
            $user,
            'avatar_updated',
            [],
            $request
        );

        return response()->json([
            'data' => [
                'avatar' => $user->avatar,
                'avatar_url' => Storage::disk('public')->url($user->avatar),
            ],
            'message' => 'Avatar uploaded successfully',
        ]);
    }

    /**
     * Remove user avatar
     */
    public function removeAvatar(Request $request): JsonResponse
    {
        $user = Auth::user();

        if ($user->avatar && Storage::disk('public')->exists($user->avatar)) {
            Storage::disk('public')->delete($user->avatar);
        }

        $user->update(['avatar' => null]);

        // Log avatar removal
        $this->authLogService->logAuthenticationEvent(
            $user,
            'avatar_removed',
            [],
            $request
        );

        return response()->json([
            'message' => 'Avatar removed successfully',
        ]);
    }

    /**
     * Get user preferences
     */
    public function preferences(): JsonResponse
    {
        $user = Auth::user();

        $defaultPreferences = [
            'timezone' => 'UTC',
            'language' => 'en',
            'theme' => 'light',
            'date_format' => 'Y-m-d',
            'time_format' => 'H:i',
            'email_notifications' => true,
            'security_alerts' => true,
            'marketing_emails' => false,
        ];

        $preferences = array_merge($defaultPreferences, $user->profile['preferences'] ?? []);

        return response()->json([
            'data' => $preferences,
        ]);
    }

    /**
     * Update user preferences
     */
    public function updatePreferences(Request $request): JsonResponse
    {
        $validator = Validator::make($request->all(), [
            'timezone' => 'sometimes|string|timezone',
            'language' => 'sometimes|string|in:en,es,fr,de,it,pt,nl,ru,ja,zh',
            'theme' => 'sometimes|string|in:light,dark,auto',
            'date_format' => 'sometimes|string|in:Y-m-d,m/d/Y,d/m/Y,d-m-Y',
            'time_format' => 'sometimes|string|in:H:i,h:i A',
            'email_notifications' => 'sometimes|boolean',
            'security_alerts' => 'sometimes|boolean',
            'marketing_emails' => 'sometimes|boolean',
        ]);

        if ($validator->fails()) {
            return response()->json([
                'error' => 'validation_failed',
                'error_description' => 'The given data was invalid.',
                'details' => $validator->errors(),
            ], 422);
        }

        $user = Auth::user();
        $profile = $user->profile ?? [];
        $preferences = array_merge($profile['preferences'] ?? [], $request->all());

        $profile['preferences'] = $preferences;
        $user->update(['profile' => $profile]);

        return response()->json([
            'data' => $preferences,
            'message' => 'Preferences updated successfully',
        ]);
    }

    /**
     * Get security settings
     */
    public function security(): JsonResponse
    {
        $user = Auth::user();

        return response()->json([
            'data' => [
                'mfa_enabled' => $user->hasMfaEnabled(),
                'mfa_methods' => $user->mfa_methods ?? [],
                'recovery_codes_count' => is_array($user->two_factor_recovery_codes) ? count(json_decode($user->two_factor_recovery_codes, true) ?? []) : 0,
                'password_changed_at' => $user->password_changed_at,
                'active_sessions' => $user->tokens()->where('expires_at', '>', now())->count(),
                'recent_logins' => \App\Models\AuthenticationLog::where('user_id', $user->id)
                    ->where('event', 'login_success')
                    ->orderBy('created_at', 'desc')
                    ->limit(5)
                    ->get()
                    ->map(function ($log) {
                        return [
                            'ip_address' => $log->ip_address,
                            'user_agent' => $log->user_agent,
                            'created_at' => $log->created_at,
                        ];
                    }),
            ],
        ]);
    }

    /**
     * Change password
     */
    public function changePassword(ChangePasswordRequest $request): JsonResponse
    {
        $user = Auth::user();

        // Update password (current password already validated by FormRequest)
        $user->update([
            'password' => Hash::make($request->password),
            'password_changed_at' => now(),
        ]);

        // Revoke all other sessions except current
        $currentToken = $user->token();
        if ($currentToken) {
            $user->tokens()->where('id', '!=', $currentToken->id)->delete();
        } else {
            // No current token (e.g., in testing), revoke all tokens
            $user->tokens()->delete();
        }

        // Log password change
        $this->authLogService->logAuthenticationEvent(
            $user,
            'password_changed',
            [],
            $request
        );

        return response()->json([
            'message' => 'Password changed successfully',
        ]);
    }

    /**
     * Get MFA status
     */
    public function mfaStatus(): JsonResponse
    {
        $user = Auth::user();

        return response()->json([
            'data' => [
                'mfa_enabled' => $user->hasMfaEnabled(),
                'mfa_methods' => $user->mfa_methods ?? [],
                'backup_codes' => $user->mfa_backup_codes ?? [],
                'backup_codes_count' => count($user->mfa_backup_codes ?? []),
                'totp_configured' => ! empty($user->two_factor_secret),
            ],
        ]);
    }

    /**
     * Setup TOTP for MFA
     */
    public function setupTotp(): JsonResponse
    {
        $user = Auth::user();

        if ($user->hasMfaEnabled()) {
            return response()->json([
                'success' => false,
                'error' => 'resource_conflict',
                'error_description' => 'MFA is already enabled for this account.',
            ], 409);
        }

        $google2fa = new Google2FA;

        // Generate secret key with proper length (minimum 16 characters)
        $secretKey = $google2fa->generateSecretKey(16); // Standard length for Google2FA

        // Store the secret temporarily (not confirmed yet)
        $user->update(['two_factor_secret' => encrypt($secretKey)]);

        $qrCodeUrl = $google2fa->getQRCodeUrl(
            config('app.name', 'Auth Service'),
            $user->email,
            $secretKey
        );

        return response()->json([
            'success' => true,
            'data' => [
                'secret' => $secretKey,
                'qr_code_url' => $qrCodeUrl,
                'backup_codes' => [], // Will be generated after verification
            ],
            'message' => 'TOTP setup initiated. Please verify to complete setup.',
        ]);
    }

    /**
     * Verify and enable TOTP
     */
    public function verifyTotp(Request $request): JsonResponse
    {
        $validator = Validator::make($request->all(), [
            'code' => 'required|string|size:6',
        ]);

        if ($validator->fails()) {
            return response()->json([
                'error' => 'validation_failed',
                'error_description' => 'The given data was invalid.',
                'details' => $validator->errors(),
            ], 422);
        }

        $user = Auth::user();

        if (! $user->two_factor_secret) {
            return response()->json([
                'error' => 'resource_not_found',
                'error_description' => 'TOTP setup not initiated.',
            ], 404);
        }

        $google2fa = new Google2FA;
        $secretKey = decrypt($user->two_factor_secret);

        if (! $google2fa->verifyKey($secretKey, $request->code)) {
            return response()->json([
                'error' => 'authentication_failed',
                'error_description' => 'Invalid TOTP code.',
            ], 401);
        }

        // Generate backup codes
        $backupCodes = [];
        for ($i = 0; $i < 8; $i++) {
            $backupCodes[] = strtoupper(substr(str_shuffle('0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ'), 0, 8));
        }

        // Enable MFA
        $user->update([
            'mfa_methods' => ['totp'],
            'two_factor_recovery_codes' => json_encode($backupCodes),
            'two_factor_confirmed_at' => now(),
        ]);

        // Log MFA enabled event
        $this->authLogService->logAuthenticationEvent(
            $user,
            'mfa_enabled',
            [],
            $request
        );

        return response()->json([
            'data' => [
                'backup_codes' => $backupCodes,
            ],
            'message' => 'TOTP enabled successfully. Please store your backup codes safely.',
        ]);
    }

    /**
     * Disable TOTP
     */
    public function disableTotp(Request $request): JsonResponse
    {
        $validator = Validator::make($request->all(), [
            'password' => 'required|string',
            'code' => 'sometimes|string|size:6',
        ]);

        if ($validator->fails()) {
            return response()->json([
                'error' => 'validation_failed',
                'error_description' => 'The given data was invalid.',
                'details' => $validator->errors(),
            ], 422);
        }

        $user = Auth::user();

        // Verify password
        if (! Hash::check($request->password, $user->password)) {
            return response()->json([
                'error' => 'authentication_failed',
                'error_description' => 'Password is incorrect.',
            ], 401);
        }

        // If TOTP is enabled, verify code
        if ($user->hasMfaEnabled() && $request->has('code')) {
            $google2fa = new Google2FA;
            $secretKey = decrypt($user->two_factor_secret);

            if (! $google2fa->verifyKey($secretKey, $request->code)) {
                return response()->json([
                    'error' => 'authentication_failed',
                    'error_description' => 'Invalid TOTP code.',
                ], 401);
            }
        }

        // Disable MFA
        $user->update([
            'two_factor_secret' => null,
            'mfa_methods' => null,
            'two_factor_recovery_codes' => null,
            'two_factor_confirmed_at' => null,
        ]);

        // Log MFA disabled event
        $this->authLogService->logAuthenticationEvent(
            $user,
            'mfa_disabled',
            [],
            $request
        );

        return response()->json([
            'message' => 'TOTP disabled successfully.',
        ]);
    }

    /**
     * Get recovery codes
     */
    public function getRecoveryCodes(Request $request): JsonResponse
    {
        $validator = Validator::make($request->all(), [
            'password' => 'required|string',
        ]);

        if ($validator->fails()) {
            return response()->json([
                'error' => 'validation_failed',
                'error_description' => 'The given data was invalid.',
                'details' => $validator->errors(),
            ], 422);
        }

        $user = Auth::user();

        // Verify password
        if (! Hash::check($request->password, $user->password)) {
            return response()->json([
                'error' => 'authentication_failed',
                'error_description' => 'Password is incorrect.',
            ], 401);
        }

        if (! $user->hasMfaEnabled()) {
            return response()->json([
                'error' => 'resource_not_found',
                'error_description' => 'MFA is not enabled.',
            ], 404);
        }

        return response()->json([
            'data' => [
                'recovery_codes' => json_decode($user->two_factor_recovery_codes, true) ?? [],
            ],
        ]);
    }

    /**
     * Regenerate recovery codes
     */
    public function regenerateRecoveryCodes(Request $request): JsonResponse
    {
        $validator = Validator::make($request->all(), [
            'password' => 'required|string',
        ]);

        if ($validator->fails()) {
            return response()->json([
                'error' => 'validation_failed',
                'error_description' => 'The given data was invalid.',
                'details' => $validator->errors(),
            ], 422);
        }

        $user = Auth::user();

        // Verify password
        if (! Hash::check($request->password, $user->password)) {
            return response()->json([
                'error' => 'authentication_failed',
                'error_description' => 'Password is incorrect.',
            ], 401);
        }

        if (! $user->hasMfaEnabled()) {
            return response()->json([
                'error' => 'resource_not_found',
                'error_description' => 'MFA is not enabled.',
            ], 404);
        }

        // Generate new backup codes
        $backupCodes = [];
        for ($i = 0; $i < 8; $i++) {
            $backupCodes[] = strtoupper(substr(str_shuffle('0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ'), 0, 8));
        }

        $user->update(['two_factor_recovery_codes' => json_encode($backupCodes)]);

        // Log recovery codes regenerated
        $this->authLogService->logAuthenticationEvent(
            $user,
            'recovery_codes_regenerated',
            [],
            $request
        );

        return response()->json([
            'data' => [
                'recovery_codes' => $backupCodes,
            ],
            'message' => 'Recovery codes regenerated successfully.',
        ]);
    }

    /**
     * Enable MFA after setup
     */
    public function enableMfa(Request $request): JsonResponse
    {
        $request->validate([
            'code' => 'required|string|size:6',
        ]);

        $user = Auth::user();

        if (! $user->two_factor_secret) {
            return response()->json([
                'success' => false,
                'error' => 'resource_not_found',
                'error_description' => 'TOTP setup not initiated.',
            ], 404);
        }

        $google2fa = new Google2FA;
        $secretKey = decrypt($user->two_factor_secret);

        if (! $google2fa->verifyKey($secretKey, $request->code)) {
            return response()->json([
                'success' => false,
                'error' => 'authentication_failed',
                'error_description' => 'Invalid TOTP code.',
            ], 401);
        }

        // Generate backup codes
        $backupCodes = [];
        for ($i = 0; $i < 8; $i++) {
            $backupCodes[] = strtoupper(substr(str_shuffle('0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ'), 0, 8));
        }

        // Enable MFA
        $user->update([
            'mfa_methods' => ['totp'],
            'mfa_backup_codes' => $backupCodes,
            'two_factor_recovery_codes' => json_encode($backupCodes),
            'two_factor_confirmed_at' => now(),
        ]);

        // Log MFA enabled event
        $this->authLogService->logAuthenticationEvent(
            $user,
            'mfa_enabled',
            [],
            $request
        );

        return response()->json([
            'success' => true,
            'data' => [
                'backup_codes' => $backupCodes,
                'mfa_enabled' => true,
                'methods' => ['totp'],
            ],
            'message' => 'MFA enabled successfully. Please store your backup codes safely.',
        ]);
    }

    /**
     * Disable MFA
     */
    public function disableMfa(Request $request): JsonResponse
    {
        $request->validate([
            'password' => 'required|string',
        ]);

        $user = Auth::user();

        // Disable MFA for the user
        $user->update([
            'two_factor_secret' => null,
            'two_factor_recovery_codes' => null,
            'two_factor_confirmed_at' => null,
            'mfa_methods' => null,
        ]);

        // Log MFA disabled event
        $this->authLogService->logAuthenticationEvent(
            $user,
            'mfa_disabled',
            [],
            $request
        );

        return response()->json([
            'success' => true,
            'data' => [
                'mfa_enabled' => false,
                'methods' => [],
            ],
            'message' => 'MFA disabled successfully',
        ]);
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
        $socialAccount = \App\Models\SocialAccount::where('user_id', $user->id)
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
