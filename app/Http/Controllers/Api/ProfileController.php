<?php

namespace App\Http\Controllers\Api;

use App\Http\Requests\Profile\ChangePasswordRequest;
use App\Http\Requests\Profile\UpdateProfileRequest;
use App\Models\AuthenticationLog;
use App\Notifications\PasswordChangedNotification;
use App\Services\AuthenticationLogService;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Routing\Controller as BaseController;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Storage;

class ProfileController extends BaseController
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
        $request->validate([
            'avatar' => 'required|image|mimes:jpeg,png,jpg,gif|max:2048', // 2MB max
        ]);

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
        $request->validate([
            'timezone' => 'sometimes|string|timezone',
            'language' => 'sometimes|string|in:en,es,fr,de,it,pt,nl,ru,ja,zh',
            'theme' => 'sometimes|string|in:light,dark,auto',
            'date_format' => 'sometimes|string|in:Y-m-d,m/d/Y,d/m/Y,d-m-Y',
            'time_format' => 'sometimes|string|in:H:i,h:i A',
            'email_notifications' => 'sometimes|boolean',
            'security_alerts' => 'sometimes|boolean',
            'marketing_emails' => 'sometimes|boolean',
        ]);

        $user = Auth::user();
        $profile = $user->profile ?? [];
        $validatedKeys = ['timezone', 'language', 'theme', 'date_format', 'time_format', 'email_notifications', 'security_alerts', 'marketing_emails'];
        $preferences = array_merge($profile['preferences'] ?? [], $request->only($validatedKeys));

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
                'recent_logins' => AuthenticationLog::where('user_id', $user->id)
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

        // Notify user about password change
        $user->notify(new PasswordChangedNotification($request->ip()));

        return response()->json([
            'message' => 'Password changed successfully',
        ]);
    }
}
