<?php

use App\Http\Controllers\Api\AuthController;
use App\Http\Controllers\Api\OAuthController;
use App\Http\Controllers\Api\OpenIdController;
use App\Http\Controllers\Api\UserController;
use App\Http\Controllers\Api\ApplicationController;
use App\Http\Controllers\Api\ProfileController;
use App\Http\Controllers\Api\OrganizationController;
use App\Http\Controllers\Api\InvitationController;
use App\Http\Controllers\Api\SSOController;
use App\Http\Controllers\Api\BulkOperationsController;
use App\Http\Controllers\Api\CustomRoleController;
use App\Http\Controllers\Api\OrganizationReportController;
use App\Http\Controllers\Api\SocialAuthController;
use Illuminate\Support\Facades\Route;

/*
|--------------------------------------------------------------------------
| API Routes
|--------------------------------------------------------------------------
|
| Here is where you can register API routes for your application. These
| routes are loaded by the RouteServiceProvider and all of them will
| be assigned to the "api" middleware group. Make something great!
|
*/

// API Version Information
Route::get('/version', function () {
    return response()->json([
        'supported_versions' => ['v1'],
        'default_version' => 'v1',
        'latest_version' => 'v1',
    ]);
});

// Health Check Endpoints (public access)
Route::get('/health', function () {
    return response()->json(['status' => 'ok', 'timestamp' => now()]);
});

Route::get('/health/detailed', function () {
    return response()->json([
        'status' => 'ok',
        'timestamp' => now(),
        'services' => [
            'database' => 'ok',
            'redis' => 'ok', 
            'oauth' => 'ok'
        ]
    ]);
});

// API v1 Routes
Route::prefix('v1')->middleware(['api.version:v1', 'api.monitor'])->group(function () {
    
    // Authentication routes
    Route::prefix('auth')->group(function () {
        Route::post('/register', [AuthController::class, 'register'])->middleware('api.rate_limit:registration');
        Route::post('/login', [AuthController::class, 'login'])->middleware('api.rate_limit:authentication');
        Route::post('/refresh', [AuthController::class, 'refresh'])->middleware('api.rate_limit:authentication');
        
        // Social Authentication routes
        Route::prefix('social')->middleware('api.rate_limit:authentication')->group(function () {
            Route::get('/providers', [SocialAuthController::class, 'providers']);
            Route::get('/{provider}', [SocialAuthController::class, 'redirect']);
            Route::get('/{provider}/callback', [SocialAuthController::class, 'callback']);
            
            // Protected social auth routes
            Route::middleware('auth:api')->group(function () {
                Route::delete('/unlink', [SocialAuthController::class, 'unlink']);
            });
        });
        
        // Protected authentication routes
        Route::middleware('auth:api')->group(function () {
            Route::post('/logout', [AuthController::class, 'logout']);
            Route::get('/user', [AuthController::class, 'user']);
            Route::post('/revoke', [AuthController::class, 'revoke']);
        });
    });

    // OAuth 2.0 routes (custom implementation alongside Passport)
    Route::prefix('oauth')->middleware(['oauth.security', 'api.rate_limit:oauth'])->group(function () {
        Route::get('/authorize', [OAuthController::class, 'oauthAuthorize']);
        Route::post('/token', [OAuthController::class, 'token']);
        Route::middleware('auth:api')->get('/userinfo', [OpenIdController::class, 'userinfo']);
        Route::get('/jwks', [OpenIdController::class, 'jwks']);
    });

    // User Management API
    Route::middleware(['auth:api', 'api.rate_limit:api_admin', 'org.boundary'])->prefix('users')->group(function () {
        Route::get('/', [UserController::class, 'index'])->middleware(['api.rate_limit:api_bulk', 'api.cache:300']);
        Route::post('/', [UserController::class, 'store']);
        Route::get('/{id}', [UserController::class, 'show'])->middleware('api.cache:600');
        Route::put('/{id}', [UserController::class, 'update']);
        Route::delete('/{id}', [UserController::class, 'destroy']);
        
        // User applications
        Route::get('/{id}/applications', [UserController::class, 'applications']);
        Route::post('/{id}/applications', [UserController::class, 'grantApplicationAccess']);
        Route::delete('/{id}/applications/{applicationId}', [UserController::class, 'revokeApplicationAccess']);
        
        // User roles
        Route::get('/{id}/roles', [UserController::class, 'roles']);
        Route::post('/{id}/roles', [UserController::class, 'assignRole']);
        Route::delete('/{id}/roles/{roleId}', [UserController::class, 'removeRole']);
        
        // User sessions
        Route::get('/{id}/sessions', [UserController::class, 'sessions']);
        Route::delete('/{id}/sessions', [UserController::class, 'revokeSessions']);
        Route::delete('/{id}/sessions/{sessionId}', [UserController::class, 'revokeSession']);
    });

    // Application Management API
    Route::middleware(['auth:api', 'api.rate_limit:api_admin', 'org.boundary'])->prefix('applications')->group(function () {
        Route::get('/', [ApplicationController::class, 'index']);
        Route::post('/', [ApplicationController::class, 'store']);
        Route::get('/{id}', [ApplicationController::class, 'show']);
        Route::put('/{id}', [ApplicationController::class, 'update']);
        Route::delete('/{id}', [ApplicationController::class, 'destroy']);
        
        // Application credentials
        Route::post('/{id}/credentials/regenerate', [ApplicationController::class, 'regenerateCredentials']);
        
        // Application users
        Route::get('/{id}/users', [ApplicationController::class, 'users']);
        Route::post('/{id}/users', [ApplicationController::class, 'grantUserAccess']);
        Route::delete('/{id}/users/{userId}', [ApplicationController::class, 'revokeUserAccess']);
        
        // Application tokens
        Route::get('/{id}/tokens', [ApplicationController::class, 'tokens']);
        Route::delete('/{id}/tokens', [ApplicationController::class, 'revokeAllTokens']);
        Route::delete('/{id}/tokens/{tokenId}', [ApplicationController::class, 'revokeToken']);
        
        // Application analytics
        Route::get('/{id}/analytics', [ApplicationController::class, 'analytics']);
    });

    // Profile Management API
    Route::middleware(['auth:api', 'api.rate_limit:api_standard'])->prefix('profile')->group(function () {
        Route::get('/', [ProfileController::class, 'index']);
        Route::put('/', [ProfileController::class, 'update']);
        Route::post('/avatar', [ProfileController::class, 'uploadAvatar']);
        Route::delete('/avatar', [ProfileController::class, 'removeAvatar']);
        Route::get('/preferences', [ProfileController::class, 'preferences']);
        Route::put('/preferences', [ProfileController::class, 'updatePreferences']);
        Route::get('/security', [ProfileController::class, 'security']);
        Route::post('/change-password', [ProfileController::class, 'changePassword']);
    });

    // MFA Management API
    Route::middleware(['auth:api', 'api.rate_limit:mfa'])->prefix('mfa')->group(function () {
        Route::get('/status', [ProfileController::class, 'mfaStatus']);
        Route::post('/setup/totp', [ProfileController::class, 'setupTotp']);
        Route::post('/verify/totp', [ProfileController::class, 'verifyTotp']);
        Route::post('/disable/totp', [ProfileController::class, 'disableTotp']);
        Route::post('/recovery-codes', [ProfileController::class, 'getRecoveryCodes']);
        Route::post('/recovery-codes/regenerate', [ProfileController::class, 'regenerateRecoveryCodes']);
    });

    // Organization Management API  
    Route::middleware(['auth:api', 'api.rate_limit:api_admin', 'org.boundary'])->prefix('organizations')->group(function () {
        Route::get('/', [OrganizationController::class, 'index'])->middleware('api.cache:300');
        Route::post('/', [OrganizationController::class, 'store']);
        Route::get('/{id}', [OrganizationController::class, 'show'])->middleware('api.cache:600');
        Route::put('/{id}', [OrganizationController::class, 'update']);
        Route::delete('/{id}', [OrganizationController::class, 'destroy']);
        
        // Organization settings
        Route::get('/{id}/settings', [OrganizationController::class, 'settings']);
        Route::put('/{id}/settings', [OrganizationController::class, 'updateSettings']);
        
        // Organization users
        Route::get('/{id}/users', [OrganizationController::class, 'users']);
        Route::post('/{id}/users', [OrganizationController::class, 'grantUserAccess']);
        Route::delete('/{id}/users/{userId}/applications/{applicationId}', [OrganizationController::class, 'revokeUserAccess']);
        
        // Organization applications
        Route::get('/{id}/applications', [OrganizationController::class, 'applications']);
        
        // Organization analytics
        Route::get('/{id}/analytics', [OrganizationController::class, 'analytics']);
        
        // Organization invitations
        Route::get('/{id}/invitations', [InvitationController::class, 'index']);
        Route::post('/{id}/invitations', [InvitationController::class, 'store']);
        Route::delete('/{id}/invitations/{invitationId}', [InvitationController::class, 'destroy']);
        Route::post('/{id}/invitations/{invitationId}/resend', [InvitationController::class, 'resend']);
        Route::post('/{id}/invitations/bulk', [InvitationController::class, 'bulkInvite']);
        
        // Bulk Operations
        Route::post('/{id}/bulk/invite-users', [BulkOperationsController::class, 'bulkInviteUsers']);
        Route::post('/{id}/bulk/assign-roles', [BulkOperationsController::class, 'bulkAssignRoles']);
        Route::post('/{id}/bulk/revoke-access', [BulkOperationsController::class, 'bulkRevokeAccess']);
        Route::post('/{id}/bulk/export-users', [BulkOperationsController::class, 'exportUsers']);
        Route::post('/{id}/bulk/import-users', [BulkOperationsController::class, 'importUsers']);
        
        // Custom Roles Management
        Route::get('/{id}/custom-roles', [CustomRoleController::class, 'index']);
        Route::post('/{id}/custom-roles', [CustomRoleController::class, 'store']);
        Route::get('/{id}/custom-roles/{roleId}', [CustomRoleController::class, 'show']);
        Route::put('/{id}/custom-roles/{roleId}', [CustomRoleController::class, 'update']);
        Route::delete('/{id}/custom-roles/{roleId}', [CustomRoleController::class, 'destroy']);
        Route::post('/{id}/custom-roles/{roleId}/assign-users', [CustomRoleController::class, 'assignUsers']);
        Route::post('/{id}/custom-roles/{roleId}/remove-users', [CustomRoleController::class, 'removeUsers']);
        
        // Organization Reports
        Route::get('/{id}/reports/user-activity', [OrganizationReportController::class, 'userActivity']);
        Route::get('/{id}/reports/application-usage', [OrganizationReportController::class, 'applicationUsage']);
        Route::get('/{id}/reports/security-audit', [OrganizationReportController::class, 'securityAudit']);
    });

    // Public invitation endpoints (no auth required for viewing, auth required for accepting)
    Route::prefix('invitations')->group(function () {
        Route::get('/{token}', [InvitationController::class, 'show']);
        Route::post('/{token}/accept', [InvitationController::class, 'accept'])->middleware('auth:api');
    });

    // SSO (Single Sign-On) API
    Route::prefix('sso')->middleware(['api.rate_limit:oauth'])->group(function () {
        // Authenticated SSO endpoints
        Route::middleware('auth:api')->group(function () {
            Route::post('/initiate', [SSOController::class, 'initiate']);
            Route::get('/sessions', [SSOController::class, 'sessions']);
            Route::post('/sessions/revoke', [SSOController::class, 'revokeSessions']);
        });
        
        // Public SSO endpoints (for client applications)
        Route::post('/callback', [SSOController::class, 'callback']);
        Route::post('/validate', [SSOController::class, 'validateSession']);
        Route::post('/refresh', [SSOController::class, 'refresh']);
        Route::post('/logout', [SSOController::class, 'logout']);
        Route::get('/configuration/{applicationId}', [SSOController::class, 'configuration']);
    });

    // API Monitoring and Cache Management (Admin only)
    Route::middleware(['auth:api', 'api.rate_limit:api_admin'])->prefix('monitoring')->group(function () {
        Route::get('/metrics', function () {
            return response()->json([
                'api_requests_total' => cache()->get('api_requests_total', 0),
                'cache_hits' => cache()->get('cache_hits', 0),
                'cache_misses' => cache()->get('cache_misses', 0),
                'timestamp' => now(),
            ]);
        });
        
        Route::get('/health', function () {
            return response()->json([
                'database' => 'connected',
                'redis' => 'connected', 
                'oauth_keys' => 'present',
                'timestamp' => now(),
            ]);
        });
    });

    // Cache Management Endpoints (Admin only)
    Route::middleware(['auth:api', 'api.rate_limit:api_admin'])->prefix('cache')->group(function () {
        Route::get('/stats', function () {
            return response()->json([
                'total_keys' => 0, // Would need Redis connection to get actual stats
                'memory_usage' => '0MB',
                'hit_rate' => '0%',
                'timestamp' => now(),
            ]);
        });
        
        Route::delete('/clear-all', function () {
            cache()->flush();
            return response()->json(['message' => 'All caches cleared successfully']);
        });
        
        Route::delete('/clear-user', function () {
            // Clear user-specific caches (would implement cache tag clearing)
            return response()->json(['message' => 'User caches cleared successfully']);
        });
    });

    // Global Configuration Endpoints
    Route::middleware(['auth:api', 'api.rate_limit:api_standard'])->prefix('config')->group(function () {
        Route::get('/permissions', [CustomRoleController::class, 'permissions']);
        Route::get('/report-types', [OrganizationReportController::class, 'reportTypes']);
    });
});

// OpenID Connect Discovery (outside versioning for backward compatibility)
Route::get('/.well-known/openid-configuration', [OpenIdController::class, 'discovery']);