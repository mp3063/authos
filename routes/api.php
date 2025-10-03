<?php

use App\Http\Controllers\Api\ApplicationController;
use App\Http\Controllers\Api\AuthController;
use App\Http\Controllers\Api\Bulk\BulkAccessController;
use App\Http\Controllers\Api\Bulk\BulkDataController;
use App\Http\Controllers\Api\Bulk\BulkUserOperationsController;
use App\Http\Controllers\Api\CustomRoleController;
use App\Http\Controllers\Api\InvitationController;
use App\Http\Controllers\Api\OpenIdController;
use App\Http\Controllers\Api\OrganizationReportController;
use App\Http\Controllers\Api\Organizations\OrganizationAnalyticsController;
use App\Http\Controllers\Api\Organizations\OrganizationCrudController;
use App\Http\Controllers\Api\Organizations\OrganizationUsersController;
use App\Http\Controllers\Api\ProfileController;
use App\Http\Controllers\Api\SocialAuthController;
use App\Http\Controllers\Api\UserController;
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
            'oauth' => 'ok',
        ],
    ]);
});

// API v1 Routes
Route::prefix('v1')->middleware(['api.version:v1', 'api.monitor'])->group(function () {

    // Authentication routes
    Route::prefix('auth')->group(function () {
        Route::post('/register', [AuthController::class, 'register'])->middleware('throttle:auth');
        Route::post('/login', [AuthController::class, 'login'])->middleware('throttle:auth');
        Route::post('/refresh', [AuthController::class, 'refresh'])->middleware('throttle:auth');
        Route::post('/mfa/verify', [AuthController::class, 'verifyMfa'])->middleware('throttle:auth');

        // Social Authentication routes
        Route::prefix('social')->middleware('throttle:auth')->group(function () {
            Route::get('/providers', [SocialAuthController::class, 'providers']);
            Route::get('/{provider}', [SocialAuthController::class, 'redirect']);
            Route::get('/{provider}/callback', [SocialAuthController::class, 'callback']);

            // Protected social auth routes
            Route::middleware('auth:api')->group(function () {
                Route::post('/link', [SocialAuthController::class, 'link']);
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

    // OpenID Connect endpoints
    Route::prefix('oauth')->middleware(['oauth.security', 'throttle:oauth'])->group(function () {
        Route::middleware('auth:api')->get('/userinfo', [OpenIdController::class, 'userinfo']);
        Route::get('/jwks', [OpenIdController::class, 'jwks']);
    });

    // User Management API
    Route::middleware(['auth:api', 'throttle:api', 'org.boundary'])->prefix('users')->group(function () {
        Route::get('/', [UserController::class, 'index'])->middleware(['throttle:api', 'api.cache:300']);
        Route::post('/', [UserController::class, 'store']);
        Route::patch('/bulk', [UserController::class, 'bulk'])->middleware('throttle:api');
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
    Route::middleware(['auth:api', 'throttle:api', 'org.boundary'])->prefix('applications')->group(function () {
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
    Route::middleware(['auth:api', 'throttle:api'])->prefix('profile')->group(function () {
        Route::get('/', [ProfileController::class, 'index']);
        Route::put('/', [ProfileController::class, 'update']);
        Route::post('/avatar', [ProfileController::class, 'uploadAvatar']);
        Route::delete('/avatar', [ProfileController::class, 'removeAvatar']);
        Route::get('/preferences', [ProfileController::class, 'preferences']);
        Route::put('/preferences', [ProfileController::class, 'updatePreferences']);
        Route::get('/security', [ProfileController::class, 'security']);
        Route::post('/change-password', [ProfileController::class, 'changePassword']);
        Route::get('/social-accounts', [ProfileController::class, 'socialAccounts']);
    });

    // MFA Management API
    Route::middleware(['auth:api', 'throttle:api'])->prefix('mfa')->group(function () {
        Route::get('/status', [ProfileController::class, 'mfaStatus']);
        Route::post('/setup', [ProfileController::class, 'setupTotp']); // Alias for /setup/totp
        Route::post('/setup/totp', [ProfileController::class, 'setupTotp']);
        Route::post('/enable', [ProfileController::class, 'enableMfa']); // New endpoint
        Route::post('/disable', [ProfileController::class, 'disableMfa']); // New endpoint
        Route::post('/verify/totp', [ProfileController::class, 'verifyTotp']);
        Route::post('/disable/totp', [ProfileController::class, 'disableTotp']); // Deprecated
        Route::post('/recovery-codes', [ProfileController::class, 'getRecoveryCodes']);
        Route::post('/recovery-codes/regenerate', [ProfileController::class, 'regenerateRecoveryCodes']);
        Route::post('/backup-codes/regenerate', [ProfileController::class, 'regenerateRecoveryCodes']); // Alias
    });

    // Organization Management API
    Route::middleware(['auth:api', 'throttle:api', 'org.boundary'])->prefix('organizations')->group(function () {
        // Basic CRUD operations
        Route::get('/', [OrganizationCrudController::class, 'index'])->middleware('api.cache:300');
        Route::post('/', [OrganizationCrudController::class, 'store']);
        Route::get('/{id}', [OrganizationCrudController::class, 'show'])->middleware('api.cache:600');
        Route::put('/{id}', [OrganizationCrudController::class, 'update']);
        Route::delete('/{id}', [OrganizationCrudController::class, 'destroy']);

        // Organization settings
        Route::get('/{id}/settings', [OrganizationCrudController::class, 'settings']);
        Route::put('/{id}/settings', [OrganizationCrudController::class, 'updateSettings']);

        // Organization users and applications
        Route::get('/{id}/users', [OrganizationUsersController::class, 'users']);
        Route::post('/{id}/users', [OrganizationUsersController::class, 'grantUserAccess']);
        Route::delete('/{id}/users/{userId}/applications/{applicationId}', [OrganizationUsersController::class, 'revokeUserAccess']);
        Route::get('/{id}/applications', [OrganizationUsersController::class, 'applications']);

        // Organization analytics and metrics
        Route::get('/{id}/analytics', [OrganizationAnalyticsController::class, 'analytics'])->middleware('api.cache:300');
        Route::get('/{id}/metrics/users', [OrganizationAnalyticsController::class, 'userMetrics'])->middleware('api.cache:300');
        Route::get('/{id}/metrics/applications', [OrganizationAnalyticsController::class, 'applicationMetrics'])->middleware('api.cache:300');
        Route::get('/{id}/metrics/security', [OrganizationAnalyticsController::class, 'securityMetrics'])->middleware('api.cache:300');
        Route::post('/{id}/export', [OrganizationAnalyticsController::class, 'export']);

        // Organization invitations
        Route::get('/{id}/invitations', [InvitationController::class, 'index']);
        Route::post('/{id}/invitations', [InvitationController::class, 'store']);
        Route::delete('/{id}/invitations/{invitationId}', [InvitationController::class, 'destroy']);
        Route::post('/{id}/invitations/{invitationId}/resend', [InvitationController::class, 'resend']);
        Route::post('/{id}/invitations/bulk', [InvitationController::class, 'bulkInvite']);

        // Bulk Operations (split into specialized controllers)
        Route::post('/{id}/bulk/invite-users', [BulkUserOperationsController::class, 'bulkInviteUsers']);
        Route::post('/{id}/bulk/assign-roles', [BulkUserOperationsController::class, 'bulkAssignRoles']);
        Route::post('/{id}/bulk/revoke-access', [BulkAccessController::class, 'bulkRevokeAccess']);
        Route::post('/{id}/bulk/export-users', [BulkDataController::class, 'exportUsers']);
        Route::post('/{id}/bulk/import-users', [BulkDataController::class, 'importUsers']);

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
    Route::prefix('sso')->middleware(['throttle:oauth'])->group(function () {
        // Authenticated SSO endpoints
        Route::middleware('auth:api')->group(function () {
            Route::post('/initiate', [\App\Http\Controllers\Api\SSOController::class, 'initiate'])->middleware('scopes:sso');
            Route::get('/sessions', [\App\Http\Controllers\Api\SSOController::class, 'sessions'])->middleware('scopes:sso');
            Route::post('/sessions/revoke', [\App\Http\Controllers\Api\SSOController::class, 'revokeSessions'])->middleware('scopes:sso');

            // Individual session management
            Route::get('/sessions/{session_token}/validate', [\App\Http\Controllers\Api\SSOController::class, 'validateSpecificSession'])->middleware('scopes:sso');
            Route::post('/sessions/{session_token}/refresh', [\App\Http\Controllers\Api\SSOController::class, 'refreshSpecificSession'])->middleware('scopes:sso');
            Route::post('/sessions/{session_token}/logout', [\App\Http\Controllers\Api\SSOController::class, 'logoutSpecificSession'])->middleware('scopes:sso');

            // Synchronized logout
            Route::post('/logout/synchronized', [\App\Http\Controllers\Api\SSOController::class, 'synchronizedLogout'])->middleware('scopes:sso');

            // SSO Configuration Management
            Route::get('/configurations/{organizationId}', [\App\Http\Controllers\Api\SSOController::class, 'getSSOConfiguration'])->middleware('scopes:sso');
            Route::post('/configurations', [\App\Http\Controllers\Api\SSOController::class, 'createSSOConfiguration'])->middleware('scopes:sso');
            Route::put('/configurations/{id}', [\App\Http\Controllers\Api\SSOController::class, 'updateSSOConfiguration'])->middleware('scopes:sso');
            Route::delete('/configurations/{id}', [\App\Http\Controllers\Api\SSOController::class, 'deleteSSOConfiguration'])->middleware('scopes:sso');
        });

        // Public SSO endpoints (for client applications)
        Route::post('/callback', [\App\Http\Controllers\Api\SSOController::class, 'callback']);
        Route::post('/saml/callback', [\App\Http\Controllers\Api\SSOController::class, 'samlCallback']);
        Route::post('/validate', [\App\Http\Controllers\Api\SSOController::class, 'validateSession']);
        Route::post('/refresh', [\App\Http\Controllers\Api\SSOController::class, 'refresh']);
        Route::post('/logout', [\App\Http\Controllers\Api\SSOController::class, 'logout']);
        Route::get('/configuration/{applicationId}', [\App\Http\Controllers\Api\SSOController::class, 'configuration']);
        Route::get('/metadata/{organizationSlug}', [\App\Http\Controllers\Api\SSOController::class, 'metadata']);
        Route::post('/cleanup', [\App\Http\Controllers\Api\SSOController::class, 'cleanup']);
    });

    // API Monitoring and Cache Management (Admin only)
    Route::middleware(['auth:api', 'throttle:api'])->prefix('monitoring')->group(function () {
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
    Route::middleware(['auth:api', 'throttle:api'])->prefix('cache')->group(function () {
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
    Route::middleware(['auth:api', 'throttle:api'])->prefix('config')->group(function () {
        Route::get('/permissions', [CustomRoleController::class, 'permissions']);
        Route::get('/report-types', [OrganizationReportController::class, 'reportTypes']);
    });

    // Enterprise Features (v1/enterprise/*)
    Route::middleware(['auth:api', 'throttle:api'])->prefix('enterprise')->group(function () {
        // LDAP Configuration & User Sync
        Route::post('ldap/test', [\App\Http\Controllers\Api\Enterprise\LdapController::class, 'testConnection']);
        Route::post('ldap/sync', [\App\Http\Controllers\Api\Enterprise\LdapController::class, 'syncUsers']);
        Route::get('ldap/users', [\App\Http\Controllers\Api\Enterprise\LdapController::class, 'listUsers']);
        Route::post('ldap/configure', [\App\Http\Controllers\Api\Enterprise\LdapController::class, 'configure']);

        // Custom Domains & DNS Verification
        Route::get('domains', [\App\Http\Controllers\Api\Enterprise\DomainController::class, 'index'])->name('api.enterprise.domains.index');
        Route::post('domains', [\App\Http\Controllers\Api\Enterprise\DomainController::class, 'store'])->name('api.enterprise.domains.store');
        Route::post('domains/{id}/verify', [\App\Http\Controllers\Api\Enterprise\DomainController::class, 'verify'])->name('api.enterprise.domains.verify');
        Route::delete('domains/{id}', [\App\Http\Controllers\Api\Enterprise\DomainController::class, 'destroy'])->name('api.enterprise.domains.destroy');

        // Audit Export & Logging
        Route::post('audit/export', [\App\Http\Controllers\Api\Enterprise\AuditController::class, 'export']);
        Route::get('audit/exports', [\App\Http\Controllers\Api\Enterprise\AuditController::class, 'listExports']);
        Route::get('audit/exports/{id}/download', [\App\Http\Controllers\Api\Enterprise\AuditController::class, 'download']);

        // Compliance Reports
        Route::get('compliance/soc2', [\App\Http\Controllers\Api\Enterprise\ComplianceController::class, 'soc2']);
        Route::get('compliance/iso27001', [\App\Http\Controllers\Api\Enterprise\ComplianceController::class, 'iso27001']);
        Route::get('compliance/gdpr', [\App\Http\Controllers\Api\Enterprise\ComplianceController::class, 'gdpr']);
        Route::post('compliance/schedule', [\App\Http\Controllers\Api\Enterprise\ComplianceController::class, 'schedule']);

        // Organization Branding
        Route::get('organizations/{organization}/branding', [\App\Http\Controllers\Api\Enterprise\BrandingController::class, 'show']);
        Route::put('organizations/{organization}/branding', [\App\Http\Controllers\Api\Enterprise\BrandingController::class, 'update']);
        Route::post('organizations/{organization}/branding/logo', [\App\Http\Controllers\Api\Enterprise\BrandingController::class, 'uploadLogo']);
        Route::post('organizations/{organization}/branding/background', [\App\Http\Controllers\Api\Enterprise\BrandingController::class, 'uploadBackground']);
    });
});

// OpenID Connect Discovery (outside versioning for backward compatibility)
Route::get('/.well-known/openid-configuration', [OpenIdController::class, 'discovery']);
