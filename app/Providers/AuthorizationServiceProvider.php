<?php

namespace App\Providers;

use App\Models\AccountLockout;
use App\Models\Application;
use App\Models\ApplicationGroup;
use App\Models\AuditExport;
use App\Models\AuthenticationLog;
use App\Models\BulkImportJob;
use App\Models\CustomDomain;
use App\Models\CustomRole;
use App\Models\FailedLoginAttempt;
use App\Models\Invitation;
use App\Models\IpBlocklist;
use App\Models\LdapConfiguration;
use App\Models\MigrationJob;
use App\Models\Organization;
use App\Models\OrganizationBranding;
use App\Models\Permission;
use App\Models\Role;
use App\Models\SecurityIncident;
use App\Models\SocialAccount;
use App\Models\SSOConfiguration;
use App\Models\SSOSession;
use App\Models\User;
use App\Models\UserApplication;
use App\Models\Webhook;
use App\Models\WebhookDelivery;
use App\Models\WebhookEvent;
use App\Policies\AccountLockoutPolicy;
use App\Policies\ApplicationGroupPolicy;
use App\Policies\ApplicationPolicy;
use App\Policies\AuditExportPolicy;
use App\Policies\AuthenticationLogPolicy;
use App\Policies\BulkImportJobPolicy;
use App\Policies\CustomDomainPolicy;
use App\Policies\CustomRolePolicy;
use App\Policies\FailedLoginAttemptPolicy;
use App\Policies\InvitationPolicy;
use App\Policies\IpBlocklistPolicy;
use App\Policies\LdapConfigurationPolicy;
use App\Policies\MigrationJobPolicy;
use App\Policies\OrganizationBrandingPolicy;
use App\Policies\OrganizationPolicy;
use App\Policies\PermissionPolicy;
use App\Policies\RolePolicy;
use App\Policies\SecurityIncidentPolicy;
use App\Policies\SocialAccountPolicy;
use App\Policies\SSOConfigurationPolicy;
use App\Policies\SSOSessionPolicy;
use App\Policies\UserApplicationPolicy;
use App\Policies\UserPolicy;
use App\Policies\WebhookDeliveryPolicy;
use App\Policies\WebhookEventPolicy;
use App\Policies\WebhookPolicy;
use Illuminate\Foundation\Support\Providers\AuthServiceProvider as ServiceProvider;
use Illuminate\Support\Facades\Gate;
use Spatie\Permission\Exceptions\PermissionDoesNotExist;
use Spatie\Permission\PermissionRegistrar;

class AuthorizationServiceProvider extends ServiceProvider
{
    protected $policies = [
        AccountLockout::class => AccountLockoutPolicy::class,
        Application::class => ApplicationPolicy::class,
        ApplicationGroup::class => ApplicationGroupPolicy::class,
        AuditExport::class => AuditExportPolicy::class,
        AuthenticationLog::class => AuthenticationLogPolicy::class,
        BulkImportJob::class => BulkImportJobPolicy::class,
        CustomDomain::class => CustomDomainPolicy::class,
        CustomRole::class => CustomRolePolicy::class,
        FailedLoginAttempt::class => FailedLoginAttemptPolicy::class,
        Invitation::class => InvitationPolicy::class,
        IpBlocklist::class => IpBlocklistPolicy::class,
        LdapConfiguration::class => LdapConfigurationPolicy::class,
        MigrationJob::class => MigrationJobPolicy::class,
        Organization::class => OrganizationPolicy::class,
        OrganizationBranding::class => OrganizationBrandingPolicy::class,
        Permission::class => PermissionPolicy::class,
        Role::class => RolePolicy::class,
        SecurityIncident::class => SecurityIncidentPolicy::class,
        SocialAccount::class => SocialAccountPolicy::class,
        SSOConfiguration::class => SSOConfigurationPolicy::class,
        SSOSession::class => SSOSessionPolicy::class,
        User::class => UserPolicy::class,
        UserApplication::class => UserApplicationPolicy::class,
        Webhook::class => WebhookPolicy::class,
        WebhookDelivery::class => WebhookDeliveryPolicy::class,
        WebhookEvent::class => WebhookEventPolicy::class,
    ];

    /**
     * Register services.
     */
    public function register(): void {}

    /**
     * Bootstrap services.
     */
    public function boot(): void
    {
        $this->registerPolicies();
        // Override Gate authorization to handle team context
        Gate::before(function ($user, $ability) {
            // Super admins have access to all abilities
            if ($user->isSuperAdmin()) {
                return true;
            }

            // Only process for API requests with organization context
            if (! request()->is('api/*') || ! $user->organization_id) {
                return null; // Let normal authorization proceed
            }

            // Ensure team context is set
            $user->setPermissionsTeamId($user->organization_id);
            app(PermissionRegistrar::class)->setPermissionsTeamId($user->organization_id);

            // Force refresh permissions to prevent cache issues
            $user->unsetRelation('permissions');
            $user->unsetRelation('roles');

            // Check if user has permission within their organization
            try {
                if ($user->hasPermissionTo($ability)) {
                    return true;
                }
            } catch (PermissionDoesNotExist $e) {
                // Permission doesn't exist, return false instead of throwing
                return false;
            }

            // Fallback: Manual check for organization-scoped permissions
            $permissions = $user->getAllPermissions();
            $orgScopedPermission = "$ability (org:$user->organization_id)";

            foreach ($permissions as $permission) {
                if ($permission->name === $ability || $permission->name === $orgScopedPermission) {
                    return true;
                }
            }

            // Check CustomRole permissions (organization-specific roles)
            if ($user->hasCustomPermission($ability)) {
                return true;
            }

            // Deny if user has CustomRoles but lacks the required permission
            if ($user->customRoles()->where('is_active', true)->exists()) {
                return false;
            }

            // Let normal authorization proceed (may deny)
            return null;
        });
    }
}
