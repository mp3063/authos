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
        Gate::before(fn ($user, string $ability) => $user->hasOrganizationPermission($ability) ? true : null);
    }
}
