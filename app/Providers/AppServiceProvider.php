<?php

namespace App\Providers;

use App\Http\Responses\AuthorizationViewResponse as CustomAuthorizationViewResponse;
use App\Models\Application;
use App\Models\Organization;
use App\Models\User;
use App\Observers\ApplicationObserver;
use App\Observers\OrganizationObserver;
use App\Observers\UserObserver;
use App\Repositories\ApplicationRepository;
use App\Repositories\Contracts\ApplicationRepositoryInterface;
use App\Repositories\Contracts\OrganizationRepositoryInterface;
use App\Repositories\Contracts\UserRepositoryInterface;
use App\Repositories\OrganizationRepository;
use App\Repositories\UserRepository;
use App\Services\PerformanceMonitoringService;
use Illuminate\Cache\RateLimiting\Limit;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Queue;
use Illuminate\Support\Facades\RateLimiter;
use Illuminate\Support\ServiceProvider;
use Illuminate\Validation\Rules\Password;
use Laravel\Fortify\Fortify;
use Laravel\Passkeys\Passkeys;
use Laravel\Passport\Contracts\AuthorizationViewResponse;
use Laravel\Passport\Passport;
use Spatie\Permission\PermissionRegistrar;

class AppServiceProvider extends ServiceProvider
{
    /**
     * Register any application services.
     */
    public function register(): void
    {
        Passport::$deviceCodeGrantEnabled = false;
        Fortify::ignoreRoutes();
        Passkeys::ignoreRoutes();

        // Register repositories
        $this->app->bind(UserRepositoryInterface::class, UserRepository::class);
        $this->app->bind(OrganizationRepositoryInterface::class, OrganizationRepository::class);
        $this->app->bind(ApplicationRepositoryInterface::class, ApplicationRepository::class);

        // Bind Laravel Passport contracts
        $this->app->bind(AuthorizationViewResponse::class, CustomAuthorizationViewResponse::class);

        // Performance optimization services
        $this->app->singleton(PerformanceMonitoringService::class);

        // Note: Passport routes are automatically registered
        // We don't call Passport::ignoreRoutes() so OAuth endpoints are available
    }

    /**
     * Bootstrap any application services.
     */
    public function boot(): void
    {
        Model::preventLazyLoading(! app()->isProduction());

        Password::defaults(fn () => Password::min(8)->mixedCase()->numbers()->symbols()
            ->when(! app()->environment('testing'), fn (Password $rule) => $rule->uncompromised()));

        // Register model observers for cache invalidation
        User::observe(UserObserver::class);
        Organization::observe(OrganizationObserver::class);
        Application::observe(ApplicationObserver::class);

        $resetPermissionTeam = fn () => app(PermissionRegistrar::class)->setPermissionsTeamId(null);
        $this->app->terminating($resetPermissionTeam);
        Queue::before($resetPermissionTeam);
        Queue::after($resetPermissionTeam);
        Queue::failing($resetPermissionTeam);

        // Configure rate limiting
        RateLimiter::for('api', function (Request $request) {
            return Limit::perMinute(60)->by($request->user()?->id ?: $request->ip());
        });

        RateLimiter::for('auth', function (Request $request) {
            return Limit::perMinute(10)->by($request->ip());
        });

        RateLimiter::for('oauth', function (Request $request) {
            return Limit::perMinute(20)->by($request->ip());
        });

        // Configure OAuth token lifetimes
        Passport::tokensExpireIn(now()->addDays(15));
        Passport::refreshTokensExpireIn(now()->addDays(30));
        Passport::personalAccessTokensExpireIn(now()->addMonths(6));

        // Enable password grant type
        Passport::enablePasswordGrant();

        // Configure OAuth routes - We'll use custom routes for PKCE integration
        // Passport routes are available but we extend them with middleware

        // Configure OpenID Connect scopes
        Passport::tokensCan([
            '*' => 'Full access',
            'openid' => 'OpenID Connect access',
            'profile' => 'Access user profile information',
            'email' => 'Access user email address',
            'read' => 'Read access to your account',
            'write' => 'Write access to your account',
            'users.read' => 'Read user information',
            'users.write' => 'Write user information',
            'users.update' => 'Update user information',
            'users.delete' => 'Delete users',
            'users.manage' => 'Manage users',
            'applications.read' => 'Read application information',
            'applications.write' => 'Write application information',
            'applications.update' => 'Update applications',
            'applications.delete' => 'Delete applications',
            'applications.manage' => 'Manage applications',
            'organizations.read' => 'Read organization information',
            'organizations.write' => 'Write organization information',
            'organizations.update' => 'Update organizations',
            'organizations.manage' => 'Manage organizations',
            'sso' => 'Single Sign-On access',
            'roles.assign' => 'Assign roles to users',
            'mfa.setup' => 'Set up multi-factor authentication',
        ]);

        Passport::defaultScopes(['openid']);
    }
}
