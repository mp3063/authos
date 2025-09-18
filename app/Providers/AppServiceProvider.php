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
use Illuminate\Cache\RateLimiting\Limit;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\RateLimiter;
use Illuminate\Support\ServiceProvider;
use Laravel\Passport\Contracts\AuthorizationViewResponse;
use Laravel\Passport\Passport;

class AppServiceProvider extends ServiceProvider
{
    /**
     * Register any application services.
     */
    public function register(): void
    {
        // Register repositories
        $this->app->bind(UserRepositoryInterface::class, UserRepository::class);
        $this->app->bind(OrganizationRepositoryInterface::class, OrganizationRepository::class);
        $this->app->bind(ApplicationRepositoryInterface::class, ApplicationRepository::class);

        // Bind Laravel Passport contracts
        $this->app->bind(AuthorizationViewResponse::class, CustomAuthorizationViewResponse::class);

        // Performance optimization services
        $this->app->singleton(\App\Services\Database\OptimizedQueryService::class);
        $this->app->singleton(\App\Services\Database\UserQueryService::class);
        $this->app->singleton(\App\Services\Database\AnalyticsQueryService::class);
        $this->app->singleton(\App\Services\PerformanceMonitoringService::class);
    }

    /**
     * Bootstrap any application services.
     */
    public function boot(): void
    {
        // Register model observers for cache invalidation
        User::observe(UserObserver::class);
        Organization::observe(OrganizationObserver::class);
        Application::observe(ApplicationObserver::class);

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

        // Configure OAuth routes - Passport routes are auto-registered in Laravel 12

        // Configure OpenID Connect scopes
        Passport::tokensCan([
            'openid' => 'OpenID Connect access',
            'profile' => 'Access user profile information',
            'email' => 'Access user email address',
            'read' => 'Read access to your account',
            'write' => 'Write access to your account',
        ]);

        Passport::defaultScopes(['openid']);
    }
}
