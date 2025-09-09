<?php

namespace App\Providers;

use App\Models\Application;
use App\Models\Organization;
use App\Models\User;
use App\Observers\ApplicationObserver;
use App\Observers\OrganizationObserver;
use App\Observers\UserObserver;
use Illuminate\Cache\RateLimiting\Limit;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\RateLimiter;
use Illuminate\Support\ServiceProvider;
use Laravel\Passport\Passport;

class AppServiceProvider extends ServiceProvider
{
    /**
     * Register any application services.
     */
    public function register(): void
    {
        //
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

        Passport::setDefaultScope(['openid']);
    }
}
