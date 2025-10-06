<?php

/**
 * OPcache Preload Script for Laravel 12 AuthOS
 *
 * This script preloads frequently used classes into OPcache
 * to improve performance by reducing class loading overhead.
 *
 * Usage:
 * Add to php.ini:
 * opcache.preload=/path/to/authos/deployment/php/preload.php
 * opcache.preload_user=www-data
 */

// Require Composer autoloader
require_once __DIR__.'/../../vendor/autoload.php';

/**
 * Preload Laravel framework classes
 */
$laravelClasses = [
    // Core Laravel
    \Illuminate\Foundation\Application::class,
    \Illuminate\Foundation\Http\Kernel::class,
    \Illuminate\Http\Request::class,
    \Illuminate\Http\Response::class,
    \Illuminate\Http\JsonResponse::class,
    \Illuminate\Routing\Router::class,
    \Illuminate\Routing\RouteCollection::class,

    // Database
    \Illuminate\Database\Eloquent\Model::class,
    \Illuminate\Database\Eloquent\Builder::class,
    \Illuminate\Database\Eloquent\Collection::class,
    \Illuminate\Database\Query\Builder::class,
    \Illuminate\Database\Connection::class,

    // Cache
    \Illuminate\Cache\CacheManager::class,
    \Illuminate\Cache\Repository::class,

    // Support
    \Illuminate\Support\Facades\Facade::class,
    \Illuminate\Support\Collection::class,
    \Illuminate\Support\Str::class,
    \Illuminate\Support\Arr::class,

    // Auth
    \Illuminate\Auth\AuthManager::class,
    \Illuminate\Auth\SessionGuard::class,
];

/**
 * Preload application models
 */
$appModels = [
    \App\Models\User::class,
    \App\Models\Organization::class,
    \App\Models\Application::class,
    \App\Models\AuthenticationLog::class,
    \App\Models\Webhook::class,
    \App\Models\WebhookDelivery::class,
    \App\Models\Invitation::class,
    \App\Models\SocialAccount::class,
    \App\Models\CustomDomain::class,
    \App\Models\LdapConfiguration::class,
];

/**
 * Preload application services
 */
$appServices = [
    \App\Services\UserManagementService::class,
    \App\Services\OrganizationAnalyticsService::class,
    \App\Services\AuthenticationLogService::class,
    \App\Services\CacheInvalidationService::class,
    \App\Services\CacheWarmingService::class,
    \App\Services\PerformanceMonitoringService::class,
];

/**
 * Preload middleware
 */
$middleware = [
    \App\Http\Middleware\ApiResponseCache::class,
    \App\Http\Middleware\CompressResponse::class,
    \App\Http\Middleware\ApiMonitoring::class,
];

/**
 * Preload controllers
 */
$controllers = [
    \App\Http\Controllers\Api\BaseApiController::class,
    \App\Http\Controllers\Api\UserController::class,
    \App\Http\Controllers\Api\ApplicationController::class,
    \App\Http\Controllers\Api\AuthController::class,
    \App\Http\Controllers\Api\OrganizationController::class,
];

/**
 * Preload third-party packages
 */
$thirdParty = [
    // Laravel Passport
    \Laravel\Passport\Token::class,
    \Laravel\Passport\Client::class,
    \Laravel\Passport\Http\Controllers\AccessTokenController::class,

    // Spatie Permission
    \Spatie\Permission\Models\Role::class,
    \Spatie\Permission\Models\Permission::class,
    \Spatie\Permission\PermissionRegistrar::class,
];

// Combine all classes to preload
$classesToPreload = array_merge(
    $laravelClasses,
    $appModels,
    $appServices,
    $middleware,
    $controllers,
    $thirdParty
);

// Preload classes
$preloadedCount = 0;
$failedCount = 0;

foreach ($classesToPreload as $class) {
    try {
        if (class_exists($class)) {
            opcache_compile_file((new ReflectionClass($class))->getFileName());
            $preloadedCount++;
        }
    } catch (Throwable $e) {
        $failedCount++;
        error_log("Preload failed for {$class}: {$e->getMessage()}");
    }
}

// Log preload statistics
error_log("OPcache preload completed: {$preloadedCount} classes preloaded, {$failedCount} failed");
