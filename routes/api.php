<?php

use App\Http\Controllers\Api\AuthController;
use App\Http\Controllers\Api\OAuthController;
use App\Http\Controllers\Api\OpenIdController;
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

// Authentication routes
Route::prefix('auth')->group(function () {
    Route::post('/login', [AuthController::class, 'login']);
    Route::post('/refresh', [AuthController::class, 'refresh']);
    
    // Protected authentication routes
    Route::middleware('auth:api')->group(function () {
        Route::post('/logout', [AuthController::class, 'logout']);
        Route::get('/user', [AuthController::class, 'user']);
        Route::post('/revoke', [AuthController::class, 'revoke']);
    });
});

// OAuth 2.0 routes (custom implementation alongside Passport)
Route::prefix('oauth')->middleware('oauth.security')->group(function () {
    Route::get('/authorize', [OAuthController::class, 'authorize']);
    Route::post('/token', [OAuthController::class, 'token']);
    Route::middleware('auth:api')->get('/userinfo', [OpenIdController::class, 'userinfo']);
    Route::get('/jwks', [OpenIdController::class, 'jwks']);
});

// OpenID Connect Discovery
Route::get('/.well-known/openid-configuration', [OpenIdController::class, 'discovery']);