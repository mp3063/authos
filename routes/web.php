<?php

use App\Http\Controllers\Api\SocialAuthController;
use Illuminate\Support\Facades\Route;

Route::get('/', function () {
    return view('welcome');
});

Route::redirect('/docs', '/docs/index.html');

// Social Authentication routes for web (Filament admin panel)
Route::prefix('auth/social')->group(function () {
    Route::get('/{provider}', [SocialAuthController::class, 'webLogin']);
    Route::get('/{provider}/callback', [SocialAuthController::class, 'webCallback']);
});
