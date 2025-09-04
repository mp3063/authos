<?php

use Illuminate\Support\Facades\Route;

Route::get('/', function () {
    return view('welcome');
});

Route::get('/test', function () {
    return response()->json([
        'message' => 'Laravel is working!',
        'timestamp' => now(),
        'user_count' => \App\Models\User::count(),
    ]);
});

Route::get('/test-db', function () {
    try {
        $users = \App\Models\User::take(3)->get();
        return response()->json([
            'message' => 'Database connection working!',
            'users_found' => $users->count(),
            'users' => $users->pluck('email'),
        ]);
    } catch (\Exception $e) {
        return response()->json([
            'error' => 'Database error: ' . $e->getMessage()
        ], 500);
    }
});

// Route::get('/admin', function () {
//     return response('<h1>Laravel is working! Admin route accessible.</h1><p>Timestamp: ' . now() . '</p><p>Users in database: ' . \App\Models\User::count() . '</p>');
// });
