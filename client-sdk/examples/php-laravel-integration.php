<?php

/**
 * Example Laravel Integration with AuthOS
 * 
 * This example shows how to integrate AuthOS SSO with a Laravel application
 */

// 1. Install the AuthOS client (add to composer.json or include directly)
require_once __DIR__ . '/../php/AuthosClient.php';

use Authos\Client\AuthosClient;

// 2. Configure AuthOS in your Laravel app (config/authos.php)
return [
    'authos_url' => env('AUTHOS_URL', 'https://auth.yourapp.com'),
    'application_id' => env('AUTHOS_APP_ID'),
    'callback_url' => env('APP_URL') . '/auth/callback',
    'logout_url' => env('APP_URL') . '/logout',
    'allowed_domains' => explode(',', env('AUTHOS_ALLOWED_DOMAINS', '')),
];

// 3. Create AuthOS service provider (app/Providers/AuthosServiceProvider.php)
class AuthosServiceProvider extends \Illuminate\Support\ServiceProvider
{
    public function register()
    {
        $this->app->singleton(AuthosClient::class, function ($app) {
            return new AuthosClient(config('authos'));
        });
    }
}

// 4. Create middleware for protecting routes (app/Http/Middleware/AuthosAuth.php)
class AuthosAuth
{
    private AuthosClient $authos;

    public function __construct(AuthosClient $authos)
    {
        $this->authos = $authos;
    }

    public function handle($request, \Closure $next)
    {
        if (!$this->authos->isAuthenticated()) {
            return redirect($this->authos->getLoginUrl());
        }

        // Add user to request
        $request->attributes->set('authos_user', $this->authos->getUser());

        return $next($request);
    }
}

// 5. Create authentication controller (app/Http/Controllers/AuthController.php)
class AuthController extends \Illuminate\Http\Controller
{
    private AuthosClient $authos;

    public function __construct(AuthosClient $authos)
    {
        $this->authos = $authos;
    }

    /**
     * Redirect to AuthOS login
     */
    public function login()
    {
        return redirect($this->authos->getLoginUrl());
    }

    /**
     * Handle AuthOS callback
     */
    public function callback(\Illuminate\Http\Request $request)
    {
        try {
            $tokens = $this->authos->handleCallback($request->all());
            
            if ($tokens) {
                return redirect('/dashboard')->with('success', 'Login successful');
            }
            
            return redirect('/login')->with('error', 'Login failed');
            
        } catch (\Exception $e) {
            return redirect('/login')->with('error', $e->getMessage());
        }
    }

    /**
     * Logout user
     */
    public function logout()
    {
        try {
            $result = $this->authos->logout();
            
            // Handle logout URLs for other applications
            if (!empty($result['data']['logout_urls'])) {
                $logoutUrls = $result['data']['logout_urls'];
                return view('auth.logout', compact('logoutUrls'));
            }
            
            return redirect('/')->with('success', 'Logged out successfully');
            
        } catch (\Exception $e) {
            return redirect('/')->with('error', 'Logout failed: ' . $e->getMessage());
        }
    }

    /**
     * Get current user
     */
    public function user()
    {
        return response()->json($this->authos->getUser());
    }
}

// 6. Routes (routes/web.php)
Route::get('/login', [AuthController::class, 'login'])->name('login');
Route::get('/auth/callback', [AuthController::class, 'callback'])->name('auth.callback');
Route::post('/logout', [AuthController::class, 'logout'])->name('logout');
Route::get('/auth/user', [AuthController::class, 'user'])->middleware('authos');

// Protected routes
Route::middleware(['authos'])->group(function () {
    Route::get('/dashboard', function (\Illuminate\Http\Request $request) {
        $user = $request->attributes->get('authos_user');
        return view('dashboard', compact('user'));
    });
    
    Route::get('/profile', function (\Illuminate\Http\Request $request) {
        $user = $request->attributes->get('authos_user');
        return view('profile', compact('user'));
    });
});

// 7. Blade templates

// resources/views/auth/login.blade.php
?>
<!DOCTYPE html>
<html>
<head>
    <title>Login - {{ config('app.name') }}</title>
</head>
<body>
    <div class="container">
        <div class="card">
            <h2>Sign In</h2>
            <p>Sign in with your organizational account</p>
            <a href="{{ route('login') }}" class="btn btn-primary">
                Sign in with AuthOS
            </a>
        </div>
    </div>
</body>
</html>

<?php
// resources/views/auth/logout.blade.php
?>
<!DOCTYPE html>
<html>
<head>
    <title>Logging out...</title>
</head>
<body>
    <div class="container">
        <p>Logging you out from all applications...</p>
    </div>
    
    @if(!empty($logoutUrls))
        @foreach($logoutUrls as $url)
            <iframe src="{{ $url }}" style="display: none;"></iframe>
        @endforeach
        
        <script>
        // Redirect after logout iframes load
        setTimeout(function() {
            window.location.href = '/';
        }, 2000);
        </script>
    @endif
</body>
</html>

<?php
// resources/views/dashboard.blade.php
?>
<!DOCTYPE html>
<html>
<head>
    <title>Dashboard - {{ config('app.name') }}</title>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>Welcome, {{ $user['name'] }}</h1>
            <form method="POST" action="{{ route('logout') }}" style="display: inline;">
                @csrf
                <button type="submit">Logout</button>
            </form>
        </div>
        
        <div class="content">
            <h2>Your Profile</h2>
            <p><strong>Email:</strong> {{ $user['email'] }}</p>
            <p><strong>Organization:</strong> {{ $user['organization_id'] }}</p>
        </div>
    </div>
</body>
</html>

<?php

/**
 * Environment Variables (.env):
 * 
 * AUTHOS_URL=https://your-authos-instance.com
 * AUTHOS_APP_ID=1
 * AUTHOS_ALLOWED_DOMAINS=yourapp.com,*.yourapp.com
 */

/**
 * Installation Instructions:
 * 
 * 1. Add AuthosServiceProvider to config/app.php providers array
 * 2. Register AuthosAuth middleware in app/Http/Kernel.php
 * 3. Configure environment variables
 * 4. Create SSO configuration in AuthOS admin panel
 * 5. Test the integration
 */