<?php

namespace App\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Spatie\Permission\PermissionRegistrar;
use Symfony\Component\HttpFoundation\Response;

class SetPermissionContext
{
    /**
     * Handle an incoming request.
     *
     * @param  \Closure(\Illuminate\Http\Request): (\Symfony\Component\HttpFoundation\Response)  $next
     */
    public function handle(Request $request, Closure $next): Response
    {
        // Only process for authenticated API users
        if ($request->user() && $request->is('api/*')) {
            $user = $request->user();
            
            // Set team context for organization-scoped permissions
            if ($user->organization_id) {
                // Set on user instance
                $user->setPermissionsTeamId($user->organization_id);
                
                // Set globally on PermissionRegistrar
                app(PermissionRegistrar::class)->setPermissionsTeamId($user->organization_id);
            }
        }

        return $next($request);
    }
}