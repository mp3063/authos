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
     * @param  Closure(Request): (Response)  $next
     */
    public function handle(Request $request, Closure $next): Response
    {
        if ($request->user()) {
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
